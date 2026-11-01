#!/usr/bin/env python3
"""Traffic sink for the sandbox network: pretends to be "the internet".

Runs inside the sbxsink namespace (sbx-sink.service), stdlib only.

- TCP catch-all on 10.200.0.1:9999. nft-sink.nft DNATs every TCP connection
  from a guest, to any address/port, here; the original destination is read
  back with SO_ORIGINAL_DST.
- TLS (first byte 0x16) is terminated with a self-signed certificate, so
  `wget --no-check-certificate` / `curl -k` style fetches complete.
- HTTP requests are parsed and answered from rules.json (serve a file, fixed
  body, status); anything else gets the rule's raw action (hold the
  connection and log what the client sends, send a banner, close).
- DNS on :53 (every UDP query, to any server, is DNATed here): A queries get
  10.200.0.1 or a per-name address from rules.json "dns"; AAAA and other
  types get an empty NOERROR (musl fails a lookup whose AAAA is refused).
  DNS framed over TCP (any port, also inside TLS, so DNS over TLS on :853)
  is recognised by the catch-all and answered the same way.
- UDP logger on :9998 (summarised per source, flood-safe). The original UDP
  destination is not recoverable after DNAT; the host-side pcap has it.
- GET /_sbx/<path> to the sink address serves files from SERVE_DIR: this is
  how guests are handed samples.

Every connection is logged as one JSON line to EVENTS; request bodies and
raw client data are kept in BLOBS by SHA-256.
"""
import hashlib
import json
import os
import re
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

SINK_IP = "10.200.0.1"
TCP_PORT = 9999
UDP_PORT = 9998
STATE = os.environ.get("SBX_STATE", "/var/lib/sbx/sink")
EVENTS = os.path.join(STATE, "events.jsonl")
BLOBS = os.path.join(STATE, "blobs")
SERVE_DIR = os.environ.get("SBX_SERVE", "/srv/sandbox/serve")
RULES = os.environ.get("SBX_RULES", "/etc/sbx/rules.json")
CERT = os.environ.get("SBX_CERT", "/etc/sbx/sink.crt")
KEY = os.environ.get("SBX_KEY", "/etc/sbx/sink.key")

SO_ORIGINAL_DST = 80
MAX_CAPTURE = 1 << 20          # per connection, client->sink bytes kept
FIRST_WAIT = 5.0               # seconds to wait for the client to speak
# sends get their own, long timeout: an emulated guest under load can read
# a large download slowly, and the short receive timeouts would otherwise
# abort sendall() mid-body
SEND_TIMEOUT = 120.0
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE ",
                b"CONNECT ", b"PATCH ")

_log_lock = threading.Lock()
_rules = {"mtime": 0, "data": {}}


def log(ev):
    ev["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z"
    line = json.dumps(ev, separators=(",", ":"))
    with _log_lock:
        with open(EVENTS, "a") as f:
            f.write(line + "\n")


def keep_blob(data):
    if not data:
        return None
    h = hashlib.sha256(data).hexdigest()
    p = os.path.join(BLOBS, h)
    if not os.path.exists(p):
        with open(p, "wb") as f:
            f.write(data)
    return h


def rules():
    try:
        m = os.stat(RULES).st_mtime
        if m != _rules["mtime"]:
            with open(RULES) as f:
                _rules["data"] = json.load(f)
            _rules["mtime"] = m
    except (OSError, ValueError) as e:
        if not _rules["data"]:
            sys.stderr.write(f"rules: {e}\n")
    return _rules["data"]


def original_dst(sock):
    raw = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, = struct.unpack("!H", raw[2:4])
    return socket.inet_ntoa(raw[4:8]), port


def match_rule(proto, dst, port, host=None, path=None):
    for r in rules().get("rules", []):
        m = r.get("match", {})
        if m.get("proto", proto) != proto:
            continue
        if "dst" in m and m["dst"] != dst:
            continue
        if "port" in m and m["port"] != port:
            continue
        if "host" in m and not re.fullmatch(m["host"], host or ""):
            continue
        groups = {}
        if "path" in m:
            mm = re.match(m["path"], path or "")
            if not mm:
                continue
            groups = mm.groupdict()
        return r, groups
    return None, {}


def safe_join(base, rel):
    p = os.path.realpath(os.path.join(base, rel))
    if not p.startswith(os.path.realpath(base) + os.sep):
        return None
    return p


def recv_some(conn, n, timeout):
    conn.settimeout(timeout)
    try:
        return conn.recv(n)
    except (socket.timeout, ssl.SSLError, OSError):
        return b""


def send(conn, data):
    conn.settimeout(SEND_TIMEOUT)
    conn.sendall(data)


def read_http(conn, first):
    data = first
    while b"\r\n\r\n" not in data and len(data) < 65536:
        more = recv_some(conn, 65536, 5)
        if not more:
            break
        data += more
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, _, rest = lines[0].partition(" ")
    path, _, version = rest.rpartition(" ") if rest.count(" ") else (rest, "", "")
    hdrs = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    want = int(hdrs.get("content-length", "0") or 0)
    want = min(want, MAX_CAPTURE)
    while len(body) < want:
        more = recv_some(conn, 65536, 5)
        if not more:
            break
        body += more
    return method, path or rest, version, hdrs, body, head.decode("latin-1")


def http_response(status, body, ctype="text/html", extra=None):
    reason = {200: "OK", 301: "Moved Permanently", 302: "Found", 403: "Forbidden",
              404: "Not Found", 500: "Internal Server Error"}.get(status, "OK")
    h = [f"HTTP/1.1 {status} {reason}", "Server: nginx", f"Content-Type: {ctype}",
         f"Content-Length: {len(body)}", "Connection: close"]
    for k, v in (extra or {}).items():
        h.append(f"{k}: {v}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def answer_http(dst, port, method, path, hdrs):
    host = hdrs.get("host", "").split(":")[0]
    if dst == SINK_IP and path.startswith("/_sbx/"):
        p = safe_join(SERVE_DIR, path[len("/_sbx/"):])
        if p and os.path.isfile(p):
            with open(p, "rb") as f:
                return http_response(200, f.read(), "application/octet-stream"), "serve"
        return http_response(404, b"not found\n", "text/plain"), "serve-miss"
    r, groups = match_rule("http", dst, port, host, path)
    resp = (r or {}).get("respond") or rules().get("default_http") or {}
    name = (r or {}).get("name", "default_http")
    status = resp.get("status", 200)
    ctype = resp.get("type", "text/html")
    if "file" in resp:
        p = safe_join(SERVE_DIR, resp["file"].format(**groups))
        if p and os.path.isfile(p):
            with open(p, "rb") as f:
                body = f.read()
        else:
            status, body, ctype = 404, b"not found\n", "text/plain"
    else:
        body = resp.get("body", "").encode()
    return http_response(status, body if method != "HEAD" else b"", ctype,
                         resp.get("headers")), name


def sni_of(hello):
    """Server name from a TLS ClientHello, best effort."""
    try:
        i = 5 + 4 + 2 + 32
        i += 1 + hello[i]
        i += 2 + struct.unpack("!H", hello[i:i + 2])[0]
        i += 1 + hello[i]
        end = i + 2 + struct.unpack("!H", hello[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            t, l = struct.unpack("!HH", hello[i:i + 4])
            if t == 0:
                return hello[i + 9:i + 4 + l].decode("ascii", "replace")
            i += 4 + l
    except (IndexError, struct.error):
        pass
    return None


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        src = "%s:%d" % self.client_address
        try:
            dst, port = original_dst(conn)
        except OSError:
            dst, port = SINK_IP, TCP_PORT
        ev = {"proto": "tcp", "src": src, "dst": f"{dst}:{port}"}
        t0 = time.time()
        # held connections can outlive a run, so their open is logged now and
        # the summary (with "secs") when they close
        log({"proto": "tcp", "event": "open", "src": src, "dst": f"{dst}:{port}"})
        try:
            first = recv_some(conn, 65536, FIRST_WAIT)
            if not first:
                r, _ = match_rule("raw", dst, port)
                banner = ((r or {}).get("respond") or {}).get("banner")
                if banner:
                    send(conn, banner.encode("latin-1").decode("unicode_escape").encode("latin-1"))
                    ev["sent_banner"] = (r or {}).get("name")
                    first = recv_some(conn, 65536, 30)
            if first[:1] == b"\x16" and os.path.exists(CERT):
                ev["tls"] = True
                ev["sni"] = sni_of(first)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(CERT, KEY)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                # the ClientHello was already read; hand it back to the TLS layer
                conn = ctx.wrap_socket(_Replay(conn, first), server_side=True)
                first = recv_some(conn, 65536, FIRST_WAIT)
            if first.startswith(HTTP_METHODS):
                method, path, version, hdrs, body, head = read_http(conn, first)
                resp, rule = answer_http(dst, port, method, path, hdrs)
                # record the request before sending, so a failed send still
                # shows what was asked for
                ev.update({"kind": "http", "method": method, "path": path,
                           "host": hdrs.get("host"), "ua": hdrs.get("user-agent"),
                           "head": head[:4096], "body_len": len(body),
                           "body_sha256": keep_blob(body), "rule": rule,
                           "resp_len": len(resp)})
                send(conn, resp)
            elif looks_like_dns_tcp(first):
                ev["kind"] = "dns"
                ev["queries"] = self.dns_tcp(conn, first, src, f"{dst}:{port}", ev.get("tls"))
            else:
                r, _ = match_rule("raw", dst, port)
                resp = (r or {}).get("respond") or rules().get("default_raw") or {}
                ev["rule"] = (r or {}).get("name", "default_raw")
                data = first
                if first:
                    log({"proto": "tcp", "event": "data", "src": src, "dst": f"{dst}:{port}",
                         "rule": ev["rule"], "head_hex": first[:256].hex()})
                if "send_hex" in resp:
                    send(conn, bytes.fromhex(resp["send_hex"]))
                if resp.get("action", "hold") == "hold":
                    deadline = t0 + resp.get("timeout", 120)
                    while len(data) < MAX_CAPTURE and time.time() < deadline:
                        more = recv_some(conn, 65536, max(0.1, deadline - time.time()))
                        if not more:
                            break
                        data += more
                ev.update({"kind": "raw", "bytes": len(data),
                           "data_sha256": keep_blob(data),
                           "head_hex": data[:256].hex()})
        except Exception as e:  # never let one connection kill the sink
            ev["error"] = repr(e)[:200]
        finally:
            ev["event"] = "close"
            ev["secs"] = round(time.time() - t0, 2)
            log(ev)
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def dns_tcp(conn, buf, src, dst, tls):
        """Answer length-framed DNS queries (plain TCP or, after the TLS
        unwrap above, DNS over TLS) until the client stops sending."""
        n = 0
        while True:
            while len(buf) >= 2 and len(buf) >= 2 + struct.unpack("!H", buf[:2])[0]:
                ln = struct.unpack("!H", buf[:2])[0]
                q, buf = buf[2:2 + ln], buf[2 + ln:]
                r = dns_reply(q)
                if not r:
                    return n
                send(conn, struct.pack("!H", len(r[0])) + r[0])
                log({"proto": "dns", "transport": "tls" if tls else "tcp",
                     "src": src, "dst": dst, **r[1]})
                n += 1
            if len(buf) > 65537:
                return n
            more = recv_some(conn, 65536, 10)
            if not more:
                return n
            buf += more


class _Replay:
    """Return a socket that yields `prefix` and then whatever `sock` receives.

    wrap_socket() needs a real socket, so the already-read bytes are pushed
    into one end of a socketpair and two threads relay the rest both ways."""

    def __new__(cls, sock, prefix):
        a, b = socket.socketpair()
        a.sendall(prefix)

        def pump(src, dst):
            try:
                while True:
                    d = src.recv(65536)
                    if not d:
                        break
                    dst.sendall(d)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threading.Thread(target=pump, args=(sock, a), daemon=True).start()
        threading.Thread(target=pump, args=(a, sock), daemon=True).start()
        return b


class UDPLogger(threading.Thread):
    """Count datagrams per source; log one summary line per source per minute."""

    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((SINK_IP, UDP_PORT))
        self.stats = {}

    def run(self):
        last = time.time()
        while True:
            self.s.settimeout(5)
            try:
                d, a = self.s.recvfrom(65535)
                st = self.stats.setdefault(a[0], {"n": 0, "bytes": 0, "first_hex": d[:128].hex()})
                st["n"] += 1
                st["bytes"] += len(d)
            except socket.timeout:
                pass
            if time.time() - last >= 60 and self.stats:
                for ip, st in self.stats.items():
                    log({"proto": "udp", "src": ip, "datagrams": st["n"],
                         "bytes": st["bytes"], "first_hex": st["first_hex"]})
                self.stats, last = {}, time.time()


DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
              16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def dns_answer_for(name):
    dns = rules().get("dns", {})
    for pattern, ip in dns.get("names", {}).items():
        if re.fullmatch(pattern, name, re.I):
            return ip
    return dns.get("default", SINK_IP)


def dns_reply(q):
    """Answer one DNS query message: (reply, log fields), or None if `q` is
    not a single-question query. A -> dns_answer_for(); anything else gets an
    empty NOERROR."""
    if len(q) < 17:
        return None
    qid, flags, qd = struct.unpack("!HHH", q[:6])
    if flags & 0xF800 or qd != 1:      # a response, or not a standard query
        return None
    i, labels = 12, []
    while i < len(q) and q[i]:
        labels.append(q[i + 1:i + 1 + q[i]].decode("ascii", "replace"))
        i += 1 + q[i]
    if i + 5 > len(q):
        return None
    qtype, qclass = struct.unpack("!HH", q[i + 1:i + 5])
    question = q[12:i + 5]
    name = ".".join(labels)
    ans = b""
    ip = None
    if qtype == 1 and qclass == 1:
        ip = dns_answer_for(name)
        ans = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    rflags = 0x8180 | (flags & 0x0100)
    hdr = struct.pack("!HHHHHH", qid, rflags, 1, 1 if ans else 0, 0, 0)
    return hdr + question + ans, {"qname": name, "qtype": DNS_QTYPES.get(qtype, qtype),
                                  "answer": ip}


def looks_like_dns_tcp(data):
    """DNS over TCP framing (RFC 1035 4.2.2): 2-byte length, then a query."""
    if len(data) < 19:
        return False
    n = struct.unpack("!H", data[:2])[0]
    return 17 <= n <= len(data) - 2 and dns_reply(data[2:2 + n]) is not None


class DNSServer(threading.Thread):
    """Wildcard resolver on UDP :53, see dns_reply()."""

    def __init__(self):
        super().__init__(daemon=True)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((SINK_IP, 53))

    def run(self):
        while True:
            try:
                q, a = self.s.recvfrom(4096)
                r = dns_reply(q)
                if not r:
                    continue
                self.s.sendto(r[0], a)
                log({"proto": "dns", "src": "%s:%d" % a, **r[1]})
            except Exception as e:
                sys.stderr.write(f"dns: {e!r}\n")


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def main():
    os.makedirs(BLOBS, exist_ok=True)
    rules()
    DNSServer().start()
    UDPLogger().start()
    srv = Server((SINK_IP, TCP_PORT), TCPHandler)
    log({"proto": "sink", "event": "start"})
    srv.serve_forever()


if __name__ == "__main__":
    main()
