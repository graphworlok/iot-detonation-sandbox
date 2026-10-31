#!/bin/sh
# install.sh: build the sandbox host from this directory. Idempotent.
#
#   sudo sh host/install.sh                    # packages, users, files, units
#   sudo python3 -I /opt/sbx/guests/sbx-images.py   # guest images (downloads)
#
# Works the same on Ubuntu Desktop and Ubuntu Server (no GUI dependencies).
set -eu
SRC=$(cd "$(dirname "$0")/.." && pwd)

# --no-install-recommends keeps qemu-user-binfmt (and its host-wide binfmt
# handlers) off the box: a foreign-arch sample must never run on the host by
# accident.
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    qemu-system-x86 qemu-system-arm qemu-system-mips qemu-utils \
    dnsmasq-base nftables tcpdump iproute2 e2fsprogs openssl python3 \
    gdb-multiarch gzip
if ls /proc/sys/fs/binfmt_misc 2>/dev/null | grep -q qemu; then
    echo "WARNING: qemu binfmt handlers are registered on this host" >&2
fi

# users: sbx runs QEMU, sbxsink runs the sink and dnsmasq (after drop)
for u in sbx sbxsink; do
    id "$u" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$u"
done
usermod -aG kvm sbx

install -d -m 0755 /opt/sbx /opt/sbx/host /opt/sbx/sink /opt/sbx/guests /opt/sbx/run
install -m 0755 "$SRC/host/sbx-net.sh" /opt/sbx/host/
install -m 0644 "$SRC/host/nft-host.nft" /opt/sbx/host/
install -m 0644 "$SRC/sink/nft-sink.nft" "$SRC/sink/dnsmasq.conf" /opt/sbx/sink/
install -m 0755 "$SRC/sink/sink.py" /opt/sbx/sink/
install -m 0755 "$SRC/guests/sbx-images.py" /opt/sbx/guests/
install -m 0644 "$SRC/guests/targets.json" /opt/sbx/guests/
rm -rf /opt/sbx/guests/overlay
cp -r "$SRC/guests/overlay" /opt/sbx/guests/overlay
install -m 0755 "$SRC/run/sbx-run.py" /opt/sbx/run/
install -m 0644 "$SRC/run/sbx-trace.py" /opt/sbx/run/
ln -sf /opt/sbx/run/sbx-run.py /usr/local/sbin/sbx-run

# config: rules.json is only seeded; local edits survive re-installs
install -d -m 0755 /etc/sbx
[ -f /etc/sbx/rules.json ] || install -m 0644 "$SRC/sink/rules.json" /etc/sbx/rules.json
if [ ! -f /etc/sbx/sink.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=localhost" \
        -keyout /etc/sbx/sink.key -out /etc/sbx/sink.crt 2>/dev/null
fi
chown root:sbxsink /etc/sbx/sink.key
chmod 0640 /etc/sbx/sink.key

# data: samples to serve (read-only to the sink), images, runs, sink state
install -d -m 0755 /srv/sandbox /srv/sandbox/serve /srv/sandbox/images /srv/sandbox/runs
install -d -m 0750 -o sbxsink -g sbxsink /var/lib/sbx /var/lib/sbx/sink

install -m 0644 "$SRC"/host/systemd/sbx-*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sbx-net.service sbx-dnsmasq.service sbx-sink.service
systemctl --no-pager --lines=0 status sbx-net sbx-dnsmasq sbx-sink || true
