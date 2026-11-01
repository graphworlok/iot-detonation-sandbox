#!/usr/bin/env python3
"""Download, verify and customise the OpenWrt guest images.

    sudo python3 -I /opt/sbx/guests/sbx-images.py [target ...]

For each target in targets.json (default: all):
  1. fetch the release's sha256sums and the kernel + ext4 rootfs over HTTPS,
     checking every file against sha256sums;
  2. gunzip the rootfs, grow it to 256 MiB;
  3. inject the overlay with debugfs (no loop mount needed):
       /etc/uci-defaults/99-sbx      DHCP from the sink, services off
       /usr/libexec/sbx/sh           copy of the image's own /bin/busybox
       /usr/libexec/sbx/bin/sleep    hard link to it
       /usr/libexec/sbx/mon.sh       guest-side process monitor
  4. write /srv/sandbox/images/<target>/{kernel,rootfs.ext4,manifest.json}.
Guests boot the rootfs through a per-run qcow2 overlay, so the image is never
modified.
Re-running is safe: downloads are cached in /srv/sandbox/images/cache.
"""
import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("SBX_IMAGES", "/srv/sandbox/images")
BASE = "https://downloads.openwrt.org/releases/{rel}/targets/{target}/"
ROOTFS_SIZE = "256M"


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def cached(url, path, want):
    if os.path.exists(path) and sha256(open(path, "rb").read()) == want:
        return
    data = fetch(url)
    got = sha256(data)
    if got != want:
        sys.exit(f"checksum mismatch for {url}: {got} != {want}")
    with open(path + ".part", "wb") as f:
        f.write(data)
    os.replace(path + ".part", path)


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def debugfs(image, cmds):
    with tempfile.NamedTemporaryFile("w", suffix=".cmd", delete=False) as f:
        f.write("\n".join(cmds) + "\n")
        cmdfile = f.name
    try:
        r = subprocess.run(["debugfs", "-w", "-f", cmdfile, image],
                           capture_output=True, text=True)
    finally:
        os.unlink(cmdfile)
    # mkdir of an existing dir and rm of a missing file are expected (the
    # overlay is written idempotently); anything else is a real failure
    benign = ("already exists", "File not found by ext2_lookup", "File exists")
    errs = [l for l in r.stderr.splitlines()
            if l.strip() and not l.startswith("debugfs ")
            and not any(b in l for b in benign)]
    if r.returncode or errs:
        sys.exit(f"debugfs failed on {image}:\n{r.stderr}")


def build(name, t, rel):
    target_dir = os.path.join(OUT, name)
    cache = os.path.join(OUT, "cache", rel, t["openwrt"].replace("/", "_"))
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(cache, exist_ok=True)
    base = BASE.format(rel=rel, target=t["openwrt"])
    sums = {}
    for line in fetch(base + "sha256sums").decode().splitlines():
        h, _, fn = line.partition(" ")
        sums[fn.lstrip(" *")] = h
    files = {}
    for key in ("kernel", "rootfs"):
        fn = t[key].format(rel=rel)
        if fn not in sums:
            sys.exit(f"{name}: {fn} not in {base}sha256sums")
        cached(base + fn, os.path.join(cache, fn), sums[fn])
        files[key] = (fn, sums[fn])

    kernel = os.path.join(target_dir, "kernel")
    shutil.copyfile(os.path.join(cache, files["kernel"][0]), kernel)
    rootfs = os.path.join(target_dir, "rootfs.ext4")
    with gzip.open(os.path.join(cache, files["rootfs"][0])) as src, \
            open(rootfs + ".part", "wb") as dst:
        shutil.copyfileobj(src, dst)
    subprocess.run(["e2fsck", "-fy", rootfs + ".part"], capture_output=True)
    subprocess.run(["resize2fs", rootfs + ".part", ROOTFS_SIZE], check=True,
                   capture_output=True)

    ov = os.path.join(HERE, "overlay")
    with tempfile.TemporaryDirectory() as tmp:
        bb = os.path.join(tmp, "busybox")
        r = subprocess.run(["debugfs", "-R", f"dump /bin/busybox {bb}", rootfs + ".part"],
                           capture_output=True, text=True)
        if not os.path.exists(bb) or os.path.getsize(bb) == 0:
            sys.exit(f"{name}: could not dump /bin/busybox: {r.stderr}")
        debugfs(rootfs + ".part", [
            "mkdir /usr/libexec",
            "mkdir /usr/libexec/sbx",
            "mkdir /usr/libexec/sbx/bin",
            "rm /etc/uci-defaults/99-sbx",
            f"write {ov}/etc/uci-defaults/99-sbx /etc/uci-defaults/99-sbx",
            "sif /etc/uci-defaults/99-sbx mode 0100755",
            "rm /usr/libexec/sbx/sh",
            f"write {bb} /usr/libexec/sbx/sh",
            "sif /usr/libexec/sbx/sh mode 0100755",
            "rm /usr/libexec/sbx/bin/sleep",
            "ln /usr/libexec/sbx/sh /usr/libexec/sbx/bin/sleep",
            "sif /usr/libexec/sbx/sh links_count 2",
            "rm /usr/libexec/sbx/mon.sh",
            f"write {ov}/usr/libexec/sbx/mon.sh /usr/libexec/sbx/mon.sh",
            "sif /usr/libexec/sbx/mon.sh mode 0100644",
        ] + [f"sif {p} {k} 0" for p in ("/etc/uci-defaults/99-sbx", "/usr/libexec/sbx/sh",
                                        "/usr/libexec/sbx/mon.sh")
             for k in ("uid", "gid")])
    r = subprocess.run(["e2fsck", "-fy", rootfs + ".part"], capture_output=True, text=True)
    if r.returncode > 1:
        sys.exit(f"{name}: e2fsck after injection failed:\n{r.stdout}{r.stderr}")
    os.replace(rootfs + ".part", rootfs)
    os.chmod(kernel, 0o644)
    os.chmod(rootfs, 0o644)
    manifest = {"target": name, "openwrt_release": rel, "openwrt_target": t["openwrt"],
                "kernel": {"file": files["kernel"][0], "sha256": files["kernel"][1]},
                "rootfs": {"file": files["rootfs"][0], "sha256_gz": files["rootfs"][1],
                           "sha256_built": sha256(open(rootfs, "rb").read())},
                "overlay": {p: sha256(open(os.path.join(ov, p), "rb").read())
                            for p in ("etc/uci-defaults/99-sbx", "usr/libexec/sbx/mon.sh")}}
    with open(os.path.join(target_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    print(f"{name}: ok ({rel} {t['openwrt']})")


def main():
    cfg = json.load(open(os.path.join(HERE, "targets.json")))
    rel = cfg["openwrt_release"]
    names = sys.argv[1:] or list(cfg["targets"])
    for n in names:
        if n not in cfg["targets"]:
            sys.exit(f"unknown target {n}; have {', '.join(cfg['targets'])}")
        build(n, cfg["targets"][n], rel)


if __name__ == "__main__":
    main()
