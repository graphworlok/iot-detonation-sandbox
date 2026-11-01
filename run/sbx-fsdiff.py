#!/usr/bin/env python3
"""Compare a run's guest disk with the clean image it started from.

    sbx-fsdiff.py CLEAN.ext4 RUN.qcow2 OUTDIR [BASELINE.json]

sbx-run starts this in a transient unit as user sbx, with no network and
only OUTDIR writable: the run disk was written by a guest the sample had root
in, so everything parsed here (the ext4 metadata, the extracted tree) is
untrusted. Nothing is mounted; e2fsprogs read the images in user space.

1. qemu-img converts the copy-on-write overlay to a raw ext4 image;
2. e2fsck replays the ext4 journal only (the guest was killed, not shut
   down; without the replay recent metadata changes are missing);
3. debugfs rdump extracts both trees; they are compared by type, mode,
   content hash and symlink target. A file that disappeared and one that
   appeared with the same content are reported as a rename.
4. Paths listed in BASELINE.json (from a run with no sample: first-boot
   changes such as generated keys and uci-defaults) are marked "boot".

Output in OUTDIR: fsdiff.json and fs-changed.tar.gz (added and modified
files from the run disk, symlinks not followed). The work trees are removed.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile

MAX_TAR = 200 * 1024 * 1024


def run(*a):
    return subprocess.run(a, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def tree(root):
    """{path: (kind, mode, sha256 / link target, size)} without following links."""
    # rdump keeps the guest's modes and every file is ours (chown fails), so
    # record the mode, then give the owner access before reading or descending
    os.chmod(root, 0o700)
    out, todo = {}, [root]
    while todo:
        d = todo.pop()
        for name in os.listdir(d):
            full = os.path.join(d, name)
            rel = "/" + os.path.relpath(full, root)
            st = os.lstat(full)
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", mode, os.readlink(full), 0)
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", mode, None, 0)
                os.chmod(full, 0o700)
                todo.append(full)
            elif stat.S_ISREG(st.st_mode):
                os.chmod(full, 0o600)
                h = hashlib.sha256()
                with open(full, "rb") as f:
                    for blk in iter(lambda: f.read(1 << 20), b""):
                        h.update(blk)
                out[rel] = ("file", mode, h.hexdigest(), st.st_size)
    return out


def entry(path, v):
    e = {"path": path, "type": v[0], "mode": oct(v[1])}
    if v[0] == "file":
        e["sha256"], e["size"] = v[2], v[3]
    elif v[0] == "link":
        e["target"] = v[2]
    return e


def main():
    clean_img, run_img, out = sys.argv[1:4]
    baseline = set()
    if len(sys.argv) > 4 and os.path.exists(sys.argv[4]):
        baseline = set(json.load(open(sys.argv[4]))["paths"])
    work = os.path.join(out, "fsdiff.work")
    os.makedirs(work)
    raw = os.path.join(work, "run.ext4")
    res = {"clean": clean_img}
    try:
        r = run("qemu-img", "convert", "-O", "raw", run_img, raw)
        if r.returncode:
            raise RuntimeError("qemu-img: " + r.stdout.strip())
        r = run("e2fsck", "-E", "journal_only", "-p", raw)
        res["e2fsck"] = {"rc": r.returncode, "out": r.stdout.strip()[-2000:]}
        trees = {}
        for name, img in (("clean", clean_img), ("run", raw)):
            d = os.path.join(work, name)
            os.mkdir(d)
            # chown errors are expected (not root); modes and contents survive
            run("debugfs", "-R", "rdump / " + d, img)
            trees[name] = tree(d)
        a, b = trees["clean"], trees["run"]
        added = {p: v for p, v in b.items() if p not in a}
        deleted = {p: v for p, v in a.items() if p not in b}
        modified = []
        for p in sorted(set(a) & set(b)):
            if a[p] != b[p]:
                e = entry(p, b[p])
                e["was"] = entry(p, a[p])
                del e["was"]["path"]
                modified.append(e)
        renamed = []
        by_hash = {}
        for p, v in deleted.items():
            if v[0] == "file":
                by_hash.setdefault(v[2], []).append(p)
        for p, v in sorted(added.items()):
            src = by_hash.get(v[2]) if v[0] == "file" else None
            if src:
                renamed.append({"from": src.pop(0), "to": p, "sha256": v[2], "size": v[3]})
        moved_from = {r["from"] for r in renamed}
        moved_to = {r["to"] for r in renamed}
        res["added"] = [entry(p, v) for p, v in sorted(added.items()) if p not in moved_to]
        res["deleted"] = [entry(p, v) for p, v in sorted(deleted.items()) if p not in moved_from]
        res["modified"] = modified
        res["renamed"] = renamed
        for key in ("added", "deleted", "modified"):
            for e in res[key]:
                if e["path"] in baseline:
                    e["boot"] = True
        for e in renamed:
            if e["from"] in baseline or e["to"] in baseline:
                e["boot"] = True
        res["paths"] = sorted({e["path"] for k in ("added", "deleted", "modified")
                               for e in res[k]} | moved_from | moved_to)
        # keep what the run left behind: added, modified and renamed-to files
        keep = [e["path"] for e in res["added"] + res["modified"] if e["type"] in ("file", "link")]
        keep += sorted(moved_to)
        total = 0
        with tarfile.open(os.path.join(out, "fs-changed.tar.gz"), "w:gz") as t:
            for p in keep:
                v = b[p]
                if v[0] == "file" and total + v[3] > MAX_TAR:
                    res.setdefault("not_archived", []).append(p)
                    continue
                total += v[3]
                t.add(os.path.join(work, "run") + p, arcname=p.lstrip("/"), recursive=False)
    except Exception as e:
        res["error"] = repr(e)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    with open(os.path.join(out, "fsdiff.json"), "w") as f:
        json.dump(res, f, indent=1)


if __name__ == "__main__":
    main()
