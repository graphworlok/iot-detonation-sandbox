"""Syscall tracer that runs outside the guest, through QEMU's gdb stub.

Loaded by sbx-run as:
    gdb-multiarch -nx -batch -ex "python SBX_CFG='/srv/sandbox/tmp/<id>/trace.json'" -x sbx-trace.py

Nothing runs inside the guest: breakpoints are QEMU (TCG) breakpoints, so a
sample cannot see or kill the tracer. Kernel symbols are not needed (OpenWrt
kernels ship without kallsyms):

1. The syscall table is found in the kernel image by shape: a run of ~460
   pointers into .text, mostly distinct, whose unimplemented slots all point
   at the same stub (sys_ni_syscall).
2. Breakpoints go on the handlers of the syscalls in TRACE. At handler entry
   the user arguments are in the argument registers.
3. The current task is read from the thread_info pointer the kernel keeps in
   a register ($gp on MIPS). The pid/tgid and comm offsets inside task_struct
   are calibrated at start-up: sbx-run makes the console shell (known PID,
   comm "ash") call kill(own pid, 0), and the tracer searches that task_struct
   for the PID pair and the name.

Implemented for MIPS o32 (big- and little-endian). Other ABIs need their own
syscall numbers, argument registers and "current task" expression.

Output: one JSON object per event in cfg["out"]; progress lines in
cfg["status"] (READY, TRACING, or FAIL <reason>).
"""
import json
import struct
import time

import gdb

CFG = json.load(open(SBX_CFG))  # noqa: F821 (set by -ex on the command line)
BE = CFG["endian"] == "big"
U32 = ">I" if BE else "<I"

# MIPS o32 syscall numbers (arch/mips/kernel/syscalls/syscall_o32.tbl)
O32 = {
    "exit": 4001, "fork": 4002, "unlink": 4010, "execve": 4011, "chdir": 4012,
    "kill": 4037, "rename": 4038, "setsid": 4066, "reboot": 4088,
    "clone": 4120, "connect": 4170, "bind": 4169, "listen": 4174,
    "sendto": 4180, "socket": 4183, "prctl": 4192, "vfork": 4190,
    "exit_group": 4246, "unlinkat": 4294, "ptrace": 4026,
    "open": 4005, "openat": 4288,
}
NI_SLOTS = [17, 31, 32, 35, 44, 53, 56, 58]  # break stty gtty ftime prof lock mpx ulimit
TRACE = ["exit", "fork", "unlink", "execve", "chdir", "kill", "rename", "setsid",
         "reboot", "clone", "connect", "bind", "listen", "sendto", "socket",
         "prctl", "vfork", "exit_group", "unlinkat", "ptrace"]
if CFG.get("trace_open"):
    TRACE += ["open", "openat"]
RETURN_FOR = {"fork", "clone", "vfork", "connect", "bind", "socket"}

out = open(CFG["out"], "a", buffering=1)
status = open(CFG["status"], "a", buffering=1)
offsets = {}
# Breakpoints cannot be added or removed while a remote target runs (all-stop
# mode), so stop() handlers that need that queue the change here and return
# True; the main loop applies it with the guest halted and continues.
pending = []


def say(msg):
    status.write(msg + "\n")


def emit(ev):
    ev["t"] = round(time.time(), 3)
    out.write(json.dumps(ev, separators=(",", ":")) + "\n")


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & 0xFFFFFFFF


def mem(addr, n):
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, n))
    except gdb.MemoryError:
        return None


def u32(addr):
    b = mem(addr, 4)
    return struct.unpack(U32, b)[0] if b else None


def cstr(addr, n=256):
    if not addr:
        return None
    b = mem(addr, n)
    if b is None:
        # the page may straddle; try a shorter read
        b = mem(addr, 32)
        if b is None:
            return "<unreadable>"
    return b.split(b"\0")[0].decode("latin-1")


def sockaddr(addr, ln):
    b = mem(addr, min(max(ln, 2), 32)) if addr else None
    if not b or len(b) < 2:
        return None
    fam = struct.unpack(">H" if BE else "<H", b[:2])[0]
    if fam == 2 and len(b) >= 8:
        port = struct.unpack(">H", b[2:4])[0]
        return "%d.%d.%d.%d:%d" % (b[4], b[5], b[6], b[7], port)
    if fam == 1:
        return "unix:" + b[2:].split(b"\0")[0].decode("latin-1")
    return "family=%d" % fam


def current():
    task = u32(reg("gp"))
    info = {"task": hex(task) if task else None}
    if task and offsets:
        p = mem(task + offsets["pid"], 8)
        if p:
            info["pid"], info["tgid"] = struct.unpack(U32[0] + "II", p)
        c = mem(task + offsets["comm"], 16)
        if c:
            info["comm"] = c.split(b"\0")[0].decode("latin-1")
    return info


def find_table(path):
    f = open(path, "rb").read()
    e = ">" if f[5] == 2 else "<"
    shoff = struct.unpack_from(e + "I", f, 32)[0]
    shes, shn, shstr = struct.unpack_from(e + "HHH", f, 46)
    sh = [struct.unpack_from(e + "10I", f, shoff + i * shes) for i in range(shn)]
    names = f[sh[shstr][4]:]
    secs = [(names[s[0]:].split(b"\0")[0].decode(), s[3], s[4], s[5], s[1]) for s in sh]
    text = [s for s in secs if s[0] == ".text"][0]
    lo, hi = text[1], text[1] + text[3]
    found = []
    for name, addr, off, size, typ in secs:
        if not addr or typ == 8 or size < 2000:
            continue
        words = struct.unpack_from(e + "%dI" % (size // 4), f, off)
        for i in range(len(words) - 470):
            v = words[i + 17]
            if not lo <= v < hi or any(words[i + k] != v for k in NI_SLOTS):
                continue
            win = words[i:i + 463]
            if sum(1 for w in win if lo <= w < hi) >= 455 and len(set(win)) > 300:
                found.append((addr + 4 * i, win))
    if len(found) != 1:
        raise RuntimeError("syscall table: %d candidates" % len(found))
    return found[0]


class ReturnBP(gdb.Breakpoint):
    """One-shot breakpoint on the syscall return path for one task.

    The return address is shared by every syscall, so hits from other tasks
    (different thread_info in $gp) are ignored."""

    def __init__(self, addr, gp, ev):
        super().__init__("*0x%x" % addr, internal=True, temporary=False)
        self.gp, self.ev, self.done = gp, ev, False

    def stop(self):
        if self.done or reg("gp") != self.gp:
            return False
        self.done = True
        # right after the handler returns, v0 is the raw kernel result:
        # -errno for failures (handle_sys converts it to a3/errno later)
        v0 = reg("v0")
        if v0 >= 0xFFFFF001:
            self.ev["errno"] = 0x100000000 - v0
        else:
            self.ev["ret"] = v0
        emit(self.ev)
        pending.append(self.delete)
        return True


class SyscallBP(gdb.Breakpoint):
    def __init__(self, name, addr):
        super().__init__("*0x%x" % addr, internal=True)
        self.name = name

    def stop(self):
        a = [reg(r) for r in ("a0", "a1", "a2", "a3")]
        ev = {"sys": self.name}
        ev.update(current())
        n = self.name
        if n == "execve":
            ev["path"] = cstr(a[0])
            argv = []
            for i in range(16):
                p = u32(a[1] + 4 * i) if a[1] else None
                if not p:
                    break
                argv.append(cstr(p, 128))
            ev["argv"] = argv
        elif n in ("unlink", "chdir", "open"):
            ev["path"] = cstr(a[0])
        elif n in ("unlinkat", "openat"):
            ev["path"] = cstr(a[1])
        elif n == "rename":
            ev["from"], ev["to"] = cstr(a[0]), cstr(a[1])
        elif n == "kill":
            ev["target_pid"] = a[0] - (1 << 32) if a[0] & 0x80000000 else a[0]
            ev["sig"] = a[1]
        elif n == "prctl":
            ev["option"] = a[0]
            if a[0] == 15:       # PR_SET_NAME
                ev["name"] = cstr(a[1], 16)
        elif n in ("connect", "bind"):
            ev["fd"], ev["addr"] = a[0], sockaddr(a[1], a[2])
        elif n == "socket":
            ev["domain"], ev["type"], ev["proto"] = a[0], a[1], a[2]
        elif n == "sendto":
            ev["fd"], ev["len"] = a[0], a[2]
        elif n in ("exit", "exit_group"):
            ev["code"] = a[0]
        elif n == "reboot":
            ev["cmd"] = hex(a[2])
        else:
            ev["args"] = [hex(x) for x in a]
        emit(ev)
        if n in RETURN_FOR:
            # the result (child PID, connect status, socket fd) arrives on
            # the return path; the entry event is logged first in case the
            # task dies before returning
            gp, ra = reg("gp"), reg("ra")
            ret = {k: ev[k] for k in ("sys", "pid", "tgid", "comm") if k in ev}
            ret["phase"] = "return"
            pending.append(lambda: ReturnBP(ra, gp, ret))
            return True
        return False


class CalibrateBP(gdb.Breakpoint):
    """Waits for the console shell's kill(own pid, 0) and finds the offsets."""

    def __init__(self, addr, shell_pid, handlers):
        super().__init__("*0x%x" % addr, internal=True)
        self.pid, self.handlers, self.done = shell_pid, handlers, False

    def stop(self):
        if self.done or reg("a0") != self.pid or reg("a1") != 0:
            return False
        self.done = True
        task = u32(reg("gp"))
        blob = mem(task, 0x1800) if task else None
        if not blob:
            say("FAIL cannot read task_struct at gp=%#x" % reg("gp"))
            return False
        pidpair = struct.pack(U32[0] + "II", self.pid, self.pid)
        pid_off = blob.find(pidpair)
        comm_off = blob.find(b"ash\0")
        if pid_off < 0 or comm_off < 0:
            say("FAIL calibration pid_off=%d comm_off=%d" % (pid_off, comm_off))
            return False
        offsets.update(pid=pid_off, comm=comm_off)
        emit({"sys": "calibrated", "task": hex(task), "pid_off": pid_off,
              "comm_off": comm_off, "shell_pid": self.pid})

        def install():
            self.delete()
            for name, addr in self.handlers.items():
                SyscallBP(name, addr)
            say("TRACING %s" % json.dumps({"offsets": offsets, "syscalls": sorted(self.handlers)}))
        pending.append(install)
        return True


def main():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set architecture mips:isa32r2")
    gdb.execute("set endian %s" % ("big" if BE else "little"))
    base, table = find_table(CFG["kernel"])
    handlers = {n: table[O32[n] - 4000] for n in TRACE}
    emit({"sys": "table", "base": hex(base),
          "handlers": {n: hex(a) for n, a in handlers.items()}})
    gdb.execute("target remote 127.0.0.1:%d" % CFG["port"])
    CalibrateBP(handlers["kill"], CFG["shell_pid"], handlers)
    say("READY table=%#x" % base)
    while True:
        try:
            gdb.execute("continue", to_string=True)
        except gdb.error as e:      # QEMU gone: the run is over
            say("END %s" % e)
            return
        if not gdb.selected_inferior().pid:
            say("END target exited")
            return
        while pending:
            pending.pop(0)()


try:
    main()
except Exception as e:  # report and let QEMU run on untraced
    say("FAIL %r" % e)
    try:
        gdb.execute("detach")
    except gdb.error:
        pass
