# Guest-side process monitor. Run as:
#   /usr/libexec/sbx/sh /usr/libexec/sbx/mon.sh >/dev/console 2>&1 &
# where /usr/libexec/sbx/sh is a renamed copy of the image's busybox.
#
# Written to survive Mirai-style killers, which kill by exe path and name:
# - the binary's path holds no common blacklist substring (/tmp, /var,
#   busybox, arch names, ...) and contains "sh" (a frequent whitelist entry);
# - its argv has no ps/top/ss/netstat-style substrings;
# - it uses shell builtins only (read, echo, globbing); the one external,
#   sleep, is a hard link to the same busybox copy, never /bin/busybox,
#   which such killers target.
# Output: one "SBXMON" line per process per tick, plus /dev/shm contents.
PATH=/usr/libexec/sbx/bin
echo $$ >/var/run/sbxmon.pid
tick=0
while :; do
    read up _ </proc/uptime
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        st=
        read st <"$d/stat" 2>/dev/null || continue
        rest=${st#*) }
        comm=${st#*(}; comm=${comm%%)*}
        set -- $rest
        echo "SBXMON t=$up pid=$p ppid=$2 state=$1 comm=$comm"
    done
    for f in /dev/shm/* /dev/shm/.[!.]*; do
        [ -e "$f" ] || continue
        echo "SBXMON t=$up shm=$f"
        if [ "$f" = /dev/shm/.comm ]; then
            while read l; do echo "SBXMON t=$up shm_comm=$l"; done <"$f"
        fi
    done
    echo "SBXMON t=$up tick=$tick"
    tick=$((tick + 1))
    sleep 3
done
