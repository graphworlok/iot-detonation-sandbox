#!/bin/sh
# sbx-net.sh up|down|status
#
# Builds the sandbox network:
#   sbx0        bridge, no IPv4/IPv6 on the host side (host is not reachable from it)
#   sbxsink     network namespace holding the traffic sink (10.200.0.1/24)
#   sbx-sinkbr  veth end on the bridge (the only non-isolated bridge port)
#   eth0        veth end inside sbxsink
# Guest taps are added by sbx-run and marked "isolated", so guests can talk
# to the sink but not to each other. There is no uplink: nothing on sbx0 is
# routed or bridged to a physical interface.
set -eu

BR=sbx0
NS=sbxsink
SINK_IP=10.200.0.1/24
NFT_HOST=/opt/sbx/host/nft-host.nft
NFT_SINK=/opt/sbx/sink/nft-sink.nft

up() {
    # br_netfilter (e.g. pulled in by Docker) would push bridged frames through
    # the inet hooks, where nft-host.nft drops them: fails closed, but confusing.
    if [ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] &&
       [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables)" = 1 ]; then
        echo "br_netfilter is active; sandbox traffic would be dropped by nft-host.nft" >&2
        exit 1
    fi
    # host-side: refuse to forward anything, and drop anything arriving from sbx*
    sysctl -q -w net.ipv4.ip_forward=0
    nft -f "$NFT_HOST"

    if ! ip link show "$BR" >/dev/null 2>&1; then
        ip link add "$BR" type bridge
    fi
    sysctl -q -w "net.ipv6.conf.$BR.disable_ipv6=1"
    ip addr flush dev "$BR"
    ip link set "$BR" up

    if ! ip netns list | grep -qw "$NS"; then
        ip netns add "$NS"
    fi
    if ! ip link show sbx-sinkbr >/dev/null 2>&1; then
        ip link add sbx-sinkbr type veth peer name eth0 netns "$NS"
    fi
    sysctl -q -w net.ipv6.conf.sbx-sinkbr.disable_ipv6=1
    ip link set sbx-sinkbr master "$BR" up

    ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
    ip netns exec "$NS" sysctl -q -w net.ipv4.ip_forward=0
    ip netns exec "$NS" ip link set lo up
    ip netns exec "$NS" ip addr replace "$SINK_IP" dev eth0
    ip netns exec "$NS" ip link set eth0 up
    # sink answers for every address: replies to DNATed traffic leave via eth0
    ip netns exec "$NS" ip route replace default dev eth0
    ip netns exec "$NS" nft -f "$NFT_SINK"
}

down() {
    for t in $(ip -o link show | awk -F': ' '{print $2}' | grep '^sbxtap' || true); do
        ip link del "$t" || true
    done
    ip link del sbx-sinkbr 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$BR" 2>/dev/null || true
    nft delete table inet sbx_host 2>/dev/null || true
}

status() {
    ip -br link show master "$BR" 2>/dev/null || echo "no $BR"
    ip -br addr show "$BR" 2>/dev/null || true
    bridge -d link show 2>/dev/null | grep -E 'sbx|isolated' || true
    ip netns exec "$NS" ip -br addr 2>/dev/null || echo "no $NS"
    nft list table inet sbx_host 2>/dev/null | head -20 || true
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    status) status ;;
    *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
