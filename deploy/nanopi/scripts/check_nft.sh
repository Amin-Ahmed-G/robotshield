#!/bin/bash
# ExecStartPre guard: refuse to start the firewall if the host rules are not
# loaded, or if forwarding is enabled, since then the gateway is not the only path.
set -e
nft list table inet robot_fw > /dev/null 2>&1 || {
    echo "robot_fw nftables table not loaded; refusing to start" >&2; exit 1; }
[ "$(cat /proc/sys/net/ipv4/ip_forward)" = "0" ] || {
    echo "net.ipv4.ip_forward is enabled; refusing to start" >&2; exit 1; }
