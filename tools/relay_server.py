#!/usr/bin/env python3
"""
A tiny self-hosted relay server for ldn_mitm's internet play (and for
switch-lan-play in general). Run it on a machine both players can reach - a
low-latency VPS between the players is ideal - then list its address in each
console's sdmc:/config/ldn_mitm/relay.cfg and pick it in the Tesla overlay.

It speaks lan-play's client<->server protocol: UDP, each datagram is
[u8 type][payload].
  type 0x00 KEEPALIVE  - empty; refreshes the idle timer for every IP already
                         learned from this endpoint. It carries no address, so
                         it CANNOT learn a new mapping - a client must send at
                         least one IPv4 frame (ldn_mitm re-broadcasts its
                         advertisement periodically) before it is routable.
  type 0x01 IPV4       - payload is a bare IPv4 packet (IP header + L4 + data)
  (other types are ignored)

Routing, exactly like a real lan-play server:
  - source-learn: map the IPv4 packet's SRC address to the UDP endpoint it
    came from.
  - forward by DST address:
      broadcast (x.x.x.255 / 255.255.255.255) -> every OTHER learned client
      unicast                                 -> the client that owns that IP
  - clients idle for >60s are expired.

Requires only Python 3 (no dependencies).

Usage:
    python relay_server.py                 # bind 0.0.0.0:11451
    python relay_server.py --port 11455
    python relay_server.py -v              # log every relayed packet

For play across the internet, forward the chosen UDP port to this machine and
give the players this machine's PUBLIC IP (or a hostname) and port.
"""
import argparse
import socket
import struct
import time

TYPE_KEEPALIVE = 0x00
TYPE_IPV4 = 0x01
IDLE_TIMEOUT = 60.0  # seconds before a silent client is forgotten


def ip_str(b):
    return ".".join(str(x) for x in b)


def is_broadcast(dst4):
    # 255.255.255.255 or a directed broadcast (last octet 255).
    return dst4 == b"\xff\xff\xff\xff" or dst4[3] == 0xFF


def main():
    ap = argparse.ArgumentParser(description="Self-hosted lan-play/ldn_mitm relay server.")
    ap.add_argument("--port", "-p", type=int, default=11451, help="UDP port to bind (default 11451)")
    ap.add_argument("--bind", default="0.0.0.0", help="address to bind (default 0.0.0.0)")
    ap.add_argument("--verbose", "-v", action="store_true", help="log every relayed packet")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print(f"[relay] listening on {args.bind}:{args.port} (Ctrl-C to stop)")

    # virtual-src (4 bytes) -> (udp_endpoint, last_seen)
    clients = {}
    # udp_endpoint -> True, so a brand-new endpoint is announced once
    endpoints = {}

    def active_endpoints(now, exclude=None):
        """Live client endpoints (deduped, idle ones expired)."""
        eps = set()
        for vsrc, (ep, seen) in list(clients.items()):
            if now - seen > IDLE_TIMEOUT:
                del clients[vsrc]
                continue
            if ep != exclude:
                eps.add(ep)
        return eps

    while True:
        try:
            data, addr = sock.recvfrom(4096)
        except ConnectionResetError:
            # Windows: a prior send to a since-closed port bounced.
            continue
        if not data:
            continue

        if addr not in endpoints:
            endpoints[addr] = True
            print(f"[relay] new client {addr[0]}:{addr[1]}  ({len(active_endpoints(time.time())) + 1} online)")

        now = time.time()
        msg_type, payload = data[0], data[1:]

        if msg_type == TYPE_KEEPALIVE:
            # Refresh every IP already learned from this endpoint. A keepalive
            # carries no address, so it can only refresh - never learn - a
            # mapping; a still-idle but unlearned client stays unroutable until
            # it sends an IPv4 frame (which ldn_mitm does via its periodic
            # advertisement re-broadcast).
            for vsrc, (ep, _) in list(clients.items()):
                if ep == addr:
                    clients[vsrc] = (ep, now)
            continue

        if msg_type != TYPE_IPV4 or len(payload) < 20:
            continue

        src4 = payload[12:16]
        dst4 = payload[16:20]

        prev = clients.get(src4)
        clients[src4] = (addr, now)
        if prev is None or prev[0] != addr:
            print(f"[relay] learn {ip_str(src4)} -> {addr[0]}:{addr[1]}")

        if is_broadcast(dst4):
            sent = 0
            for ep in active_endpoints(now, exclude=addr):
                try:
                    sock.sendto(data, ep)
                    sent += 1
                except OSError:
                    pass
            if args.verbose:
                print(f"[relay] bcast {ip_str(src4)} -> {ip_str(dst4)} "
                      f"({len(payload)}B) x{sent}")
        else:
            owner = clients.get(dst4)
            if owner and owner[0] != addr:
                try:
                    sock.sendto(data, owner[0])
                    if args.verbose:
                        print(f"[relay] ucast {ip_str(src4)} -> {ip_str(dst4)} ({len(payload)}B)")
                except OSError:
                    pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[relay] stopped")
