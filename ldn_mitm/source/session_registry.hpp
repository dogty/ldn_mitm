/*
 * Copyright (c) 2018 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include <switch.h>
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* Shared, in-process handoff from LANDiscovery (the LDN session) to the
       bsd:u mitm (the socket path). LANDiscovery publishes the current peer
       set; the bsd handler reads a snapshot to convert LDN broadcast sends
       into per-peer unicast. Guarded by its own mutex so the bsd hot path
       never touches LANDiscovery's data/poll mutexes (no lock-order coupling
       between the two services). All IPs are host byte order. */
    class SessionRegistry {
        public:
            static constexpr int MaxPeers = 8;
            struct Snapshot {
                bool active;
                u32  bcast_ip;               /* LDN subnet broadcast, host order */
                int  peer_count;
                u32  peer_ips[MaxPeers];     /* other consoles, excludes self */
            };

            /* Called by LANDiscovery whenever the node set changes. Publishes
               the peers to unicast to. bcast_ip is the subnet broadcast the
               game targets; peers excludes self. */
            static void Publish(u32 bcast_ip, const u32 *peer_ips, int peer_count);

            /* Session torn down: stop converting. */
            static void Clear();

            /* Read a consistent snapshot (bsd handler, per SendTo). */
            static void Get(Snapshot *out);
    };

    /* Internet-relay receive queue (docs/internet-relay-plan.md option a).
       The relay worker pushes game session frames received from remote peers;
       the bsd:u mitm's RecvFrom handler pops them and serves them to the game
       with the peer's real source address, and its Poll handler reports the
       game socket readable while the queue is non-empty. This bypasses the
       network stack entirely for delivery (the stack does not loop back raw
       sends, and a dgram to our own IP would carry our own source), so it is
       the only way to give the game the peer's source IP. Mutex-guarded;
       independent of SessionRegistry's mutex. */
    class GameRx {
        public:
            static constexpr int  MaxEntries = 32;
            static constexpr int  MaxPayload = 1472;   /* observed recv bufsize */

            /* Record the game's session socket fd (from a broadcast SendTo),
               so RecvFrom/Poll only act on that fd. -1 = none. */
            static void SetGameFd(s32 fd);
            static s32  GameFd();

            /* Relay worker: enqueue a peer game frame. src_ip/ports host order.
               Drops the oldest entry if full. No-op if no game fd is known. */
            static void Push(u32 src_ip, u16 sport, u16 dport, const void *data, size_t len);

            /* bsd RecvFrom handler: dequeue the oldest frame. Returns false if
               empty. Copies up to max_len bytes; out_len is the real length. */
            static bool Pop(u32 *src_ip, u16 *sport, u16 *dport, void *out, size_t max_len, size_t *out_len);

            /* Destination port of the oldest queued frame (host order), or 0
               if the queue is empty. Used to verify a socket's bound port
               before latching it as the game session fd. */
            static u16 PeekDport();

            static bool HasData();

            /* Session torn down: drop everything and forget the fd. */
            static void Clear();
    };

}
