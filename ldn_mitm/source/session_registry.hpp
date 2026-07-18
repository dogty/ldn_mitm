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

    /* In-process handoff from LANDiscovery to the bsd:u mitm: LANDiscovery
       publishes the current peer set, the bsd handler snapshots it to convert
       broadcast sends into per-peer unicast. Own mutex - no lock-order
       coupling with LANDiscovery. IPs host byte order. */
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

    /* Internet-relay receive queue (docs/internet-relay-plan.md option a): the
       relay worker pushes peer game frames, the bsd:u RecvFrom pops them and
       serves them with the peer's real source address (the local stack can't
       deliver a spoofed source, so this bypasses it), and Poll reports the
       game socket readable while non-empty. Own mutex. */
    class GameRx {
        public:
            static constexpr int  MaxEntries = 32;
            static constexpr int  MaxPayload = 1472;   /* observed recv bufsize */

            /* Record the game's session socket fd (from a broadcast SendTo),
               so RecvFrom/Poll only act on that fd. -1 = none. */
            static void SetGameFd(s32 fd);
            static s32  GameFd();

            /* Relay worker: enqueue a peer game frame. src_ip/ports host order.
               Drops the oldest entry if full. */
            static void Push(u32 src_ip, u16 sport, u16 dport, const void *data, size_t len);

            /* bsd RecvFrom handler: dequeue the oldest frame. Returns false if
               empty. Copies up to max_len bytes; out_len is the real length. */
            static bool Pop(u32 *src_ip, u16 *sport, void *out, size_t max_len, size_t *out_len);

            /* Destination port of the oldest queued frame (host order), or 0
               if the queue is empty. Used to verify a socket's bound port
               before latching it as the game session fd. */
            static u16 PeekDport();

            static bool HasData();

            /* Session torn down: drop everything and forget the fd. */
            static void Clear();
    };

}
