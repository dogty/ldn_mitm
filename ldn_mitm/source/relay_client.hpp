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

    /* On-console internet relay client (docs/internet-relay-plan.md): two
       consoles on different networks play an LDN game with no PC, by relaying
       LDN discovery/join and game traffic through a lan-play relay server
       (UDP, [u8 type][payload]; keepalive 0x00, IPv4 0x01). Off unless
       configured AND enabled in the overlay. */
    namespace relay {

        /* Server list config; format documented at LoadConfig (relay_client.cpp). */
        constexpr const char RelayConfigPath[] = "sdmc:/config/ldn_mitm/relay.cfg";
        constexpr int MaxServers    = 8;
        constexpr int ServerNameLen = 32;

        /* Read RelayConfigPath into the server list. Call once at startup
           (from Main). Safe if the file is missing. */
        void LoadConfig();

        /* Effective relay gate: user enabled it AND a server is configured.
           When true, LANDiscovery keeps the console on the internet and
           mirrors discovery/join over the relay, and the bsd:u mitm relays +
           serves game session traffic. When false, shipped local-only LDN. */
        bool IsEnabled();

        /* Runtime on/off toggle (independent of whether servers exist), and
           the server picker - all driven by the Tesla overlay via the config
           IPC service. */
        void SetRelayEnabled(bool on);
        /* Rewrite relay.cfg's directive lines (enabled/broadcast/selected)
           from current runtime state; called by the config service when the
           broadcast-relay toggle changes (the other setters persist
           themselves). */
        void PersistSettings();
        bool GetRelayEnabled();
        int  ServerCount();
        const char *ServerName(int index);   /* "" if out of range */
        int  SelectedServer();
        void SelectServer(int index);

        /* Selected relay server. ServerIp is the literal IPv4 (host order) or
           0 for a hostname; ServerHost is the raw address token (RelayTransport
           resolves a hostname at connect time). Valid when IsEnabled(). */
        u32 ServerIp();
        const char *ServerHost();
        u16 ServerPort();

        /* Thread-safe entry for bsd:u IPC threads: wrap the payload and send to
           the relay. Returns -1 when the transport is closed. dport host order. */
        int BridgeSendGameBroadcast(const void *payload, size_t len, u16 dport);

        /* Like BridgeSendGameBroadcast but for a unicast to a specific peer:
           wraps the payload with dst = dst_ip (host order) so the relay routes
           it to the client that owns that address. Games that switch from a
           broadcast handshake to unicast session traffic need this - the peer
           IP is unroutable across the internet otherwise. */
        int BridgeSendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip);

        /* Reusable relay socket: the proven observer setup (internet nifm
           request + registered UDP socket connected to the relay) plus
           helpers to send/recv a LANPacket as an IPv4/UDP broadcast frame.
           Not thread-safe; owned and driven by one LANDiscovery worker. */
        class RelayTransport {
            public:
                RelayTransport() = default;
                ~RelayTransport() { this->Close(); }

                /* Acquire internet, open+register+connect the socket. The
                   virtual src (10.13.<ip3>.<ip4>) is derived from our real IP
                   so peers can tell us apart. */
                Result Open();
                void Close();
                bool IsOpen() const { return m_fd >= 0; }
                int GetFd() const { return m_fd; }

                /* Wrap a LANPacket as an IPv4/UDP broadcast (virtual src ->
                   10.13.255.255:11452) and send it to the relay. */
                int SendBroadcast(const void *lan_packet, size_t size);

                /* Keep our registration alive while otherwise silent (an idle
                   host). Call periodically from the worker. */
                int SendKeepalive();

                /* Receive one relay frame. A discovery frame (UDP dst 11452) is
                   copied to out (returns length, sets *out_src_ip to its virtual
                   IP); a peer game frame is handed to GameRx (returns 0). <0 on
                   error. */
                int RecvBroadcast(void *out, size_t max_size, u32 *out_src_ip);

                /* Wrap a game datagram (src = our real IP, dst = 255.255.255.255,
                   sport = dport) and send to the relay. Called from bsd:u mitm
                   threads via BridgeSendGameBroadcast. */
                int SendGameBroadcast(const void *payload, size_t len, u16 dport);

                /* As SendGameBroadcast but dst = dst_ip (host order): the relay
                   routes it to the owning peer. */
                int SendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip);

            private:
                /* Build [0x01][IPv4+UDP+payload] and send to the relay. */
                int SendWrapped(u32 src, u32 dst, u16 sport, u16 dport, u16 ip_id, const void *payload, size_t len);

                /* Resolve a hostname to IPv4 (host order) via a hand-built DNS
                   query (libnx getaddrinfo aborts in this sysmodule). 0 on
                   failure. */
                u32 ResolveHostname(const char *host);

                /* Queue a relay-received peer frame for the bsd:u RecvFrom to
                   serve with the peer's real source address. */
                void InjectGameFrame(const u8 *ip, size_t iplen);

                int m_fd = -1;
                NifmRequest m_req{};
                bool m_have_req = false;
                bool m_have_nifm_session = false;
                u32 m_vsrc = 0;
                u32 m_rsrc = 0;   /* our REAL IP, host order */
        };

    }

}
