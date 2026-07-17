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

    /* On-console internet relay client (docs/internet-relay-plan.md).

       Lets two consoles on DIFFERENT networks play an LDN game together with
       no PC on either end, by relaying LDN discovery/join AND game session
       traffic through a lan-play relay server. Speaks lan-play's protocol
       (UDP to server, [u8 type][payload]; keepalive 0x00, IPv4 0x01).

       Enabled per-console by dropping a config file at RelayConfigPath with a
       relay server address; absent = normal local-only LDN (shipped default).
       See LoadConfig. */
    namespace relay {

        /* Config file listing relay servers, one per line:
             MyServer 82.65.234.243:11455
             public   relay.example.com     (hostname, default port 11451)
           Address may be an IPv4 literal or a hostname (resolved via DNS at
           connect time); '#' and blank lines ignored. The list only feeds the
           picker - relay stays OFF (normal local LDN) until the user enables
           it and chooses a server in the Tesla overlay. */
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

        /* Thread-safe entry for the bsd:u mitm (its IPC threads, not the
           LANDiscovery worker that owns the transport). Wraps the payload and
           sends it to the relay. No-op (returns -1) when the relay transport
           is not open. dport is the game's destination port, host order. */
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
                   so peers can tell us apart. Returns success only when the
                   socket is ready. */
                Result Open();
                void Close();
                bool IsOpen() const { return m_fd >= 0; }
                int GetFd() const { return m_fd; }
                u32 GetVirtualSrc() const { return m_vsrc; }

                /* Wrap a LANPacket as an IPv4/UDP broadcast (from our virtual
                   src to 10.13.255.255:11452) and send it to the relay. */
                int SendBroadcast(const void *lan_packet, size_t size);

                /* Keep our registration alive when we are otherwise silent
                   (e.g. an idle host). Call periodically from the worker. */
                int SendKeepalive();

                /* Receive one relay frame. A type-0x01 IPv4/UDP frame to port
                   11452 (LDN discovery) is copied into out (returns its
                   length); a frame to any other port is a peer game frame and
                   is handed to the game via the GameRx queue (returns 0).
                   Returns 0 on timeout/other frames, <0 on error. Also outputs
                   the frame's source virtual IP (host order). */
                int RecvBroadcast(void *out, size_t max_size, u32 *out_src_ip);

                /* Wrap a game datagram as IPv4/UDP (src = our REAL IP, dst =
                   255.255.255.255, sport = dport - the true source port is
                   not visible in the SendTo hook; symmetric game protocols
                   send port N -> port N) and send it to the relay. Called via
                   BridgeSendGameBroadcast from bsd:u mitm threads. */
                int SendGameBroadcast(const void *payload, size_t len, u16 dport);

                /* As SendGameBroadcast but dst = dst_ip (host order) for
                   unicast session traffic routed to a specific peer. */
                int SendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip);

            private:
                /* Resolve a hostname to an IPv4 (host order) with a hand-built
                   DNS query over an nifm-registered socket. 0 on failure. */
                u32 ResolveHostname(const char *host);

                /* Queue one relay-received peer game frame for the game to
                   receive via the bsd:u mitm's RecvFrom (with the peer's real
                   source address - the stack cannot deliver a spoofed source
                   locally, so we serve it directly). */
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
