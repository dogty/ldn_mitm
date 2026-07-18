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

#include "relay_client.hpp"
#include "debug.hpp"
#include "nifm_manager.hpp"
#include "session_registry.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <sys/time.h>
#include <atomic>
#include <mutex>
#include <cstdio>

namespace ams::mitm::ldn::relay {

    namespace {
        /* lan-play relay message types (switch-lan-play/src/lan-client.c). */
        constexpr u8 TypeKeepalive = 0x00;
        constexpr u8 TypeIpv4      = 0x01;

        /* Largest game/LAN payload we can wrap: the 1500-byte frame buffer
           minus the 1-byte relay type, 20-byte IPv4 header and 8-byte UDP
           header (1500 - 29). A full MTU-1500 datagram carries up to 1472
           payload bytes, but 1472 would need a 1501-byte buffer; the games
           that push near-MTU frames (pia titles) still fit under this. A
           tighter cap silently dropped valid 1401-1471 byte datagrams. */
        constexpr size_t MaxWrapPayload = 1500 - 1 - 20 - 8; /* 1471 */

        /* IPv4 header checksum (16-bit ones-complement over the header). */
        u16 IpChecksum(const u8 *d, size_t n) {
            u32 s = 0;
            for (size_t i = 0; i + 1 < n; i += 2) {
                s += (static_cast<u32>(d[i]) << 8) | d[i + 1];
            }
            if (n & 1) {
                s += static_cast<u32>(d[n - 1]) << 8;
            }
            while (s >> 16) {
                s = (s & 0xffff) + (s >> 16);
            }
            return static_cast<u16>(~s & 0xffff);
        }

        /* Relay server list, parsed from RelayConfigPath by LoadConfig().
           host holds the raw address token (an IPv4 literal or a hostname);
           ip is the parsed literal in host order, or 0 for a hostname that
           must be resolved at connect time. */
        struct Server { char name[ServerNameLen]; char host[64]; u32 ip; u16 port; };
        Server g_servers[MaxServers];
        int g_count = 0;
        /* Runtime state, driven by the Tesla overlay. Relay is OFF by default
           even when servers are configured, so normal LOCAL LDN is unaffected
           until the user explicitly turns it on and picks a server. */
        std::atomic_int  g_selected{0};
        std::atomic_bool g_enabled{false};
    }

    void LoadConfig() {
        /* RelayConfigPath lists relay servers, one per line:
             MyServer 82.65.234.243:11455
             lan-play 1.2.3.4              (default port 11451)
           IPv4 only; lines starting with '#' and blank lines are ignored.
           An "enabled=1" line turns the relay on at boot; the Tesla overlay
           toggle rewrites it (SetRelayEnabled), so the choice survives
           reboots instead of silently resetting to off. */
        g_count = 0;
        g_selected = 0;
        g_enabled = false;

        fs::FileHandle f;
        if (R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Read))) {
            return;
        }
        s64 size = 0;
        char buf[1024] = {};
        if (R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size > 0) {
            const size_t n = static_cast<size_t>(size) < sizeof(buf) - 1
                                 ? static_cast<size_t>(size) : sizeof(buf) - 1;
            if (R_SUCCEEDED(fs::ReadFile(f, 0, buf, n))) {
                buf[n] = '\0';
            }
        }
        fs::CloseFile(f);

        char *save = nullptr;
        for (char *line = strtok_r(buf, "\r\n", std::addressof(save));
             line != nullptr && g_count < MaxServers;
             line = strtok_r(nullptr, "\r\n", std::addressof(save))) {
            while (*line == ' ' || *line == '\t') { line++; }
            if (*line == '#' || *line == '\0') {
                continue;
            }
            /* Directive line, not a server: enabled=0/1. Must be matched
               before server parsing or it would register as a bogus server
               named "enabled=1". */
            if (std::strncmp(line, "enabled", 7) == 0 &&
                (line[7] == '\0' || line[7] == '=' || line[7] == ' ' || line[7] == '\t')) {
                const char *v = line + 7;
                while (*v == '=' || *v == ' ' || *v == '\t') { v++; }
                g_enabled = (std::atoi(v) != 0);
                continue;
            }
            char name[ServerNameLen] = {};
            char addr[64] = {};
            /* "Name Addr" or just "Addr" (name defaults to the address). */
            if (std::sscanf(line, "%31s %63s", name, addr) < 2) {
                if (std::sscanf(line, "%63s", addr) < 1) {
                    continue;
                }
                std::strncpy(name, addr, sizeof(name) - 1);
            }

            /* addr = "host[:port]"; host is an IPv4 literal or a hostname. */
            unsigned port = 11451;
            char *colon = std::strchr(addr, ':');
            if (colon != nullptr) {
                *colon = '\0';
                port = static_cast<unsigned>(std::atoi(colon + 1));
            }
            if (addr[0] == '\0' || port == 0 || port > 65535) {
                continue;
            }
            unsigned a = 0, b = 0, c = 0, d = 0;
            u32 ip = 0;
            if (std::sscanf(addr, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
                a <= 255 && b <= 255 && c <= 255 && d <= 255) {
                ip = (a << 24) | (b << 16) | (c << 8) | d;   /* literal IPv4 */
            }

            Server &s = g_servers[g_count];
            std::strncpy(s.name, name, sizeof(s.name) - 1);
            s.name[sizeof(s.name) - 1] = '\0';
            std::strncpy(s.host, addr, sizeof(s.host) - 1);
            s.host[sizeof(s.host) - 1] = '\0';
            s.ip   = ip;
            s.port = static_cast<u16>(port);
            g_count++;
        }
        LogFormat("relay: loaded %d server(s)", g_count);
    }

    namespace {
        /* Rewrite relay.cfg with the current enabled state as its first line,
           preserving every other line. Best-effort: a write failure only
           costs persistence across the next reboot, never the live toggle. */
        void PersistEnabled(bool on) {
            char buf[1024] = {};
            fs::FileHandle f;
            if (R_SUCCEEDED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Read))) {
                s64 size = 0;
                if (R_SUCCEEDED(fs::GetFileSize(std::addressof(size), f)) && size > 0) {
                    const size_t n = static_cast<size_t>(size) < sizeof(buf) - 1
                                         ? static_cast<size_t>(size) : sizeof(buf) - 1;
                    if (R_FAILED(fs::ReadFile(f, 0, buf, n))) {
                        buf[0] = '\0';
                    } else {
                        buf[n] = '\0';
                    }
                }
                fs::CloseFile(f);
            }

            char out[1152];
            size_t pos = static_cast<size_t>(std::snprintf(out, sizeof(out), "enabled=%d\n", on ? 1 : 0));
            char *save = nullptr;
            for (char *line = strtok_r(buf, "\r\n", std::addressof(save));
                 line != nullptr;
                 line = strtok_r(nullptr, "\r\n", std::addressof(save))) {
                const char *p = line;
                while (*p == ' ' || *p == '\t') { p++; }
                /* Drop old enabled lines; ours is already at the top. */
                if (std::strncmp(p, "enabled", 7) == 0 &&
                    (p[7] == '\0' || p[7] == '=' || p[7] == ' ' || p[7] == '\t')) {
                    continue;
                }
                const size_t need = std::strlen(line) + 1;
                if (pos + need >= sizeof(out)) {
                    break;
                }
                std::memcpy(out + pos, line, need - 1);
                out[pos + need - 1] = '\n';
                pos += need;
            }

            if (R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                if (R_FAILED(fs::CreateFile(RelayConfigPath, 0)) ||
                    R_FAILED(fs::OpenFile(std::addressof(f), RelayConfigPath, fs::OpenMode_Write | fs::OpenMode_AllowAppend))) {
                    LogFormat("relay: persisting enabled=%d failed (open)", on ? 1 : 0);
                    return;
                }
            }
            fs::SetFileSize(f, 0);
            if (R_FAILED(fs::WriteFile(f, 0, out, pos, fs::WriteOption::Flush))) {
                LogFormat("relay: persisting enabled=%d failed (write)", on ? 1 : 0);
            }
            fs::CloseFile(f);
        }
    }

    /* Effective gate: user turned it on AND at least one server exists. */
    bool IsEnabled()          { return g_enabled.load() && g_count > 0; }
    void SetRelayEnabled(bool on) { g_enabled = on; PersistEnabled(on); }
    bool GetRelayEnabled()    { return g_enabled.load(); }

    int  ServerCount()        { return g_count; }
    const char *ServerName(int i) { return (i >= 0 && i < g_count) ? g_servers[i].name : ""; }

    int  SelectedServer()     { return g_selected.load(); }
    void SelectServer(int i)  { if (i >= 0 && i < g_count) { g_selected = i; } }

    /* Selected server's literal IPv4 (host order), or 0 if it is a hostname
       (resolved by RelayTransport at connect time). */
    u32  ServerIp() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].ip : 0;
    }
    /* Selected server's raw address token (IP literal or hostname). */
    const char *ServerHost() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].host : "";
    }
    u16  ServerPort() {
        const int i = g_selected.load();
        return (i >= 0 && i < g_count) ? g_servers[i].port : 0;
    }

    /* ---- Game-traffic bridge (Phase 2 session traffic) ----
       The bsd:u mitm's IPC threads need to hand game payloads to the relay
       socket, which is owned by the LANDiscovery worker and torn down on
       finalize. A mutex-guarded global pointer gives them a safe rendezvous:
       Open() registers the transport, Close() unregisters it BEFORE anything
       is destroyed, and the send happens under the mutex, so a game send can
       never race the teardown into a use-after-close. sendto on a shared fd
       is atomic per datagram, and the fd is non-blocking, so holding the
       mutex across the send is cheap. */
    namespace {
        constinit os::SdkMutex g_bridge_mutex;
        constinit RelayTransport *g_bridge_transport = nullptr;
    }

    int BridgeSendGameBroadcast(const void *payload, size_t len, u16 dport) {
        std::scoped_lock lk(g_bridge_mutex);
        if (g_bridge_transport == nullptr) {
            return -1;
        }
        return g_bridge_transport->SendGameBroadcast(payload, len, dport);
    }

    int BridgeSendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        std::scoped_lock lk(g_bridge_mutex);
        if (g_bridge_transport == nullptr) {
            return -1;
        }
        return g_bridge_transport->SendGameUnicast(payload, len, dport, dst_ip);
    }

    /* ---- RelayTransport (Phase 1b step 2): reusable relay socket ---- */

    u32 RelayTransport::ResolveHostname(const char *host) {
        /* Minimal DNS A-record lookup, built by hand and sent over an
           nifm-registered socket (libnx getaddrinfo aborts in this sysmodule).
           Returns the first A record (host order), or 0 on any failure. */
        if (host == nullptr || host[0] == '\0') {
            return 0;
        }
        u32 a = 0, mask = 0, gw = 0, dns1 = 0, dns2 = 0;
        nifmGetCurrentIpConfigInfo(&a, &mask, &gw, &dns1, &dns2);

        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(53);
        srv.sin_addr.s_addr = (dns1 != 0) ? dns1 : htonl(0x08080808u); /* fall back to 8.8.8.8 */

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return 0;
        }
        if (m_have_req) {
            nifmRequestRegisterSocketDescriptor(&m_req, fd);
        }
        struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        auto cleanup = [&]() {
            if (m_have_req) { nifmRequestUnregisterSocketDescriptor(&m_req, fd); }
            close(fd);
        };

        /* Build the query. */
        u8 q[300];
        size_t p = 0;
        q[p++] = 0x13; q[p++] = 0x37;               /* id */
        q[p++] = 0x01; q[p++] = 0x00;               /* flags: standard query, RD */
        q[p++] = 0x00; q[p++] = 0x01;               /* qdcount 1 */
        q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; q[p++] = 0; /* an/ns/ar */
        const char *s = host;
        while (*s != '\0') {
            const char *dot = std::strchr(s, '.');
            const size_t len = dot ? static_cast<size_t>(dot - s) : std::strlen(s);
            if (len == 0 || len > 63 || p + len + 6 >= sizeof(q)) {
                cleanup();
                return 0;
            }
            q[p++] = static_cast<u8>(len);
            std::memcpy(q + p, s, len);
            p += len;
            s += len;
            if (*s == '.') { s++; }
        }
        q[p++] = 0x00;                              /* root label */
        q[p++] = 0x00; q[p++] = 0x01;              /* qtype A */
        q[p++] = 0x00; q[p++] = 0x01;              /* qclass IN */

        if (::sendto(fd, q, p, 0, reinterpret_cast<struct sockaddr *>(&srv), sizeof(srv)) < 0) {
            cleanup();
            return 0;
        }

        u8 r[512];
        const ssize_t n = ::recvfrom(fd, r, sizeof(r), 0, nullptr, nullptr);
        cleanup();
        if (n < 12) {
            return 0;
        }
        const int ancount = (r[6] << 8) | r[7];
        if (ancount < 1) {
            return 0;
        }

        /* Skip the question: walk the qname to its 0 terminator, then qtype +
           qclass (4 bytes). */
        size_t off = 12;
        while (off < static_cast<size_t>(n) && r[off] != 0) {
            if ((r[off] & 0xc0) == 0xc0) { off += 1; break; } /* compression ptr */
            off += r[off] + 1;
        }
        off += 1 + 4;

        for (int i = 0; i < ancount && off + 12 <= static_cast<size_t>(n); i++) {
            if ((r[off] & 0xc0) == 0xc0) {
                off += 2;
            } else {
                while (off < static_cast<size_t>(n) && r[off] != 0) { off += r[off] + 1; }
                off += 1;
            }
            if (off + 10 > static_cast<size_t>(n)) {
                break;
            }
            const int type  = (r[off] << 8) | r[off + 1];
            const int rdlen = (r[off + 8] << 8) | r[off + 9];
            off += 10;
            if (type == 1 && rdlen == 4 && off + 4 <= static_cast<size_t>(n)) {
                return (r[off] << 24) | (r[off + 1] << 16) | (r[off + 2] << 8) | r[off + 3];
            }
            off += rdlen;
        }
        return 0;
    }

    Result RelayTransport::Open() {
        /* Internet route (proven chain): nifm session + request + register the
           socket, deliberately NOT LocalNetworkMode. */
        Result rc = NifmSessionManager::Acquire();
        if (R_FAILED(rc)) {
            LogFormat("relay xport: nifm acquire failed %x", rc);
            return rc;
        }
        m_have_nifm_session = true;

        rc = nifmCreateRequest(&m_req, true);
        if (R_FAILED(rc)) {
            LogFormat("relay xport: nifmCreateRequest %x", rc);
            this->Close();
            return rc;
        }
        m_have_req = true;

        rc = nifmRequestSubmitAndWait(&m_req);
        if (R_FAILED(rc)) {
            LogFormat("relay xport: submit %x", rc);
            this->Close();
            return rc;
        }
        /* Let the link settle (submit can return before Available). */
        for (int i = 0; i < 10; i++) {
            NifmRequestState st = NifmRequestState_Invalid;
            if (R_FAILED(nifmGetRequestState(&m_req, &st)) || st == NifmRequestState_Available) {
                break;
            }
            svcSleepThread(500000000L); /* 0.5s */
        }

        /* Virtual src 10.13.<ip3>.<ip4> from our real IP, so peers tell us
           apart over the relay (and never see their own echo). The real IP is
           kept too: game frames are stamped with it (it is what NodeInfo
           advertises), so the peer's game accepts them as genuine LAN traffic. */
        u32 ip = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&ip))) {
            ip = ntohl(ip);
            m_rsrc = ip;
            m_vsrc = (10u << 24) | (13u << 16) | (((ip >> 8) & 0xff) << 8) | (ip & 0xff);
        } else {
            m_rsrc = 0;
            m_vsrc = (10u << 24) | (13u << 16) | 0x0001;
        }

        /* Resolve the server: a literal IP is used directly; a hostname is
           resolved by our own tiny DNS client (libnx's getaddrinfo aborts in
           this sysmodule - its resolver allocates through a path AMS does not
           support). 0 = bad/unresolvable -> fail and fall back to local LDN. */
        u32 server_ip = ServerIp();
        if (server_ip == 0) {
            server_ip = this->ResolveHostname(ServerHost());
        }
        if (server_ip == 0) {
            LogFormat("relay xport: no/unresolvable server address ('%s')", ServerHost());
            this->Close();
            return MAKERESULT(0xFD, 102);
        }

        const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LogFormat("relay xport: socket %d", errno);
            this->Close();
            return MAKERESULT(0xFD, 100);
        }

        struct sockaddr_in srv = {};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(ServerPort());
        srv.sin_addr.s_addr = htonl(server_ip);

        nifmRequestRegisterSocketDescriptor(&m_req, fd);

        /* Connect so recv only accepts the server and a local port binds.
           Short retry: LANDiscovery init runs long after boot, link is up. */
        int conn = -1;
        for (int i = 0; i < 3; i++) {
            conn = connect(fd, (struct sockaddr *)&srv, sizeof(srv));
            if (conn == 0) {
                break;
            }
            svcSleepThread(1000000000L);
        }
        if (conn != 0) {
            LogFormat("relay xport: connect failed %d", errno);
            nifmRequestUnregisterSocketDescriptor(&m_req, fd);
            close(fd);
            this->Close();
            return MAKERESULT(0xFD, 101);
        }

        /* Non-blocking: the LANDiscovery worker polls this fd and only recvs
           when readable, but stay non-blocking to be safe. */
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        m_fd = fd;

        /* Publish the transport so the bsd:u mitm's IPC threads can relay the
           game's session sends through it (guarded by g_bridge_mutex). */
        {
            std::scoped_lock lk(g_bridge_mutex);
            g_bridge_transport = this;
        }

        this->SendKeepalive();
        LogFormat("relay xport: open, vsrc=%08x rsrc=%08x fd=%d", m_vsrc, m_rsrc, m_fd);
        R_SUCCEED();
    }

    void RelayTransport::Close() {
        /* Unregister the bridge FIRST: after this no bsd thread can enter
           SendGameBroadcast on this object, so the closes below are safe. */
        {
            std::scoped_lock lk(g_bridge_mutex);
            if (g_bridge_transport == this) {
                g_bridge_transport = nullptr;
            }
        }
        if (m_fd >= 0) {
            if (m_have_req) {
                nifmRequestUnregisterSocketDescriptor(&m_req, m_fd);
            }
            close(m_fd);
            m_fd = -1;
        }
        if (m_have_req) {
            nifmRequestCancel(&m_req);
            nifmRequestClose(&m_req);
            m_have_req = false;
        }
        if (m_have_nifm_session) {
            NifmSessionManager::Release();
            m_have_nifm_session = false;
        }
    }

    int RelayTransport::SendKeepalive() {
        if (m_fd < 0) {
            return -1;
        }
        const u8 ka = TypeKeepalive;
        return send(m_fd, &ka, sizeof(ka), 0);
    }

    int RelayTransport::SendBroadcast(const void *lan_packet, size_t size) {
        if (m_fd < 0 || size > MaxWrapPayload) {
            return -1;
        }
        /* [0x01][IPv4(20) + UDP(8) + LANPacket] from vsrc -> 10.13.255.255. */
        u8 buf[1500];
        const u16 udplen = static_cast<u16>(8 + size);
        const u16 total  = static_cast<u16>(20 + udplen);
        buf[0] = TypeIpv4;
        u8 *ip = buf + 1;
        ip[0] = 0x45; ip[1] = 0x00; ip[2] = total >> 8; ip[3] = total & 0xff;
        ip[4] = 0x42; ip[5] = 0x43; ip[6] = 0x40; ip[7] = 0x00;
        ip[8] = 64; ip[9] = 17; ip[10] = 0; ip[11] = 0;
        ip[12] = (m_vsrc >> 24) & 0xff; ip[13] = (m_vsrc >> 16) & 0xff;
        ip[14] = (m_vsrc >> 8) & 0xff;  ip[15] = m_vsrc & 0xff;
        ip[16] = 10; ip[17] = 13; ip[18] = 255; ip[19] = 255;
        const u16 cs = IpChecksum(ip, 20);
        ip[10] = cs >> 8; ip[11] = cs & 0xff;
        u8 *udp = ip + 20;
        udp[0] = 11452 >> 8; udp[1] = 11452 & 0xff;
        udp[2] = 11452 >> 8; udp[3] = 11452 & 0xff;
        udp[4] = udplen >> 8; udp[5] = udplen & 0xff;
        udp[6] = 0; udp[7] = 0;
        std::memcpy(udp + 8, lan_packet, size);
        return send(m_fd, buf, 1 + total, 0);
    }

    int RelayTransport::SendGameBroadcast(const void *payload, size_t len, u16 dport) {
        /* dst 255.255.255.255: unambiguous broadcast for the relay's routing,
           regardless of either console's netmask. */
        return this->SendGameUnicast(payload, len, dport, 0xFFFFFFFFu);
    }

    int RelayTransport::SendGameUnicast(const void *payload, size_t len, u16 dport, u32 dst_ip) {
        if (m_fd < 0 || m_rsrc == 0 || len == 0 || len > MaxWrapPayload) {
            return -1;
        }
        /* [0x01][IPv4(20) + UDP(8) + game payload] from our REAL IP to dst_ip.
           sport = dport: the true source port is not visible in the SendTo
           hook; symmetric game protocols send port N -> port N. The relay
           routes by dst - broadcast to all clients, unicast to the owner. */
        u8 buf[1500];
        const u16 udplen = static_cast<u16>(8 + len);
        const u16 total  = static_cast<u16>(20 + udplen);
        buf[0] = TypeIpv4;
        u8 *ip = buf + 1;
        ip[0] = 0x45; ip[1] = 0x00; ip[2] = total >> 8; ip[3] = total & 0xff;
        ip[4] = 0x47; ip[5] = 0x4D; ip[6] = 0x40; ip[7] = 0x00; /* id "GM", DF */
        ip[8] = 64; ip[9] = 17; ip[10] = 0; ip[11] = 0;
        ip[12] = (m_rsrc >> 24) & 0xff; ip[13] = (m_rsrc >> 16) & 0xff;
        ip[14] = (m_rsrc >> 8) & 0xff;  ip[15] = m_rsrc & 0xff;
        ip[16] = (dst_ip >> 24) & 0xff; ip[17] = (dst_ip >> 16) & 0xff;
        ip[18] = (dst_ip >> 8) & 0xff;  ip[19] = dst_ip & 0xff;
        const u16 cs = IpChecksum(ip, 20);
        ip[10] = cs >> 8; ip[11] = cs & 0xff;
        u8 *udp = ip + 20;
        udp[0] = dport >> 8; udp[1] = dport & 0xff;
        udp[2] = dport >> 8; udp[3] = dport & 0xff;
        udp[4] = udplen >> 8; udp[5] = udplen & 0xff;
        udp[6] = 0; udp[7] = 0;
        std::memcpy(udp + 8, payload, len);
        return send(m_fd, buf, 1 + total, 0);
    }

    void RelayTransport::InjectGameFrame(const u8 *ip, size_t iplen) {
        if (m_rsrc == 0) {
            return;
        }
        const size_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || ihl + 8 > iplen) {
            return;
        }
        const u8 *udp = ip + ihl;
        const u16 sport = (udp[0] << 8) | udp[1];
        const u16 dport = (udp[2] << 8) | udp[3];
        const u8 *payload = udp + 8;
        const size_t plen = (ip + iplen) - payload;
        if (plen == 0 || plen > MaxWrapPayload) {
            return;
        }
        const u32 src = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];

        /* Our own frame echoed back (a relay can reflect it) - never feed the
           game its own traffic. */
        if (src == m_rsrc) {
            return;
        }
        /* Only inject during an active LDN session; never spray other relay
           users' traffic at local ports outside one. */
        SessionRegistry::Snapshot snap;
        SessionRegistry::Get(&snap);
        if (!snap.active) {
            return;
        }

        /* No socket send can deliver a peer's source IP locally on this stack
           (raw egresses without looping back; a dgram to our own IP loops back
           but carries OUR source). So hand the frame to the bsd:u mitm's
           RecvFrom queue, which serves it to the game with the peer's real
           source address, bypassing the stack. */
        GameRx::Push(src, sport, dport, payload, plen);
    }

    int RelayTransport::RecvBroadcast(void *out, size_t max_size, u32 *out_src_ip) {
        if (m_fd < 0) {
            return -1;
        }
        u8 buf[2048];
        const ssize_t n = recv(m_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            return (n == 0) ? 0 : -1;
        }
        if ((buf[0] & 0x7f) != TypeIpv4) {
            return 0;
        }
        const u8 *ip = buf + 1;
        const size_t iplen = static_cast<size_t>(n) - 1;
        if (iplen < 20) {
            return 0;
        }
        const size_t ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > iplen || ip[9] != 17) {
            return 0;
        }
        const u8 *udp = ip + ihl;
        if (ip + iplen < udp + 8) {
            return 0;
        }
        const u16 dport = (udp[2] << 8) | udp[3];
        if (dport != 11452) { /* LANDiscovery::DefaultPort */
            /* Not discovery traffic: a peer game session frame - hand it to
               the game via the RecvFrom queue. */
            this->InjectGameFrame(ip, iplen);
            return 0;
        }
        const u8 *payload = udp + 8;
        const size_t plen = static_cast<size_t>((ip + iplen) - payload);
        if (plen == 0 || plen > max_size) {
            return 0;
        }
        if (out_src_ip) {
            *out_src_ip = (ip[12] << 24) | (ip[13] << 16) | (ip[14] << 8) | ip[15];
        }
        std::memcpy(out, payload, plen);
        return static_cast<int>(plen);
    }

}
