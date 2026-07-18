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

#include "bsd_mitm_service.hpp"
#include "session_registry.hpp"
#include "ldnmitm_config.hpp"
#include "relay_client.hpp"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <atomic>
#include <cstring>

namespace ams::mitm::ldn {

    namespace {

        /* Poll/Select bounded-wait policy (docs/HANDOFF.md #4): waits <=
           ForwardMaxMs are forwarded verbatim; longer/infinite waits are
           re-issued in WaitCapMs slices so a game dying mid-wait frees our
           thread (an in-flight forward would pin the real bsd:u session). */
        constexpr s32 WaitCapMs    = 1000;
        constexpr s32 ForwardMaxMs = 60000;

        /* Reply layout shared by Select/Poll/SendTo. */
        struct BsdOutData {
            s32 ret;
            s32 bsd_errno;
        };

        /* Log the first few capped re-polls, then sample, to avoid flooding
           when a game thread sits in an idle poll(-1). */
        bool ShouldLogCapped(u32 n) {
            return n <= 8 || (n % 256) == 0;
        }

        /* getsockname (bsd cmd 16) on the forward session: the local port a
           socket is bound to. Wire (libnx bsd.c): in { s32 sockfd }, out
           { s32 ret; s32 errno; u32 addrlen }, one AutoSelect-Out sockaddr.
           False on any failure. */
        bool GetForwardBoundPort(::Service *fwd, s32 sockfd, u16 *out_port) {
            struct sockaddr_in sa = {};
            const struct { s32 sockfd; } in = { sockfd };
            struct { s32 ret; s32 bsd_errno; u32 addrlen; } out = {};
            const Result rc = serviceDispatchInOut(fwd, 16, in, out,
                .buffer_attrs = { SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out },
                .buffers = { { std::addressof(sa), sizeof(sa) } },
            );
            if (R_FAILED(rc) || out.ret != 0 || out.addrlen < sizeof(sa)) {
                return false;
            }
            *out_port = ntohs(sa.sin_port);
            return true;
        }

    }

    Result BsdMitmService::Select(sf::Out<s32> ret, sf::Out<s32> bsd_errno, BsdSelectInData in_data, sf::InAutoSelectBuffer rd_in, sf::InAutoSelectBuffer wr_in, sf::InAutoSelectBuffer ex_in, sf::OutAutoSelectBuffer rd_out, sf::OutAutoSelectBuffer wr_out, sf::OutAutoSelectBuffer ex_out) {
        /* Bounded (and sane) timeout: forward the original request verbatim.
           tv_sec is checked on its own first so a large value cannot overflow
           the ms conversion. */
        if (in_data.is_null == 0 && in_data.tv_sec >= 0 && in_data.tv_sec <= ForwardMaxMs / 1000) {
            const s64 wait_ms = in_data.tv_sec * 1000 + in_data.tv_usec / 1000;
            if (wait_ms <= ForwardMaxMs) {
                R_RETURN(sm::mitm::ResultShouldForwardToSession());
            }
        }

        static std::atomic<u32> s_capped{0};
        const u32 n = s_capped.fetch_add(1, std::memory_order_relaxed) + 1;
        if (ShouldLogCapped(n)) {
            LogFormat("bsd Select capped #%u nfds %d is_null %d tv %lld.%06lld",
                n, in_data.nfds, static_cast<int>(in_data.is_null),
                static_cast<long long>(in_data.tv_sec), static_cast<long long>(in_data.tv_usec));
        }

        /* Re-issue in WaitCapMs slices; honor a FINITE timeout to its real
           deadline, return after one slice when infinite (is_null). Wire
           mirrors libnx bsdSelect (cmd 5): 32-byte in-data, 3 AutoSelect-In +
           3 AutoSelect-Out fd_sets, out {ret, errno}. */
        const bool finite = (in_data.is_null == 0);
        s64 remaining = finite ? (static_cast<s64>(in_data.tv_sec) * 1000 + in_data.tv_usec / 1000) : 0;
        ::Service *fwd = this->m_forward_service.get();
        for (;;) {
            s64 slice = WaitCapMs;
            if (finite && remaining < WaitCapMs) {
                slice = remaining;
            }
            BsdSelectInData in = in_data;
            in.is_null = 0;
            in.tv_sec  = static_cast<s64>(slice / 1000);
            in.tv_usec = static_cast<s64>((slice % 1000) * 1000);
            BsdOutData out = {};

            R_TRY((serviceDispatchInOut(fwd, 5, in, out,
                .buffer_attrs = {
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                },
                .buffers = {
                    { rd_in.GetPointer(),  rd_in.GetSize()  },
                    { wr_in.GetPointer(),  wr_in.GetSize()  },
                    { ex_in.GetPointer(),  ex_in.GetSize()  },
                    { rd_out.GetPointer(), rd_out.GetSize() },
                    { wr_out.GetPointer(), wr_out.GetSize() },
                    { ex_out.GetPointer(), ex_out.GetSize() },
                },
            )));

            if (out.ret != 0 || !finite) {
                ret.SetValue(out.ret);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }

            remaining -= slice;
            if (remaining <= 0) {
                ret.SetValue(0);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }
        }
    }

    Result BsdMitmService::Poll(sf::Out<s32> ret, sf::Out<s32> bsd_errno, u32 nfds, s32 timeout, sf::InAutoSelectBuffer fds_in, sf::OutAutoSelectBuffer fds_out) {
        /* Queued relay frame + game polling its session fd: re-poll with
           timeout 0 for real readiness on the other fds, then force POLLIN on
           the game fd so it proceeds to RecvFrom. Peer traffic arrives via the
           relay, never the socket, so the game would otherwise never recv. */
        if (relay::IsEnabled() && GameRx::HasData()) {
            const s32 gfd = GameRx::GameFd();
            const size_t need = static_cast<size_t>(nfds) * sizeof(struct pollfd);
            if (gfd >= 0 && fds_in.GetSize() >= need && fds_out.GetSize() >= need) {
                const auto *pin = reinterpret_cast<const struct pollfd *>(fds_in.GetPointer());
                bool present = false;
                for (u32 i = 0; i < nfds; i++) {
                    if (pin[i].fd == gfd) { present = true; break; }
                }
                if (present) {
                    const struct { u32 nfds; s32 timeout; } in = { nfds, 0 };
                    BsdOutData out = {};
                    ::Service *fwd = this->m_forward_service.get();
                    R_TRY((serviceDispatchInOut(fwd, 6, in, out,
                        .buffer_attrs = {
                            SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                            SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                        },
                        .buffers = {
                            { fds_in.GetPointer(),  fds_in.GetSize()  },
                            { fds_out.GetPointer(), fds_out.GetSize() },
                        },
                    )));
                    if (out.ret >= 0) {
                        auto *pout = reinterpret_cast<struct pollfd *>(fds_out.GetPointer());
                        for (u32 i = 0; i < nfds; i++) {
                            if (pout[i].fd == gfd) {
                                /* poll() counts fds with any revents set: only
                                   bump when this fd had none, else it is already
                                   counted. */
                                if (pout[i].revents == 0) {
                                    out.ret += 1;
                                }
                                pout[i].revents |= POLLIN;
                                break;
                            }
                        }
                    }
                    ret.SetValue(out.ret);
                    bsd_errno.SetValue(out.bsd_errno);
                    R_SUCCEED();
                }
            }
        }

        /* Bounded timeout: forward the original request verbatim. */
        if (timeout >= 0 && timeout <= ForwardMaxMs) {
            R_RETURN(sm::mitm::ResultShouldForwardToSession());
        }

        static std::atomic<u32> s_capped{0};
        const u32 n = s_capped.fetch_add(1, std::memory_order_relaxed) + 1;
        if (ShouldLogCapped(n)) {
            LogFormat("bsd Poll capped #%u nfds %u timeout %d", n, nfds, timeout);
        }

        /* Re-issue in WaitCapMs slices; a FINITE timeout > ForwardMaxMs runs to
           its real deadline (never report 0 events early), infinite (timeout <
           0) returns after one slice so the game re-polls. Wire mirrors libnx
           bsdPoll (cmd 6): in {u32 nfds, s32 timeout}, AutoSelect-In/Out pollfd
           buffers, out {ret, errno}. */
        const bool finite = (timeout >= 0);
        s64 remaining = timeout; /* ms; only used when finite */
        ::Service *fwd = this->m_forward_service.get();
        for (;;) {
            s32 slice = WaitCapMs;
            if (finite && remaining < WaitCapMs) {
                slice = static_cast<s32>(remaining);
            }
            const struct {
                u32 nfds;
                s32 timeout;
            } in = { nfds, slice };
            BsdOutData out = {};

            R_TRY((serviceDispatchInOut(fwd, 6, in, out,
                .buffer_attrs = {
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_Out,
                },
                .buffers = {
                    { fds_in.GetPointer(),  fds_in.GetSize()  },
                    { fds_out.GetPointer(), fds_out.GetSize() },
                },
            )));

            /* Events ready or an error: done. Infinite wait: return the (0)
               result so the game re-polls, preserving teardown-friendliness. */
            if (out.ret != 0 || !finite) {
                ret.SetValue(out.ret);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }

            remaining -= slice;
            if (remaining <= 0) {
                /* The caller's real timeout elapsed with no events. */
                ret.SetValue(0);
                bsd_errno.SetValue(out.bsd_errno);
                R_SUCCEED();
            }
        }
    }

    Result BsdMitmService::RecvFrom(sf::Out<s32> ret, sf::Out<s32> bsd_errno, sf::Out<u32> addrlen, s32 sockfd, u32 flags, sf::OutAutoSelectBuffer message, sf::OutAutoSelectBuffer src_addr) {
        /* Serve a queued relay peer frame with the peer's real source address
           (the stack can't deliver a spoofed source locally). Otherwise
           forward verbatim, leaving unrelated recv traffic untouched. */
        if (relay::IsEnabled() &&
            (flags & MSG_PEEK) == 0 &&               /* don't consume on a peek */
            src_addr.GetSize() >= sizeof(struct sockaddr_in) &&
            GameRx::HasData()) {                     /* peer frames are waiting */

            /* Latch the game fd from the receive side (a joiner never
               broadcasts first, so SendTo can't record it) - but only when
               this socket's bound port matches the queued frame's dst port, so
               a second game socket (voice, discovery) is never mis-latched. On
               any mismatch or getsockname failure, forward verbatim. */
            if (GameRx::GameFd() < 0) {
                u16 bound_port = 0;
                if (GetForwardBoundPort(this->m_forward_service.get(), sockfd, std::addressof(bound_port)) &&
                    bound_port != 0 && bound_port == GameRx::PeekDport()) {
                    GameRx::SetGameFd(sockfd);
                    LogFormat("bsd RecvFrom: bootstrapped game fd %d (bound port %u) from recv", sockfd, bound_port);
                } else {
                    LogFormat("bsd RecvFrom: fd %d bound port %u != queued dport %u, not latching",
                        sockfd, bound_port, GameRx::PeekDport());
                }
            }

            if (sockfd != GameRx::GameFd()) {
                R_RETURN(sm::mitm::ResultShouldForwardToSession());
            }

            /* Pop straight into the IPC buffer: Pop already clamps to max_len. */
            u32 src_ip = 0; u16 sport = 0; size_t out_len = 0;
            if (GameRx::Pop(&src_ip, &sport, message.GetPointer(), message.GetSize(), &out_len)) {
                struct sockaddr_in sa = {};
                sa.sin_family = AF_INET;
                sa.sin_port = htons(sport);
                sa.sin_addr.s_addr = htonl(src_ip);
                std::memcpy(src_addr.GetPointer(), std::addressof(sa), sizeof(sa));

                ret.SetValue(static_cast<s32>(out_len));
                bsd_errno.SetValue(0);
                addrlen.SetValue(static_cast<u32>(sizeof(sa)));

                R_SUCCEED();
            }
        }

        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

    Result BsdMitmService::SendTo(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, sf::InAutoSelectBuffer message, sf::InAutoSelectBuffer dst_addr) {
        AMS_UNUSED(ret, bsd_errno);

        /* Two consumers of the game's sends: LAN broadcast fan-out
           (broadcast->unicast for WiFi reliability) and the internet relay.
           Enter if either is active; the relay is not gated on the fan-out
           toggle. */
        const bool want_fanout = LdnConfig::getBroadcastRelay();
        const bool want_relay  = relay::IsEnabled();
        if ((want_fanout || want_relay) && dst_addr.GetSize() >= sizeof(struct sockaddr_in)) {
            const auto *sa = reinterpret_cast<const struct sockaddr_in *>(dst_addr.GetPointer());
            if (sa->sin_family == AF_INET) {
                const u32 ip = ntohl(sa->sin_addr.s_addr);
                const u16 port = ntohs(sa->sin_port);

                SessionRegistry::Snapshot snap;
                SessionRegistry::Get(std::addressof(snap));

                const bool is_bcast = (ip == 0xFFFFFFFFu) || (snap.active && ip == snap.bcast_ip);

                /* Internet relay, unicast: games that switch from a broadcast
                   handshake to unicast target a peer IP unroutable across the
                   internet, so relay it (routed to the client owning that dst). */
                if (want_relay && snap.active && !is_bcast && ip != 0 && ip != 0x7F000001u) {
                    for (int i = 0; i < snap.peer_count; i++) {
                        if (ip == snap.peer_ips[i]) {
                            GameRx::SetGameFd(sockfd);
                            relay::BridgeSendGameUnicast(message.GetPointer(), message.GetSize(), port, ip);
                            break;
                        }
                    }
                }

                if (snap.active && snap.peer_count > 0 && is_bcast) {
                    /* LAN broadcast fan-out: unicast a copy to each peer (WiFi
                       unicast is ACKed/full-rate, the AP's broadcast re-flood
                       is lossy). The original broadcast is still forwarded
                       below, so unknown peers stay covered and duplicates are
                       harmless. */
                    if (want_fanout) {
                        ::Service *fwd = this->m_forward_service.get();
                        for (int i = 0; i < snap.peer_count; i++) {
                            struct sockaddr_in peer = *sa;
                            peer.sin_addr.s_addr = htonl(snap.peer_ips[i]);

                            const struct { s32 sockfd; s32 flags; } in = { sockfd, flags };
                            BsdOutData out = {};

                            /* libnx bsdSendTo (cmd 11), on the game's forward
                               session. Best-effort. */
                            serviceDispatchInOut(fwd, 11, in, out,
                                .buffer_attrs = {
                                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                    SfBufferAttr_HipcAutoSelect | SfBufferAttr_In,
                                },
                                .buffers = {
                                    { message.GetPointer(), message.GetSize() },
                                    { std::addressof(peer), sizeof(peer) },
                                },
                            );
                        }
                    }

                    /* Internet relay, broadcast: carry it to remote peers and
                       record the game's session fd for the RecvFrom/Poll
                       intercept. */
                    if (want_relay) {
                        GameRx::SetGameFd(sockfd);
                        relay::BridgeSendGameBroadcast(message.GetPointer(), message.GetSize(), port);
                    }
                }
            }
        }

        /* Always forward the original request untouched. */
        R_RETURN(sm::mitm::ResultShouldForwardToSession());
    }

}
