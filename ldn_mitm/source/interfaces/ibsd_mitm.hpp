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
#include <stratosphere.hpp>

namespace ams::mitm::ldn {

    /* Wire image of libnx bsdSelect's in-data: { s32 nfds; timeval{s64 tv_sec;
       s64 tv_usec}; u8 is_null } = 32 bytes, nfds at +0, tv at +8, is_null at
       +24 (verified against libnx). One struct so the sf packer can't
       reorder/re-pad it. */
    struct BsdSelectInData {
        s32 nfds;
        u32 _pad;
        s64 tv_sec;
        s64 tv_usec;
        u8  is_null;
        u8  _pad2[7];
    };
    static_assert(sizeof(BsdSelectInData) == 32);
    static_assert(__builtin_offsetof(BsdSelectInData, tv_sec) == 8);
    static_assert(__builtin_offsetof(BsdSelectInData, is_null) == 24);

}

/* bsd:u mitm. Overridden commands:
   - SendTo (11): broadcast fan-out / relay.
   - Poll (6) / Select (5): unbounded waits are re-issued with a capped
     timeout - a verbatim forward would pin the real bsd:u session if the game
     dies mid-wait, hanging the next launch (see docs/HANDOFF.md #4). Bounded
     waits are forwarded verbatim.
   - RecvFrom (9): serve relay peer frames.
   Every other command is forwarded verbatim by the mitm framework.

   Wire layouts (libnx nx/source/services/bsd.c; note nfds is u32, NOT u64):
     Select (5): in { s32 nfds; BsdSelectInData-style timeout; } (32 bytes)
                 buffers: AutoSelect-In rd/wr/ex, AutoSelect-Out rd/wr/ex
     Poll   (6): in { u32 nfds; s32 timeout; }
                 buffers: AutoSelect-In pollfds, AutoSelect-Out pollfds
     RecvFrom (9): in { s32 sockfd; u32 flags; }
                 buffers: AutoSelect-Out message, AutoSelect-Out sockaddr
                 out { s32 ret; s32 bsd_errno; u32 addrlen } (ret at raw+16,
                 addrlen at raw+24 in the bsdRecvFrom disasm; the sockaddr
                 buffer receives the source address, addrlen its length).
     SendTo (11): in { s32 sockfd; s32 flags; }
                 buffers: AutoSelect-In payload, AutoSelect-In sockaddr
     out (5/6/11): { s32 ret; s32 bsd_errno; }

   The signatures must match the wire format exactly, or marshalling of the
   intercepted call would corrupt it - for every game on the console. */
#define AMS_BSD_MITM_INTERFACE(C, H)                                                                                                                                                              \
    AMS_SF_METHOD_INFO(C, H, 5,  Result, Select, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, ams::mitm::ldn::BsdSelectInData in_data, ams::sf::InAutoSelectBuffer rd_in, ams::sf::InAutoSelectBuffer wr_in, ams::sf::InAutoSelectBuffer ex_in, ams::sf::OutAutoSelectBuffer rd_out, ams::sf::OutAutoSelectBuffer wr_out, ams::sf::OutAutoSelectBuffer ex_out), (ret, bsd_errno, in_data, rd_in, wr_in, ex_in, rd_out, wr_out, ex_out)) \
    AMS_SF_METHOD_INFO(C, H, 6,  Result, Poll,   (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, u32 nfds, s32 timeout, ams::sf::InAutoSelectBuffer fds_in, ams::sf::OutAutoSelectBuffer fds_out), (ret, bsd_errno, nfds, timeout, fds_in, fds_out)) \
    AMS_SF_METHOD_INFO(C, H, 9,  Result, RecvFrom, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, ams::sf::Out<u32> addrlen, s32 sockfd, u32 flags, ams::sf::OutAutoSelectBuffer message, ams::sf::OutAutoSelectBuffer src_addr), (ret, bsd_errno, addrlen, sockfd, flags, message, src_addr)) \
    AMS_SF_METHOD_INFO(C, H, 11, Result, SendTo, (ams::sf::Out<s32> ret, ams::sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, ams::sf::InAutoSelectBuffer message, ams::sf::InAutoSelectBuffer dst_addr), (ret, bsd_errno, sockfd, flags, message, dst_addr))

AMS_SF_DEFINE_MITM_INTERFACE(ams::mitm::ldn, IBsdMitmInterface, AMS_BSD_MITM_INTERFACE, 0x7B5D0C41)
