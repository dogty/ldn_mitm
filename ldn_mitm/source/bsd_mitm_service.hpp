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
#include "debug.hpp"
#include "interfaces/ibsd_mitm.hpp"

namespace ams::mitm::ldn {

    /* mitm of bsd:u. See docs/bsd-mitm-plan.md. Phase 1: passive observer -
       SendTo only logs broadcast-destined datagrams and forwards everything
       unchanged. Fan-out (broadcast -> per-peer unicast) is Phase 2. */
    class BsdMitmService : public sf::MitmServiceImplBase {
        public:
            BsdMitmService(std::shared_ptr<::Service> &&s, const sm::MitmProcessInfo &c)
                : sf::MitmServiceImplBase(std::forward<std::shared_ptr<::Service>>(s), c)
            {
                LogFormat("BsdMitmService created pid: %" PRIu64 " tid: %" PRIx64,
                    c.process_id, c.program_id);
            }

            /* Logged so a capture across an app switch shows whether the
               forward session actually closes when the game exits (thread /
               session leak diagnosis). */
            ~BsdMitmService() {
                LogFormat("~BsdMitmService pid: %" PRIu64, this->m_client_info.process_id);
            }

            /* Only mitm real games. bsd is the busiest service on the system;
               never touch sysmodules (and never ldn_mitm's own sockets), so a
               bug here can only affect application networking, not the OS. */
            static bool ShouldMitm(const sm::MitmProcessInfo &client_info) {
                const bool is_app = ncm::IsApplicationId(client_info.program_id);
                LogFormat("bsd should_mitm pid: %" PRIu64 " tid: %" PRIx64 " -> %d",
                    client_info.process_id, client_info.program_id, static_cast<int>(is_app));
                return is_app;
            }
        public:
            /* Overridden commands. */
            /* Bounded-wait fix (see ibsd_mitm.hpp): unbounded waits are
               re-issued with a capped timeout so a dead client can never
               leave a request parked on the real bsd:u forever. */
            Result Select(sf::Out<s32> ret, sf::Out<s32> bsd_errno, BsdSelectInData in_data, sf::InAutoSelectBuffer rd_in, sf::InAutoSelectBuffer wr_in, sf::InAutoSelectBuffer ex_in, sf::OutAutoSelectBuffer rd_out, sf::OutAutoSelectBuffer wr_out, sf::OutAutoSelectBuffer ex_out);
            Result Poll(sf::Out<s32> ret, sf::Out<s32> bsd_errno, u32 nfds, s32 timeout, sf::InAutoSelectBuffer fds_in, sf::OutAutoSelectBuffer fds_out);
            Result SendTo(sf::Out<s32> ret, sf::Out<s32> bsd_errno, s32 sockfd, s32 flags, sf::InAutoSelectBuffer message, sf::InAutoSelectBuffer dst_addr);
    };
    static_assert(ams::mitm::ldn::IsIBsdMitmInterface<BsdMitmService>);

}
