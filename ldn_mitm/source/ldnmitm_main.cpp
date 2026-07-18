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

#include <stratosphere.hpp>

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <switch.h>

extern "C" {

#include <switch/services/bsd.h>

}

#include "ldnmitm_service.hpp"
#include "bsd_mitm_service.hpp"
#include "relay_client.hpp"

namespace ams {

    namespace {

        constexpr size_t MallocBufferSize = 1_MB;
        alignas(os::MemoryPageSize) constinit u8 g_malloc_buffer[MallocBufferSize];

        consteval size_t GetLibnxBsdTransferMemorySize(const ::SocketInitConfig *config) {
            const u32 tcp_tx_buf_max_size = config->tcp_tx_buf_max_size != 0 ? config->tcp_tx_buf_max_size : config->tcp_tx_buf_size;
            const u32 tcp_rx_buf_max_size = config->tcp_rx_buf_max_size != 0 ? config->tcp_rx_buf_max_size : config->tcp_rx_buf_size;
            const u32 sum = tcp_tx_buf_max_size + tcp_rx_buf_max_size + config->udp_tx_buf_size + config->udp_rx_buf_size;

            return config->sb_efficiency * util::AlignUp(sum, os::MemoryPageSize);
        }

        constexpr const ::SocketInitConfig LibnxSocketInitConfig = {
            .tcp_tx_buf_size = 0x800,
            .tcp_rx_buf_size = 0x1000,
            .tcp_tx_buf_max_size = 0x2000,
            .tcp_rx_buf_max_size = 0x2000,

            .udp_tx_buf_size = 0x2000,
            .udp_rx_buf_size = 0x2000,

            .sb_efficiency = 4,

            .num_bsd_sessions = 3,
            /* bsd:u. The relay socket reaches the internet by registering its
               fd with an nifm request (see relay_client.cpp), not by service
               type. (A bsd:s experiment for SOCK_RAW was tried and dropped:
               raw egress never loops back locally on this stack, so the
               receive path serves peer frames through the bsd:u RecvFrom
               intercept instead - no raw socket needed.) */
            .bsd_service_type = BsdServiceType_User,
        };

        alignas(os::MemoryPageSize) constinit u8 g_socket_tmem_buffer[GetLibnxBsdTransferMemorySize(std::addressof(LibnxSocketInitConfig))];

        constexpr const ::BsdInitConfig LibnxBsdInitConfig = {
            .version             = 1,

            .tmem_buffer         = g_socket_tmem_buffer,
            .tmem_buffer_size    = sizeof(g_socket_tmem_buffer),

            .tcp_tx_buf_size     = LibnxSocketInitConfig.tcp_tx_buf_size,
            .tcp_rx_buf_size     = LibnxSocketInitConfig.tcp_rx_buf_size,
            .tcp_tx_buf_max_size = LibnxSocketInitConfig.tcp_tx_buf_max_size,
            .tcp_rx_buf_max_size = LibnxSocketInitConfig.tcp_rx_buf_max_size,

            .udp_tx_buf_size     = LibnxSocketInitConfig.udp_tx_buf_size,
            .udp_rx_buf_size     = LibnxSocketInitConfig.udp_rx_buf_size,

            .sb_efficiency       = LibnxSocketInitConfig.sb_efficiency,
        };

    }

    namespace mitm {

        const s32 ThreadPriority = 6;
        /* bsd:u has blocking commands (Recv/RecvFrom/Poll/Select/Accept). We
           mitm bsd:u and forward those verbatim, which blocks the forwarding
           thread inside the real service until it returns. A netplay game
           keeps threads parked in blocking recv/poll, so with the old pool of
           2 these were all consumed and no thread was left to accept the next
           application's bsd:u session -> it hung at boot (blank screen, force
           shutdown needed). Give the pool enough headroom that parked forwards
           cannot starve session acceptance. */
        const size_t TotalThreads = 8;
        const size_t NumExtraThreads = TotalThreads - 1;
        const size_t ThreadStackSize = 0x4000;

        alignas(os::MemoryPageSize) u8 g_thread_stack[ThreadStackSize];
        os::ThreadType g_thread;

        alignas(0x40) constinit u8 g_heap_memory[128_KB];
        constinit lmem::HeapHandle g_heap_handle;
        constinit bool g_heap_initialized;
        constinit os::SdkMutex g_heap_init_mutex;

        lmem::HeapHandle GetHeapHandle()
        {
            if (AMS_UNLIKELY(!g_heap_initialized))
            {
                std::scoped_lock lk(g_heap_init_mutex);

                if (AMS_LIKELY(!g_heap_initialized))
                {
                    g_heap_handle = lmem::CreateExpHeap(g_heap_memory, sizeof(g_heap_memory), lmem::CreateOption_ThreadSafe);
                    g_heap_initialized = true;
                }
            }

            return g_heap_handle;
        }

        void *Allocate(size_t size)
        {
            return lmem::AllocateFromExpHeap(GetHeapHandle(), size);
        }

        void Deallocate(void *p, size_t size)
        {
            AMS_UNUSED(size);
            return lmem::FreeToExpHeap(GetHeapHandle(), p);
        }

        namespace {

            struct LdnMitmManagerOptions {
                static constexpr size_t PointerBufferSize = 0x1000;
                static constexpr size_t MaxDomains = 0x10;
                static constexpr size_t MaxDomainObjects = 0x100;
                static constexpr bool   CanDeferInvokeRequest = false;
                static constexpr bool   CanManageMitmServers  = true;
            };

            /* Two mitm ports now: ldn:u (sleepy) and bsd:u (busy - every
               game's sockets). bsd:u needs many more concurrent sessions than
               ldn ever did; undersizing would make us REFUSE bsd sessions and
               break game networking outright. */
            enum PortIndex {
                PortIndex_Ldn = 0,
                PortIndex_Bsd = 1,
                PortIndex_Count,
            };
            constexpr size_t MaxSessions = 0x20;

            class ServerManager final : public sf::hipc::ServerManager<PortIndex_Count, LdnMitmManagerOptions, MaxSessions> {
                        private:
                            virtual ams::Result OnNeedsToAccept(int port_index, Server *server) override;
            };

            ServerManager g_server_manager;

            Result ServerManager::OnNeedsToAccept(int port_index, Server *server) {
                /* Acknowledge the mitm session. */
                std::shared_ptr<::Service> fsrv;
                sm::MitmProcessInfo client_info;
                server->AcknowledgeMitmSession(std::addressof(fsrv), std::addressof(client_info));

                switch (port_index) {
                    case PortIndex_Ldn:
                        return this->AcceptMitmImpl(server, sf::CreateSharedObjectEmplaced<mitm::ldn::ILdnMitMService, mitm::ldn::LdnMitMService>(decltype(fsrv)(fsrv), client_info), fsrv);
                    case PortIndex_Bsd:
                        return this->AcceptMitmImpl(server, sf::CreateSharedObjectEmplaced<mitm::ldn::IBsdMitmInterface, mitm::ldn::BsdMitmService>(decltype(fsrv)(fsrv), client_info), fsrv);
                    AMS_UNREACHABLE_DEFAULT_CASE();
                }
            }

            alignas(os::MemoryPageSize) u8 g_extra_thread_stacks[NumExtraThreads][ThreadStackSize];
            os::ThreadType g_extra_threads[NumExtraThreads];

            void LoopServerThread(void *)
            {
                g_server_manager.LoopProcess();
            }

            void ProcessForServerOnAllThreads(void *)
            {
                /* Initialize threads. */
                if constexpr (NumExtraThreads > 0)
                {
                    const s32 priority = os::GetThreadCurrentPriority(os::GetCurrentThread());
                    for (size_t i = 0; i < NumExtraThreads; i++)
                    {
                        R_ABORT_UNLESS(os::CreateThread(g_extra_threads + i, LoopServerThread, nullptr, g_extra_thread_stacks[i], ThreadStackSize, priority));
                        os::SetThreadNamePointer(g_extra_threads + i, "ldn_mitm::Thread");
                    }
                }

                /* Start extra threads. */
                if constexpr (NumExtraThreads > 0)
                {
                    for (size_t i = 0; i < NumExtraThreads; i++)
                    {
                        os::StartThread(g_extra_threads + i);
                    }
                }

                /* Loop this thread. */
                LoopServerThread(nullptr);

                /* Wait for extra threads to finish. */
                if constexpr (NumExtraThreads > 0)
                {
                    for (size_t i = 0; i < NumExtraThreads; i++)
                    {
                        os::WaitThread(g_extra_threads + i);
                    }
                }
            }
        }

    }

    namespace init {

        void InitializeSystemModule() {
            /* Initialize our connection to sm. */
            R_ABORT_UNLESS(sm::Initialize());

            /* Initialize fs. */
            fs::InitializeForSystem();
            fs::SetAllocator(mitm::Allocate, mitm::Deallocate);
            fs::SetEnabledAutoAbort(false);

            /* Mount the SD card. */
            R_ABORT_UNLESS(fs::MountSdCard("sdmc"));

            /* Initialize other services. */

            /* nifm is acquired lazily via NifmSessionManager: nifm:a only
               allows two sessions system-wide, and holding one forever
               starves the console's own network settings/connection test. */
            R_ABORT_UNLESS(bsdInitialize(&LibnxBsdInitConfig, LibnxSocketInitConfig.num_bsd_sessions, LibnxSocketInitConfig.bsd_service_type));
            R_ABORT_UNLESS(socketInitialize(&LibnxSocketInitConfig));
        }

        void FinalizeSystemModule() { /* ... */ }

        void Startup() {
            /* Initialize the global malloc allocator. */
            init::InitializeAllocator(g_malloc_buffer, sizeof(g_malloc_buffer));
        }

    }

    void NORETURN Exit(int rc) {
        AMS_UNUSED(rc);
        AMS_ABORT("Exit called by immortal process");
    }

    void Main() {
        R_ABORT_UNLESS(log::Initialize());
        LogFormat("main");

        constexpr sm::ServiceName LdnMitmServiceName = sm::ServiceName::Encode("ldn:u");
        R_ABORT_UNLESS((mitm::g_server_manager.RegisterMitmServer<mitm::ldn::LdnMitMService>(mitm::PortIndex_Ldn, LdnMitmServiceName)));

        constexpr sm::ServiceName BsdMitmServiceName = sm::ServiceName::Encode("bsd:u");
        R_ABORT_UNLESS((mitm::g_server_manager.RegisterMitmServer<mitm::ldn::BsdMitmService>(mitm::PortIndex_Bsd, BsdMitmServiceName)));
        LogFormat("registered");

        /* Load the internet-relay config (docs/internet-relay-plan.md). Relay
           mode is off unless sdmc:/ldn_mitm_relay.cfg names a relay server. */
        mitm::ldn::relay::LoadConfig();

        /* NOTE: an earlier attempt handled sleep proactively via a psc
           PmModule (ending the session at sleep entry like real ldn).
           Abandoned: every variant eventually left a psc request
           unacknowledged around the suspend gap, spsm then failed its
           sequence and omm ASSERTED (2165-0001) - an unwakeable console.
           Sleep is instead detected reactively at wake via POLLHUP on the
           dead sockets (see LDUdpSocket::onClose), which is proven safe. */

        R_ABORT_UNLESS(os::CreateThread(
            &mitm::g_thread,
            mitm::ProcessForServerOnAllThreads,
            nullptr,
            mitm::g_thread_stack,
            mitm::ThreadStackSize,
            mitm::ThreadPriority));

        os::SetThreadNamePointer(&mitm::g_thread, "ldn_mitm::MainThread");
        os::StartThread(&mitm::g_thread);

        os::WaitThread(&mitm::g_thread);
    }

}

void *operator new(size_t size)
{
    return ams::mitm::Allocate(size);
}

void *operator new(size_t size, const std::nothrow_t &)
{
    return ams::mitm::Allocate(size);
}

void operator delete(void *p)
{
    return ams::mitm::Deallocate(p, 0);
}

void operator delete(void *p, size_t size)
{
    return ams::mitm::Deallocate(p, size);
}

void *operator new[](size_t size)
{
    return ams::mitm::Allocate(size);
}

void *operator new[](size_t size, const std::nothrow_t &)
{
    return ams::mitm::Allocate(size);
}

void operator delete[](void *p)
{
    return ams::mitm::Deallocate(p, 0);
}

void operator delete[](void *p, size_t size)
{
    return ams::mitm::Deallocate(p, size);
}
