#include "lan_discovery.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include "ipinfo.hpp"
#include "nifm_manager.hpp"
#include "session_registry.hpp"

namespace ams::mitm::ldn {

    static const int ModuleID = 0xFD;
    static const int LdnModuleId = 0xCB;
    /* nn::ldn ConnectFailed (2203-0064): the result real ldn reports for a
       failed join. Games recognize it and show their normal error dialog;
       an unknown module (0xFD) here can make them abort instead. */
    static const Result ResultConnectFailed = MAKERESULT(0xCB, 64);

    const char *LANDiscovery::FakeSsid = "12345678123456781234567812345678";
    const LANDiscovery::LanEventFunc LANDiscovery::EmptyFunc = [](){};


    int LanStation::onRead() {
        if (!this->socket) {
            LogFormat("Nullptr %d\n", this->nodeId);
            return -1;
        }
        return this->socket->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
			AMS_UNUSED(reply);
            if (type == LANPacketType::Connect) {
                LogFormat("on connect");
                NodeInfo *info = (decltype(info))data;
                if (size != sizeof(*info)) {
                    LogFormat("NodeInfo size is wrong");
                    return -1;
                }
                std::scoped_lock lock(this->discovery->dataMutex);
                *this->nodeInfo = *info;
                this->status = NodeStatus::Connected;

                this->discovery->updateNodes();
            } else {
                LogFormat("unexpecting type %d", static_cast<int>(type));
            }
            return 0;
        });
    }

    void LanStation::onClose() {
        LogFormat("LanStation::onClose %d", this->nodeId);
        this->reset();
        this->discovery->updateNodes();
    }

    LDUdpSocket::LDUdpSocket(int fd, LANDiscovery *discovery)
        :   UdpLanSocketBase(fd, discovery->getListenPort()),
            discovery(discovery) {
        /* ... */
    }

    int LDUdpSocket::onRead() {
        LogFormat("LDUdpSocket::onRead");
        return this->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
            switch (type) {
                case LANPacketType::Scan: {
                    if (this->discovery->getState() == CommState::AccessPointCreated) {
                        std::scoped_lock lock(this->discovery->dataMutex);
                        reply(LANPacketType::ScanResp, &this->discovery->networkInfo, sizeof(NetworkInfo));
                    }
                    break;
                }
                case LANPacketType::ScanResp: {
                    LogFormat("ScanResp");
                    NetworkInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        break;
                    }
                    std::scoped_lock lock(this->discovery->dataMutex);
                    /* A relay (lan-play) can echo our own advertisement back
                       at us. Real ldn never shows you your own network, and a
                       game that picks it from the scan results would try to
                       join itself (Street Fighter 30th AC does exactly this),
                       so it must never reach the game. */
                    if (this->selfIp != 0 && info->ldn.nodes[0].ipv4Address == this->selfIp) {
                        LogFormat("ScanResp: ignoring our own network (echoed back by relay)");
                        break;
                    }
                    this->scanResults.insert({info->common.bssid, *info});
                    break;
                }
                default: {
                    LogFormat("LDUdpSocket::onRead unhandle type %d", static_cast<int>(type));
                    break;
                }
            }
            return 0;
        });
    }

    void LDUdpSocket::onClose() {
        /* Take the dead socket out of the poll set (same rationale as
           LDTcpSocket::onClose): after a sleep/wake or wifi loss every socket
           reports POLLHUP forever, and leaving the fd in the set spins the
           worker in Poll->onClose at full speed until the game finalizes.
           The discovery udp socket only dies with its interface (airplane
           mode, wifi loss), so mark the session for a rebuild: once the
           network is back and the game re-enters its host/join menu,
           refreshNetworkSession() re-creates everything - no game relaunch.
           Reason: interface death is a SYSTEM-initiated end from the game's
           point of view - pia classifies airplane mode (2618-0313) right
           next to sleep (2618-0314), and reporting SignalLost here instead
           sent AC into its generic-failure cascade (2123-0011...). Keep
           SignalLost for actual peer loss (TCP close / relay timeout). */
        this->close();
        discovery->needsReinit = true;
        /* Keep the FIRST recorded cause: if the session already ended (sleep
           teardown, or the other socket's close), don't rewrite the reason. */
        if (discovery->getState() != CommState::Error) {
            discovery->disconnect_reason =
                (discovery->getState() == CommState::AccessPointCreated)
                    ? DisconnectReason::DestroyedBySystem
                    : DisconnectReason::DisconnectedBySystem;
            discovery->setState(CommState::Error);
        }
    };

    /* --- RelayLanSocket (Phase 1b step 2): LDN discovery over the relay --- */

    void RelayLanSocket::onClose() {
        /* The relay transport only HUPs when its interface dies (airplane
           mode, wifi loss, or waking from sleep).
           Close it and mark the session for rebuild so relay play recovers
           on the next host/join without relaunching the game. */
        this->transport.Close();
        this->discovery->needsReinit = true;
    }

    ssize_t RelayLanSocket::recvfrom(void *buf, size_t len, struct sockaddr_in *addr) {
        u32 src = 0;
        const int n = this->transport.RecvBroadcast(buf, len, &src);
        if (n <= 0) {
            return n;
        }
        if (addr) {
            addr->sin_family = AF_INET;
            addr->sin_port = htons(11452);
            addr->sin_addr.s_addr = htonl(src);
        }
        return n;
    }

    int RelayLanSocket::sendto(const void *buf, size_t len, struct sockaddr_in *addr) {
        AMS_UNUSED(addr);
        return this->transport.SendBroadcast(buf, len);
    }

    int RelayLanSocket::onRead() {
        /* Dispatch one relay frame like LDUdpSocket, but share the udp
           socket's scanResults so the game reads remote networks from the
           same list. Always return 0 - never let a transient recv close the
           relay (its onClose is a no-op anyway). */
        this->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
            AMS_UNUSED(reply);
            switch (type) {
                case LANPacketType::Scan: {
                    if (this->discovery->getState() == CommState::AccessPointCreated) {
                        std::scoped_lock lock(this->discovery->dataMutex);
                        /* The 5s worker beacon already advertises us to every
                           relay client; only reply if the scanner just missed
                           one, so scanners don't double our advertisement
                           traffic with their periodic Scans. */
                        const os::Tick now = os::GetSystemTick();
                        if (os::ConvertToTimeSpan(now - this->discovery->lastRelayAdvertise).GetMilliSeconds() >= LANDiscovery::RelayAdvertiseMinIntervalMs) {
                            this->discovery->lastRelayAdvertise = now;
                            this->sendPacket(LANPacketType::ScanResp, &this->discovery->networkInfo, sizeof(NetworkInfo));
                            LogFormat("relay: Scan -> replied ScanResp");
                        }
                    }
                    break;
                }
                case LANPacketType::ScanResp: {
                    NetworkInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        break;
                    }
                    std::scoped_lock lock(this->discovery->dataMutex);
                    /* The host beacons its advertisement every 5s; while we
                       are joining/joined to that network it doubles as the
                       host-liveness signal for peer-loss detection. */
                    if (this->discovery->joinActive &&
                        info->common.bssid == this->discovery->joinBssid) {
                        this->discovery->hostLastSeen = os::GetSystemTick();
                    }
                    if (this->discovery->udp) {
                        if (this->discovery->udp->selfIp != 0 &&
                            info->ldn.nodes[0].ipv4Address == this->discovery->udp->selfIp) {
                            break;
                        }
                        this->discovery->udp->scanResults.insert({info->common.bssid, *info});
                        LogFormat("relay: got ScanResp, %zu result(s)", this->discovery->udp->scanResults.size());
                    }
                    break;
                }
                case LANPacketType::Connect: {
                    /* Host side: a station is joining over the relay. */
                    NodeInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        break;
                    }
                    if (this->discovery->getState() == CommState::AccessPointCreated) {
                        LogFormat("relay: got Connect from %08x", info->ipv4Address);
                        this->discovery->onRelayConnect(info);
                    }
                    break;
                }
                case LANPacketType::SyncNetwork: {
                    /* Station side: the host published network state over the
                       relay. Apply only while we are (or are becoming) a
                       station; a host in AccessPointCreated ignores it. */
                    NetworkInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        break;
                    }
                    if (this->discovery->getState() == CommState::Station ||
                        this->discovery->getState() == CommState::StationConnected) {
                        LogFormat("relay: got SyncNetwork");
                        this->discovery->onSyncNetwork(info);
                    }
                    break;
                }
                case LANPacketType::RelayHeartbeat: {
                    /* Host side: a connected relay station signalling it is
                       still alive (it has no TCP socket whose close would
                       report the opposite). Scoped to our session's bssid so
                       a shared relay's foreign heartbeats - or an IP collision
                       across NATs - can never refresh our stations. */
                    const RelayHeartbeatPayload *hb = (decltype(hb))data;
                    if (size != sizeof(*hb)) {
                        break;
                    }
                    if (this->discovery->getState() == CommState::AccessPointCreated) {
                        std::scoped_lock lock(this->discovery->dataMutex);
                        if (hb->bssid == this->discovery->networkInfo.common.bssid) {
                            for (auto &st : this->discovery->stations) {
                                if (st.getStatus() == NodeStatus::Connected &&
                                    st.getFd() < 0 &&
                                    st.nodeInfo->ipv4Address == hb->ipv4) {
                                    st.lastSeen = os::GetSystemTick();
                                }
                            }
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            return 0;
        });
        return 0;
    }

    int LDTcpSocket::onRead() {
        LogFormat("LDTcpSocket::onRead");
        const auto state = this->discovery->getState();
        if (state == CommState::Station || state == CommState::StationConnected) {
            return this->recvPacket([&](LANPacketType type, const void *data, size_t size, ReplyFunc reply) -> int {
				AMS_UNUSED(reply);
                if (type == LANPacketType::SyncNetwork) {
                    LogFormat("SyncNetwork");
                    NetworkInfo *info = (decltype(info))data;
                    if (size != sizeof(*info)) {
                        return -1;
                    }

                    this->discovery->onSyncNetwork(info);
                } else {
                    LogFormat("LDTcpSocket::onRead unhandle type %d", static_cast<int>(type));
                    return -1;
                }

                return 0;
            });
        } else if (state == CommState::AccessPointCreated) {
            struct sockaddr_in addr;
            socklen_t addrlen = sizeof(addr);
            int new_fd = accept(this->getFd(), (struct sockaddr *)&addr, &addrlen);
            if (new_fd < 0)
            {
                LogFormat("accept failed");
                return -1;
            }
            this->discovery->onConnect(new_fd);
            return 0;
        } else {
            LogFormat("LDTcpSocket::onRead wrong state %d", static_cast<int>(state));
            return -1;
        }
    }

    void LDTcpSocket::onClose() {
        LogFormat("LDTcpSocket::onClose");
        /* Take the dead socket out of the poll set. Without this the fd
           stays readable at EOF and the worker re-enters onRead/onClose in
           a tight loop until the game finalizes. */
        this->close();
        this->discovery->onDisconnectFromHost();
    }

    u32 LDUdpSocket::getBroadcast() {
        u32 address, netmask, gateway, primary_dns, secondary_dns;
        Result rc = nifmGetCurrentIpConfigInfo(&address, &netmask, &gateway, &primary_dns, &secondary_dns);
        address = ntohl(address);
        netmask = ntohl(netmask);
        if (R_FAILED(rc)) {
            LogFormat("Broadcast failed to get ip");
            return 0xFFFFFFFF;
        }
        u32 ret = address | ~netmask;
        return ret;
    }

    void LANDiscovery::onSyncNetwork(NetworkInfo *info) {
        std::scoped_lock lock(this->dataMutex);
        /* Accept network sync only for the network we are joining/joined. A
           merely-scanning station (openStation, no connect yet) has
           joinActive == false and is never flipped connected, and on a shared
           relay another session's SyncNetwork (a different bssid) can never
           overwrite our state. */
        if (!this->joinActive || !(info->common.bssid == this->joinBssid)) {
            LogFormat("onSyncNetwork: not for our target network, ignoring");
            return;
        }
        /* Host-originated traffic for our network counts as host liveness. */
        this->hostLastSeen = os::GetSystemTick();
        this->networkInfo = *info;
        if (this->state == CommState::Station) {
            this->setState(CommState::StationConnected);
        }
        this->onNetworkInfoChanged();

        this->publishSessionRegistry();
    }

    void LANDiscovery::onConnect(int new_fd) {
        LogFormat("Accepted %d", new_fd);
        if (this->stationCount() >= StationCountMax) {
            LogFormat("Close new_fd. stations are full");
            close(new_fd);
            return;
        }

        /* Accepted sockets don't reliably inherit options from the listener. */
        this->setSocketOpts(new_fd, true);

        bool found = false;
        for (auto &i : this->stations) {
            if (i.getStatus() == NodeStatus::Disconnected) {
                i.link(new_fd);
                found = true;
                break;
            }
        }

        if (!found) {
            LogFormat("Close new_fd. no free station found");
            close(new_fd);
        }
    }

    void LANDiscovery::onRelayConnect(const NodeInfo *info) {
        /* Relay-mode equivalent of onConnect: there is no per-station TCP
           socket, so the joining station becomes a connected node record and
           the resulting SyncNetwork goes out over the shared relay from
           updateNodes(). Real IPs are kept throughout, so nodes[].ipv4Address
           stays consistent with what the game reads from GetIpv4Address. */
        std::scoped_lock lock(this->dataMutex);

        /* Idempotent: a dropped SyncNetwork makes the station retry Connect.
           If we already have this station, just re-sync instead of allocating
           a duplicate node slot. */
        for (auto &st : this->stations) {
            if (st.getStatus() != NodeStatus::Disconnected &&
                st.nodeInfo->ipv4Address == info->ipv4Address) {
                LogFormat("relay: duplicate Connect from %08x, re-syncing", info->ipv4Address);
                st.lastSeen = os::GetSystemTick();
                this->updateNodes();
                return;
            }
        }

        if (this->stationCount() >= StationCountMax) {
            LogFormat("relay: stations full, ignoring Connect");
            return;
        }
        for (auto &st : this->stations) {
            if (st.getStatus() == NodeStatus::Disconnected) {
                *st.nodeInfo = *info;             /* into networkInfo.ldn.nodes[nodeId] */
                st.status = NodeStatus::Connected;
                st.lastSeen = os::GetSystemTick();
                LogFormat("relay: station %d connected (%08x)", st.nodeId, info->ipv4Address);
                this->updateNodes();              /* recount + broadcast SyncNetwork */
                return;
            }
        }
        LogFormat("relay: no free station slot");
    }

    void LANDiscovery::onDisconnectFromHost() {
        LogFormat("onDisconnectFromHost state: %d", static_cast<int>(this->state));
        if (this->state == CommState::StationConnected) {
            {
                /* Stop heartbeating / staleness-checking a session we left. */
                std::scoped_lock lock(this->dataMutex);
                this->relayJoined = false;
            }
            /* Real ldn reports why the station left the network; without
               this the game polls GetDisconnectReason, sees None and may
               wait forever instead of showing its error UI. */
            this->disconnect_reason = DisconnectReason::SignalLost;
            this->setState(CommState::Station);
        }
    }

    void LANDiscovery::onNetworkInfoChanged() {
        if (this->isNodeStateChanged()) {
            this->lanEvent();
        }
        return;
    }

    Result LANDiscovery::setAdvertiseData(const u8 *data, uint16_t size) {
        if (size > AdvertiseDataSizeMax) {
            return MAKERESULT(ModuleID, 10);
        }

        std::scoped_lock lock(this->dataMutex);
        if (size > 0 && data != nullptr) {
            std::memcpy(this->networkInfo.ldn.advertiseData, data, size);
        } else {
            LogFormat("LANDiscovery::setAdvertiseData data %p size %lu", data, size);
        }
        this->networkInfo.ldn.advertiseDataSize = size;

        this->updateNodes();

        return 0;
    }

    Result LANDiscovery::initNetworkInfo() {
        Result rc = getFakeMac(&this->networkInfo.common.bssid);
        if (R_FAILED(rc)) {
            return rc;
        }
        this->networkInfo.common.channel = 6;
        this->networkInfo.common.linkLevel = 3;
        this->networkInfo.common.networkType = 2;
        this->networkInfo.common.ssid = FakeSsid;

        auto nodes = this->networkInfo.ldn.nodes;
        for (int i = 0; i < NodeCountMax; i++) {
            nodes[i].nodeId = i;
            nodes[i].isConnected = 0;
        }

        return 0;
    }

    Result LANDiscovery::getFakeMac(MacAddress *mac) {
        mac->raw[0] = 0x02;
        mac->raw[1] = 0x00;

        u32 ip;
        Result rc = nifmGetCurrentIpAddress(&ip);
        if (R_SUCCEEDED(rc)) {
            ip = ntohl(ip);
            memcpy(mac->raw + 2, &ip, sizeof(ip));
        }

        return rc;
    }

    Result LANDiscovery::setSocketOpts(int fd, bool isTcp) {
        int rc;

        if (!isTcp) {
            int b = 1;
            rc = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &b, sizeof(b));
            if (rc != 0) {
                return MAKERESULT(ModuleID, 4);
            }
        }
        {
            int yes = 1;
            rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
            if (rc != 0) {
                // return MAKERESULT(ModuleID, 5);
                LogFormat("SO_REUSEADDR failed");
            }
        }
        if (isTcp) {
            /* Sync packets are small; without this Nagle delays them behind ACKs. */
            int nodelay = 1;
            rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
            if (rc != 0) {
                LogFormat("TCP_NODELAY failed");
            }
            /* Bound blocking sends so one stalled station cannot hang the worker. */
            struct timeval tv = {.tv_sec = 3, .tv_usec = 0};
            rc = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (rc != 0) {
                LogFormat("SO_SNDTIMEO failed");
            }
        }

        return 0;
    }

    Result LANDiscovery::initTcp(bool listening) {
        int fd;
        Result rc;
        struct sockaddr_in addr;
        std::scoped_lock lock(this->pollMutex);

        if (this->tcp) {
            this->tcp->close();
        }
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return MAKERESULT(ModuleID, 6);
        }
        auto tcpSocket = std::make_unique<LDTcpSocket>(fd, this);

        /* SO_REUSEADDR must be set before bind to have any effect. */
        rc = setSocketOpts(fd, true);
        if (R_FAILED(rc)) {
            return rc;
        }
        if (listening) {
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(listenPort);
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                return MAKERESULT(ModuleID, 7);
            }
            if (listen(fd, 10) != 0) {
                return MAKERESULT(ModuleID, 8);
            }
        }

        this->tcp = std::move(tcpSocket);

        return 0;
    }

    Result LANDiscovery::initUdp(bool listening) {
        int fd;
        Result rc;
        struct sockaddr_in addr;
        std::scoped_lock lock(this->pollMutex);

        if (this->udp) {
            this->udp->close();
        }
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            return MAKERESULT(ModuleID, 1);
        }
        auto udpSocket = std::make_unique<LDUdpSocket>(fd, this);

        /* SO_REUSEADDR must be set before bind to have any effect. */
        rc = setSocketOpts(fd, false);
        if (R_FAILED(rc)) {
            return rc;
        }
        if (listening) {
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(listenPort);
            if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
                return MAKERESULT(ModuleID, 2);
            }
        }

        this->udp = std::move(udpSocket);

        return 0;
    }

    void LANDiscovery::initNodeStateChange() {
        for (auto &i : this->nodeChanges) {
            i.stateChange = NodeStateChange_None;
        }
        for (auto &i : this->nodeLastStates) {
            i = 0;
        }
    }

    bool LANDiscovery::isNodeStateChanged() {
        bool changed = false;
        const auto &nodes = this->networkInfo.ldn.nodes;
        for (int i = 0; i < NodeCountMax; i++) {
            if (nodes[i].isConnected != this->nodeLastStates[i]) {
                if (nodes[i].isConnected) {
                    this->nodeChanges[i].stateChange |= NodeStateChange_Connect;
                } else {
                    this->nodeChanges[i].stateChange |= NodeStateChange_Disconnect;
                }
                this->nodeLastStates[i] = nodes[i].isConnected;
                changed = true;
            }
        }
        return changed;
    }

    void LANDiscovery::Worker(void* args) {
        LANDiscovery* self = (LANDiscovery*)args;

        self->worker();
    }

    Result LANDiscovery::scan(NetworkInfo *pOutNetwork, u16 *count, ScanFilter filter) {
        if (!this->initialized || !this->udp) {
            *count = 0;
            return MAKERESULT(ModuleID, 20);
        }

        {
            std::scoped_lock lock(this->dataMutex);
            this->udp->scanResults.clear();
            /* Refresh our own IP so the ScanResp handler can drop our own
               advertisement when a relay (lan-play) echoes it back at us. */
            u32 myIp = 0;
            if (R_SUCCEEDED(nifmGetCurrentIpAddress(&myIp))) {
                this->udp->selfIp = ntohl(myIp);
            } else {
                this->udp->selfIp = 0;
            }
        }

        /* Broadcast a few times (UDP may drop packets) and exit early once
           results have been stable for two consecutive 100ms checks, instead
           of always blocking for a full second. */
        size_t lastCount = 0;
        int stable = 0;
        for (int j = 0; j < 10; j++) {
            if (j % 3 == 0) {
                int len = this->udp->sendBroadcast(LANPacketType::Scan);
                if (len < 0 && j == 0) {
                    return MAKERESULT(ModuleID, 20);
                }
                if (this->relay) {
                    this->relay->sendBroadcast(LANPacketType::Scan);
                }
            }
            svcSleepThread(100000000L); // 100ms

            std::scoped_lock lock(this->dataMutex);
            const size_t cur = this->udp->scanResults.size();
            if (cur > 0 && cur == lastCount) {
                if (++stable >= 2) {
                    break;
                }
            } else {
                stable = 0;
            }
            lastCount = cur;
        }

        std::scoped_lock lock(this->dataMutex);
        LogFormat("scan filter flag %x comm %lx scene %d type %u session %lx.%lx ssid(%d) %.32s",
            filter.flag,
            filter.networkId.intentId.localCommunicationId, filter.networkId.intentId.sceneId,
            filter.networkType,
            filter.networkId.sessionId.high, filter.networkId.sessionId.low,
            filter.ssid.length, filter.ssid.raw);
        int i = 0;
        for (auto& item : this->udp->scanResults) {
            if (i >= *count) {
                break;
            }
            auto &info = item.second;

            bool copy = true;
            // filter
            if (filter.flag & ScanFilterFlag_LocalCommunicationId) {
                copy &= filter.networkId.intentId.localCommunicationId == info.networkId.intentId.localCommunicationId;
            }
            if (filter.flag & ScanFilterFlag_SessionId) {
                copy &= filter.networkId.sessionId == info.networkId.sessionId;
            }
            if (filter.flag & ScanFilterFlag_NetworkType) {
                copy &= filter.networkType == info.common.networkType;
            }
            if (filter.flag & ScanFilterFlag_Ssid) {
                copy &= filter.ssid == info.common.ssid;
            }
            if (filter.flag & ScanFilterFlag_SceneId) {
                copy &= filter.networkId.intentId.sceneId == info.networkId.intentId.sceneId;
            }

            LogFormat("scan cand comm %lx scene %d type %u session %lx.%lx ssid(%d) %.32s -> %d",
                info.networkId.intentId.localCommunicationId, info.networkId.intentId.sceneId,
                info.common.networkType,
                info.networkId.sessionId.high, info.networkId.sessionId.low,
                info.common.ssid.length, info.common.ssid.raw,
                static_cast<int>(copy));

            if (copy) {
                pOutNetwork[i++] = info;
            }
        }
        *count = i;

        return 0;
    }

    void LANDiscovery::resetStations() {
        for (auto &i : this->stations) {
            i.reset();
        }
    }

    int LANDiscovery::stationCount() {
        int count = 0;

        for (auto const &i : this->stations) {
            if (i.getStatus() != NodeStatus::Disconnected) {
                count++;
            }
        }

        return count;
    }

    void LANDiscovery::updateNodes() {
        std::scoped_lock lock(this->dataMutex);
        int count = 0;
        for (auto &i : this->stations) {
            bool connected = i.getStatus() == NodeStatus::Connected;
            if (connected) {
                count++;
            }
            i.overrideInfo();
        }
        this->networkInfo.ldn.nodeCount = count + 1;

        if (this->relay) {
            /* Relay mode: stations joined over the relay have no per-station
               TCP socket, so one broadcast reaches them all at once. */
            this->relay->send(LANPacketType::SyncNetwork, &this->networkInfo, sizeof(this->networkInfo));
        }
        /* Also sync every station that DOES hold a TCP socket. In pure local
           mode that is all of them; in relay mode it is any same-LAN console
           that joined over TCP (relay off on its end) - dropping this send is
           what left such a joiner stuck waiting for SyncNetwork. Relay-only
           stations have no socket (getFd() < 0) and are skipped here. */
        for (auto &i : stations) {
            if (i.getStatus() == NodeStatus::Connected && i.getFd() >= 0) {
                int ret = i.sendPacket(LANPacketType::SyncNetwork, &this->networkInfo, sizeof(this->networkInfo));
                if (ret < 0) {
                    LogFormat("Failed to sendTcp");
                }
            }
        }

        this->onNetworkInfoChanged();

        this->publishSessionRegistry();
    }

    void LANDiscovery::publishSessionRegistry() {
        /* Called with dataMutex held (updateNodes / onSyncNetwork). Hand the
           current peer IPs to the bsd:u mitm so it can turn the game's LDN
           broadcasts into per-peer unicast. */
        u32 address = 0, netmask = 0, gateway, primary_dns, secondary_dns;
        if (R_FAILED(nifmGetCurrentIpConfigInfo(&address, &netmask, &gateway, &primary_dns, &secondary_dns))) {
            return;
        }
        const u32 self_ip = ntohl(address);
        const u32 bcast_ip = self_ip | ~ntohl(netmask);

        u32 peers[SessionRegistry::MaxPeers];
        int count = 0;
        const int node_count = this->networkInfo.ldn.nodeCount;
        for (int i = 0; i < node_count && i < NodeCountMax; i++) {
            const u32 ip = this->networkInfo.ldn.nodes[i].ipv4Address; /* host order */
            if (ip == 0 || ip == self_ip) {
                continue;
            }
            if (count < SessionRegistry::MaxPeers) {
                peers[count++] = ip;
            }
        }

        SessionRegistry::Publish(bcast_ip, peers, count);
    }

    int LANDiscovery::loopPoll() {
        int rc;
        if (!initialized) {
            return 0;
        }

        std::scoped_lock lock(this->pollMutex);
        int nfds = 3 + StationCountMax;
        Pollable *fds[nfds];
        fds[0] = this->udp.get();
        fds[1] = this->tcp.get();
        fds[2] = this->relay.get(); /* null unless relay mode; Poll handles null */
        for (int i = 0; i < StationCountMax; i++) {
            fds[3 + i] = this->stations.data() + i;
        }
        rc = Pollable::Poll(fds, nfds);

        return rc;
    }

    LANDiscovery::~LANDiscovery() {
        LogFormat("~LANDiscovery");
        if (this->initialized) {
            LogFormat("finalize not called");
            Result rc = this->finalize();
            LogFormat("finalize: %d", rc);
        }
    }

    void LANDiscovery::worker() {
        this->stop = false;
        /* loopPoll() blocks up to the poll timeout (100ms default), so loop
           iterations are ~100ms, not 1ms - a per-iteration counter would fire
           the keepalive ~100x too slowly (every ~8min). Measure real elapsed
           time instead so registration is refreshed well within the relay
           server's idle timeout (60s). */
        os::Tick last_beacon = os::GetSystemTick();
        while (!this->stop) {

            int rc = loopPoll();
            if (rc < 0) {
                break;
            }
            if (this->relay) {
                const os::Tick now = os::GetSystemTick();
                if (os::ConvertToTimeSpan(now - last_beacon).GetMilliSeconds() >= RelayBeaconIntervalMs) {
                    last_beacon = now;
                    /* A host that is merely idling in a lobby (no station has
                       joined yet) otherwise transmits nothing but the empty
                       keepalive, which carries no source IP - so the relay
                       server never learns its endpoint and a remote joiner's
                       Scan is forwarded to nobody. Re-broadcast our network
                       advertisement instead: it registers our source at the
                       server AND lets remote consoles discover us proactively.
                       Non-hosts just refresh their registration. */
                    if (this->state == CommState::AccessPointCreated) {
                        std::scoped_lock lock(this->dataMutex);
                        this->lastRelayAdvertise = now;
                        this->relay->send(LANPacketType::ScanResp, &this->networkInfo, sizeof(this->networkInfo));
                    } else if (this->state == CommState::StationConnected && this->relayJoined) {
                        /* Connected over the relay: heartbeat so the host can
                           tell we are alive even while idle (game traffic does
                           not pass through LANDiscovery). Being an IPv4 frame
                           with our source address, it also refreshes our
                           registration at the relay server - no separate
                           keepalive needed. */
                        RelayHeartbeatPayload hb = {};
                        {
                            std::scoped_lock lock(this->dataMutex);
                            hb.bssid = this->joinBssid;
                            hb.ipv4  = this->relayJoinedIp;
                        }
                        this->relay->send(LANPacketType::RelayHeartbeat, &hb, sizeof(hb));
                    } else {
                        this->relay->keepalive();
                    }

                    /* Peer-loss detection (relay only): there is no TCP socket
                       whose close reports a vanished relay peer, so reap peers
                       that have been silent longer than RelayPeerTimeoutMs.
                       Liveness stamps come from the host's 5s beacon /
                       SyncNetwork (station side) and from station heartbeats /
                       Connect retries (host side). Checked on the beacon
                       cadence - +-5s precision is fine for a 30s timeout. */
                    if (this->state == CommState::AccessPointCreated) {
                        std::scoped_lock lock(this->dataMutex);
                        bool changed = false;
                        for (auto &st : this->stations) {
                            if (st.getStatus() == NodeStatus::Connected && st.getFd() < 0 &&
                                os::ConvertToTimeSpan(now - st.lastSeen).GetMilliSeconds() >= RelayPeerTimeoutMs) {
                                LogFormat("relay: station %d (%08x) silent > %ds, dropping",
                                    st.nodeId, st.nodeInfo->ipv4Address,
                                    static_cast<int>(RelayPeerTimeoutMs / 1000));
                                st.reset();
                                changed = true;
                            }
                        }
                        if (changed) {
                            this->updateNodes();  /* recount + SyncNetwork to survivors */
                        }
                    } else if (this->state == CommState::StationConnected) {
                        bool host_lost = false;
                        {
                            std::scoped_lock lock(this->dataMutex);
                            host_lost = this->relayJoined &&
                                os::ConvertToTimeSpan(now - this->hostLastSeen).GetMilliSeconds() >= RelayPeerTimeoutMs;
                        }
                        if (host_lost) {
                            LogFormat("relay: host silent > %ds, disconnecting",
                                static_cast<int>(RelayPeerTimeoutMs / 1000));
                            this->onDisconnectFromHost();  /* SignalLost -> game error UI */
                        }
                    }
                }
            }
            /* Brief unlocked window so IPC threads can grab pollMutex;
               kept at 1ms so packet handling latency stays low. */
            svcSleepThread(1000000L); // 1ms
        }
        LogFormat("Worker exit");
    }

    Result LANDiscovery::getNetworkInfo(NetworkInfo *pOutNetwork) {
        Result rc = 0;

        if (this->state == CommState::AccessPointCreated || this->state == CommState::StationConnected) {
            std::scoped_lock lock(this->dataMutex);
            std::memcpy(pOutNetwork, &networkInfo, sizeof(networkInfo));
        } else {
            rc = MAKERESULT(LdnModuleId, 32);
        }

        return rc;
    }

    Result LANDiscovery::getNetworkInfo(NetworkInfo *pOutNetwork, NodeLatestUpdate *pOutUpdates, int bufferCount) {
        Result rc = 0;

        if (bufferCount < 0 || bufferCount > NodeCountMax) {
            return MAKERESULT(ModuleID, 50);
        }

        if (this->state == CommState::AccessPointCreated || this->state == CommState::StationConnected) {
            std::scoped_lock lock(this->dataMutex);
            std::memcpy(pOutNetwork, &networkInfo, sizeof(networkInfo));

            char str[10] = {0};
            for (int i = 0; i < bufferCount; i++) {
                pOutUpdates[i].stateChange = nodeChanges[i].stateChange;
                nodeChanges[i].stateChange = NodeStateChange_None;
                str[i] = '0' + pOutUpdates[i].stateChange;
            }
            LogFormat("getNetworkInfo updates %s", str);
        } else {
            rc = MAKERESULT(LdnModuleId, 32);
        }

        return rc;
    }

    Result LANDiscovery::getNodeInfo(NodeInfo *node, const UserConfig *userConfig, u16 localCommunicationVersion) {
        u32 ipAddress;
        Result rc = nifmGetCurrentIpAddress(&ipAddress);
        if (R_FAILED(rc))
        {
            return rc;
        }
        ipAddress = ntohl(ipAddress);
        rc = getFakeMac(&node->macAddress);
        if (R_FAILED(rc)) {
            return rc;
        }

        node->isConnected = 1;
        strcpy(node->userName, userConfig->userName);
        node->localCommunicationVersion = localCommunicationVersion;
        node->ipv4Address = ipAddress;

        return 0;
    }

    Result LANDiscovery::createNetwork(const SecurityConfig *securityConfig, const UserConfig *userConfig, const NetworkConfig *networkConfig) {
        return this->createNetworkImpl(securityConfig, nullptr, userConfig, networkConfig);
    }

    Result LANDiscovery::createNetworkPrivate(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig) {
        return this->createNetworkImpl(securityConfig, securityParameter, userConfig, networkConfig);
    }

    Result LANDiscovery::createNetworkImpl(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig) {
        LogFormat("SecurityConfig");
        LogHex(securityConfig->passphrase, securityConfig->passphraseSize);
        Result rc = 0;

        if (this->state != CommState::AccessPoint) {
            return MAKERESULT(LdnModuleId, 32);
        }

        rc = this->initTcp(true);
        if (R_FAILED(rc)) {
            return rc;
        }

        /* Everything below mutates networkInfo/node state shared with the
           worker thread. initTcp stays outside: it takes pollMutex, and
           dataMutex must never be held while acquiring pollMutex. */
        std::scoped_lock lock(this->dataMutex);
        rc = this->initNetworkInfo();
        if (R_FAILED(rc)) {
            return rc;
        }
        this->networkInfo.ldn.nodeCountMax = networkConfig->nodeCountMax;
        this->networkInfo.ldn.securityMode = securityConfig->securityMode;

        if (networkConfig->channel == 0) {
            this->networkInfo.common.channel = 6;
        } else {
            this->networkInfo.common.channel = networkConfig->channel;
        }

        if (securityParameter != nullptr) {
            /* Private network: the session id comes from the link code via
               SecurityParameter, so all participants derive the same one. */
            std::memcpy(&this->networkInfo.networkId.sessionId, securityParameter->sessionId, sizeof(SessionId));
            std::memcpy(this->networkInfo.ldn.unkRandom, securityParameter->unkRandom, sizeof(this->networkInfo.ldn.unkRandom));
        } else {
            ams::os::GenerateRandomBytes(&this->networkInfo.networkId.sessionId, sizeof(SessionId));
        }
        this->networkInfo.networkId.intentId = networkConfig->intentId;
        LogFormat("createNetwork comm %lx scene %d session %lx.%lx",
            this->networkInfo.networkId.intentId.localCommunicationId,
            this->networkInfo.networkId.intentId.sceneId,
            this->networkInfo.networkId.sessionId.high, this->networkInfo.networkId.sessionId.low);

        NodeInfo *node0 = &this->networkInfo.ldn.nodes[0];
        rc = this->getNodeInfo(node0, userConfig, networkConfig->localCommunicationVersion);
        if (R_FAILED(rc)) {
            return rc;
        }

        this->setState(CommState::AccessPointCreated);

        this->initNodeStateChange();
        node0->isConnected = 1;
        this->updateNodes();

        return rc;
    }

    Result LANDiscovery::destroyNetwork() {
        SessionRegistry::Clear();
        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::AccessPoint);

        return 0;
    }

    Result LANDiscovery::disconnect() {
        SessionRegistry::Clear();
        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
        }
        {
            /* No longer joined: stop accepting sync for the old network. */
            std::scoped_lock lock(this->dataMutex);
            this->joinActive = false;
            this->relayJoined = false;
        }
        this->setState(CommState::Station);

        return 0;
    }

    Result LANDiscovery::refreshNetworkSession() {
        /* The relay decision is latched at initialize(): it selects the nifm
           request mode (plain internet vs LocalNetworkMode) AND whether the
           relay transport opens, so a live toggle cannot simply open a
           socket later. The game only reaches openAccessPoint/openStation
           from its host/join menus - never mid-session - so if the overlay
           toggle changed since the latch (or the session was gutted by a
           sleep/wake, via the HUP closes), rebuild the whole network session in
           the right mode. Users don't need to relaunch the game. */
        const bool relay_changed = this->initRelay != relay::IsEnabled();
        if (!this->initialized || (!relay_changed && !this->needsReinit)) {
            return 0;
        }
        LogFormat("refreshing network session (relay %d -> %d, post-sleep %d)",
            static_cast<int>(this->initRelay), static_cast<int>(relay::IsEnabled()),
            static_cast<int>(this->needsReinit));
        LanEventFunc ev = this->lanEvent;
        this->finalize();  /* failures are logged inside; state is torn down regardless */
        R_RETURN(this->initialize(ev, this->initListening));
    }

    Result LANDiscovery::openAccessPoint() {
        this->disconnect_reason = DisconnectReason::None;
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }
        R_TRY(this->refreshNetworkSession());

        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::AccessPoint);

        return 0;
    }

    Result LANDiscovery::closeAccessPoint() {
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }

        SessionRegistry::Clear();
        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::Initialized);

        return 0;
    }

    Result LANDiscovery::openStation() {
        this->disconnect_reason = DisconnectReason::None;
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }
        R_TRY(this->refreshNetworkSession());

        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }
        {
            /* Browsing again, not joining any network yet: reject stray sync. */
            std::scoped_lock lock(this->dataMutex);
            this->joinActive = false;
            this->relayJoined = false;
        }

        this->setState(CommState::Station);

        return 0;
    }

    Result LANDiscovery::closeStation() {
        if (this->state == CommState::None) {
            return MAKERESULT(LdnModuleId, 32);
        }

        SessionRegistry::Clear();
        {
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            this->resetStations();
        }

        this->setState(CommState::Initialized);

        return 0;
    }

    Result LANDiscovery::connect(const NetworkInfo *networkInfo, UserConfig *userConfig, u16 localCommunicationVersion) {
        if (networkInfo->ldn.nodeCount == 0) {
            return MAKERESULT(ModuleID, 30);
        }

        u32 hostIp = networkInfo->ldn.nodes[0].ipv4Address;

        /* Refuse to connect to ourselves. This happens when the relay echoes
           our own advertisement back, or when two consoles are (mis)configured
           with the same IP — the TCP connect would target our own address and
           fail, and the game would retry in a tight loop. */
        u32 myIp;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&myIp))) {
            myIp = ntohl(myIp);
            if (hostIp == myIp) {
                LogFormat("connect: host IP %x equals our own; refusing self-connect", hostIp);
                return ResultConnectFailed;
            }
        }

        /* Record the target network so onSyncNetwork only accepts sync for it
           (a shared relay carries other sessions' SyncNetwork to us too). Must
           be set before Connect goes out so a fast reply is not rejected. */
        {
            std::scoped_lock lock(this->dataMutex);
            this->joinBssid = networkInfo->common.bssid;
            this->joinActive = true;
        }

        /* Relay mode: the host's IP is a real address on another network,
           unroutable directly across the internet, so there is no TCP to it.
           Send Connect over the relay and wait for the host's SyncNetwork
           (broadcast back over the relay) to mark us StationConnected. Real
           IPs are advertised throughout — the relay routes control frames as
           broadcasts, so no virtual addressing is needed here, and NodeInfo
           stays consistent with the game's own GetIpv4Address. */
        if (this->relay) {
            NodeInfo myNode = {0};
            Result rc = this->getNodeInfo(&myNode, userConfig, localCommunicationVersion);
            if (R_FAILED(rc)) {
                return rc;
            }
            {
                std::scoped_lock lock(this->dataMutex);
                this->initNodeStateChange();
            }
            LogFormat("relay connect: sending Connect to host %08x", hostIp);
            this->relay->send(LANPacketType::Connect, &myNode, sizeof(myNode));

            for (int j = 0; j < 300; j++) {
                if (this->state == CommState::StationConnected) {
                    LogFormat("relay connect: joined");
                    {
                        /* Arm relay peer-loss detection: heartbeats out every
                           beacon interval, host silence reaped by the worker. */
                        std::scoped_lock lock(this->dataMutex);
                        this->relayJoined   = true;
                        this->relayJoinedIp = myNode.ipv4Address;
                        this->hostLastSeen  = os::GetSystemTick();
                    }
                    return 0;
                }
                svcSleepThread(10000000L); /* 10ms */
            }
            /* No SyncNetwork over the relay. The host may be a local console
               that is not on the relay (relay off there, or its relay open
               failed), so fall through to a direct TCP join: on the same LAN
               hostIp still reaches the host's TCP listener. If the host really
               is remote, the TCP connect below times out and we fail as
               before, just a few seconds later. */
            LogFormat("relay connect: no SyncNetwork, falling back to direct TCP to %08x", hostIp);
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(hostIp);
        addr.sin_port = htons(listenPort);
        LogFormat("connect hostIp %x", hostIp);

        Result rc = this->initTcp(false);
        if (R_FAILED(rc)) {
            return rc;
        }

        /* Non-blocking connect with our own timeout: a stale scan result must
           not freeze the game for the OS's full TCP connect timeout. */
        const int fd = this->tcp->getFd();
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        int ret = ::connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret != 0) {
            if (flags < 0 || errno != EINPROGRESS) {
                LogFormat("connect failed");
                return ResultConnectFailed;
            }
            struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
            ret = poll(&pfd, 1, 5000);
            if (ret <= 0) {
                LogFormat("connect timeout");
                return ResultConnectFailed;
            }
            int err = 0;
            socklen_t errlen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0 || err != 0) {
                LogFormat("connect failed. SO_ERROR %d", err);
                return ResultConnectFailed;
            }
        }
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags);
        }

        NodeInfo myNode = {0};
        rc = this->getNodeInfo(&myNode, userConfig, localCommunicationVersion);
        if (R_FAILED(rc)) {
            return rc;
        }
        ret = this->tcp->sendPacket(LANPacketType::Connect, &myNode, sizeof(myNode));
        if (ret < 0) {
            LogFormat("sendPacket failed");
            return ResultConnectFailed;
        }
        {
            std::scoped_lock lock(this->dataMutex);
            this->initNodeStateChange();
        }

        /* Wait for the host's SyncNetwork instead of a fixed 1s sleep;
           on a LAN this typically completes within a few ms. */
        bool synced = false;
        for (int j = 0; j < 300; j++) {
            if (this->state == CommState::StationConnected) {
                synced = true;
                break;
            }
            svcSleepThread(10000000L); // 10ms
        }

        /* The original code returned success unconditionally here. If the
           host never syncs (e.g. it went to sleep after advertising), the
           game would be told it joined and hang waiting for nodes forever.
           Fail instead so it can show a proper error. */
        if (!synced) {
            LogFormat("connect: no SyncNetwork from host, aborting join");
            std::scoped_lock lock(this->pollMutex);
            if (this->tcp) {
                this->tcp->close();
            }
            return ResultConnectFailed;
        }

        return 0;
    }

    Result LANDiscovery::connectPrivate(const SecurityParameterData *securityParameter, const UserConfig *userConfig, u16 localCommunicationVersion, const NetworkConfig *networkConfig) {
        AMS_UNUSED(networkConfig);

        /* Unlike Connect, ConnectPrivate does not hand us a NetworkInfo:
           we must find the host whose session id matches the link code's
           SecurityParameter ourselves. */
        ScanFilter filter = {};
        std::memcpy(&filter.networkId.sessionId, securityParameter->sessionId, sizeof(SessionId));
        filter.flag = ScanFilterFlag_SessionId;

        constexpr u16 ResultCountMax = 8;
        auto results = std::make_unique<NetworkInfo[]>(ResultCountMax);

        u32 myIp = 0;
        if (R_SUCCEEDED(nifmGetCurrentIpAddress(&myIp))) {
            myIp = ntohl(myIp);
        } else {
            myIp = 0;
        }

        for (int attempt = 0; attempt < 3; attempt++) {
            u16 count = ResultCountMax;
            Result rc = this->scan(results.get(), &count, filter);
            if (R_FAILED(rc)) {
                continue;
            }
            /* Pick the first result that isn't ourselves (the relay may echo
               our own advertisement back into the scan results). */
            for (u16 j = 0; j < count; j++) {
                if (myIp != 0 && results[j].ldn.nodes[0].ipv4Address == myIp) {
                    LogFormat("connectPrivate: skipping self result %x", myIp);
                    continue;
                }
                LogFormat("connectPrivate: found session on attempt %d idx %d", attempt, j);
                UserConfig config = *userConfig;
                return this->connect(&results[j], &config, localCommunicationVersion);
            }
        }

        LogFormat("connectPrivate: no network with matching session id");
        return ResultConnectFailed;
    }

    Result LANDiscovery::finalize() {
        Result rc = 0;

        if (this->initialized) {
            SessionRegistry::Clear();
            this->stop = true;
            os::WaitThread(&this->workerThread);
            os::DestroyThread(&this->workerThread);
            this->udp.reset();
            this->tcp.reset();
            this->relay.reset(); /* dtor releases the relay socket + nifm request */
            this->resetStations();
            this->initialized = false;

            rc = nifmRequestCancel(&request);
            if (R_FAILED(rc))
            {
                LogFormat("final nifmRequestCancel failed: %x", rc);
            }
            /* Close frees the IRequest session and the two Event handles the
               request holds. Cancel alone leaks them, so rapid init/finalize
               cycling exhausts nifm sessions (2110-0350) and the process
               handle table, ending in a fatal crash. */
            nifmRequestClose(&request);

            NifmNetworkProfileData networkProfile;
            rc = nifmGetCurrentNetworkProfile(&networkProfile);
            if (R_FAILED(rc))
            {
                LogFormat("final nifmGetCurrentProfile failed: %x", rc);
            } else if (networkProfile.ip_setting_data.mtu != originalMtu) {
                /* Only restore if we actually changed it, to avoid needless
                   profile writes on every finalize. */
                networkProfile.ip_setting_data.mtu = originalMtu;
                rc = nifmSetNetworkProfile(&networkProfile, &networkProfile.uuid);
                if (R_FAILED(rc)) {
                    LogFormat("final nifmSetNetworkProfile failed: %x", rc);
                }
            }

            /* Matches the Acquire in initialize(). */
            NifmSessionManager::Release();
        }

        this->setState(CommState::None);

        return rc;
    }

    Result LANDiscovery::initialize(LanEventFunc lanEvent, bool listening) {
        if (this->initialized)
        {
            return 0;
        }

        /* Hold a nifm session for the whole initialized window; released in
           finalize(). On any failure below the guard releases it again. */
        Result rc = NifmSessionManager::Acquire();
        if (R_FAILED(rc)) {
            return rc;
        }
        auto nifmGuard = SCOPE_GUARD { NifmSessionManager::Release(); };

        NifmNetworkProfileData networkProfile;
        rc = nifmGetCurrentNetworkProfile(&networkProfile);
        if (R_FAILED(rc))
        {
            LogFormat("nifmGetCurrentNetworkProfile failed: %x", rc);
            return rc;
        }

        originalMtu = networkProfile.ip_setting_data.mtu;
        /* Respect the MTU configured in system settings instead of always
           forcing 1500. Over a lan-play relay the large LDN packets (Connect
           and SyncNetwork are ~1152B) plus the relay's UDP encapsulation
           exceed the internet path MTU and get dropped, which surfaces as the
           game's session layer failing (e.g. 2618-0006). Lowering the MTU in
           settings now actually takes effect. We still force 1500 only when
           the profile reports an unusable value. */
        /* Games can REQUIRE a large MTU: SF 30th AC's session layer (pia)
           refuses to run when the interface MTU is below its minimum — the
           host joins fine, then ignores all peer traffic and errors with
           2618-0006. Lowering the MTU (as lan-play guides recommend) is what
           breaks these games, so never clamp it down here; respect the
           profile and only fix unusable values. */
        int desiredMtu = originalMtu;
        if (desiredMtu == 0 || desiredMtu > 1500) {
            desiredMtu = 1500;
        }

        /* Only touch the profile if we actually need to change it. This both
           avoids needless nifm churn and preserves the true original value.
           mtuChanged tracks whether we must restore it if init fails partway. */
        bool mtuChanged = false;
        if (desiredMtu != originalMtu) {
            networkProfile.ip_setting_data.mtu = desiredMtu;
            rc = nifmSetNetworkProfile(&networkProfile, &networkProfile.uuid);
            if (R_FAILED(rc)) {
                LogFormat("nifmSetNetworkProfile failed: %x", rc);
                return rc;
            }
            mtuChanged = true;
        }

        auto restoreMtu = [&]() {
            if (!mtuChanged) {
                return;
            }
            NifmNetworkProfileData p;
            if (R_SUCCEEDED(nifmGetCurrentNetworkProfile(&p))) {
                p.ip_setting_data.mtu = originalMtu;
                nifmSetNetworkProfile(&p, &p.uuid);
            }
        };

        rc = nifmCreateRequest(&request, true);
        if (R_FAILED(rc))
        {
            /* nifm can transiently run out of request capacity when a game
               rapidly cycles init/finalize (a failed session retry storm).
               Restore state and return a clean error rather than leaking. */
            LogFormat("nifmCreateRequest failed: %x", rc);
            restoreMtu();
            return rc;
        }

        /* Latch the relay decision ONCE for this whole init. relay::IsEnabled()
           is a live, overlay-toggleable atomic; reading it separately for the
           nifm mode below and the transport open further down let a mid-init
           toggle produce an inconsistent session (internet request with no
           relay, or LocalNetworkMode with a relay socket that can't reach the
           server). One read keeps them consistent. */
        const bool use_relay = relay::IsEnabled();
        this->initRelay = use_relay;
        this->initListening = listening;
        this->needsReinit = false;

        /* Relay mode keeps the console on the INTERNET (so the relay socket
           can reach the server), so skip LocalNetworkMode; the submitted
           request is then a plain internet request. Local mode is only for
           same-network LDN. */
        if (!use_relay) {
            rc = nifmSetLocalNetworkMode(&request, true);
            if (R_FAILED(rc)) {
                LogFormat("nifmSetLocalNetworkMode failed %x", rc);
                nifmRequestCancel(&request);
                nifmRequestClose(&request);
                restoreMtu();
                return rc;
            }
        }

        rc = nifmRequestSubmitAndWait(&request);
        if (R_FAILED(rc))
        {
            LogFormat("nifmRequestSubmitAndWait failed: %x", rc);
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return rc;
        }

        for (auto &i : stations) {
            i.discovery = this;
            i.nodeInfo = &this->networkInfo.ldn.nodes[i.nodeId];
            i.reset();
        }

        this->lanEvent = lanEvent;
        rc = this->initUdp(listening);
        if (R_FAILED(rc)) {
            LogFormat("initUdp %x", rc);
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return rc;
        }

        /* Phase 1b: open the relay transport so discovery crosses the relay.
           Non-fatal if it fails - fall back to local-only discovery. Uses the
           same latched decision as the nifm mode above. */
        if (use_relay) {
            this->relay = std::make_unique<RelayLanSocket>(this);
            Result relay_rc = this->relay->open();
            if (R_FAILED(relay_rc)) {
                LogFormat("LANDiscovery: relay open failed %x (local-only)", relay_rc);
                this->relay.reset();
            } else {
                LogFormat("LANDiscovery: relay open ok");
            }
        }

        rc = os::CreateThread(&this->workerThread, &Worker, this, reinterpret_cast<void *>(util::AlignUp(reinterpret_cast<uintptr_t>(stack.get()), os::ThreadStackAlignment)), StackSize, 0x15, 2);
        if (R_FAILED(rc)) {
            LogFormat("LANDiscovery Failed to threadCreate: %x", rc);
            this->udp.reset();
            nifmRequestCancel(&request);
            nifmRequestClose(&request);
            restoreMtu();
            return 0xF601;
        }

        os::StartThread(&this->workerThread);
        this->setState(CommState::Initialized);

        this->initialized = true;
        nifmGuard.Cancel();
        return 0;
    }
}
