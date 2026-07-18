#pragma once
#include <stratosphere.hpp>
#include "debug.hpp"
#include <memory>
#include <thread>
#include <array>
#include <mutex>
#include <unordered_map>
#include <stdint.h>
#include <unistd.h>
#include <cstring>
#include "ldn_types.hpp"
#include "lan_protocol.hpp"
#include "relay_client.hpp"

namespace ams::mitm::ldn {
    const size_t StackSize = 0x4000;
    enum class NodeStatus : u8 {
        Disconnected,
        Connect,
        Connected,
    };
    enum class DisconnectReason {
        None,
        DisconnectedByUser,
        DisconnectedBySystem,
        DestroyedByUser,
        DestroyedBySystem,
        Rejected,
        SignalLost
    };

    class LANDiscovery;

    /* Payload of LANPacketType::RelayHeartbeat. The bssid scopes the
       heartbeat to one session (a shared relay carries other sessions'
       broadcasts too, and private IPs can collide across NATs); ipv4 is the
       sender's address in host byte order, matching NodeInfo::ipv4Address. */
    struct RelayHeartbeatPayload {
        MacAddress bssid;
        u8 _pad[2];
        u32 ipv4;
    };

    class LanStation : public Pollable {
        protected:
            friend class LANDiscovery;
            /* Heartbeat receive path stamps lastSeen and matches nodeInfo. */
            friend class RelayLanSocket;
            NodeInfo *nodeInfo;
            NodeStatus status;
            std::unique_ptr<TcpLanSocketBase> socket;
            int nodeId;
            LANDiscovery *discovery;
        public:
            /* Relay stations only (no TCP socket): last time the host heard
               anything from this station. Guarded by discovery->dataMutex. */
            os::Tick lastSeen = os::Tick(0);
        public:
            LanStation(int nodeId, LANDiscovery *discovery)
                : nodeInfo(nullptr),
                status(NodeStatus::Disconnected),
                nodeId(nodeId),
                discovery(discovery)
            {}
            NodeStatus getStatus() const {
                return this->status;
            }
            void reset() {
                this->socket.reset();
                this->status = NodeStatus::Disconnected;
            };
            void link(int fd) {
                this->socket = std::make_unique<TcpLanSocketBase>(fd);
                this->status = NodeStatus::Connect;
            };
            int getFd() override {
                if (!this->socket) {
                    return -1;
                }
                return this->socket->getFd();
            };
            int onRead() override;
            void onClose() override;
            int sendPacket(LANPacketType type, const void *data, size_t size) {
                if (!this->socket) {
                    return -1;
                }
                return this->socket->sendPacket(type, data, size);
            };
            void overrideInfo() {
                bool connected = this->getStatus() == NodeStatus::Connected;
                this->nodeInfo->nodeId = this->nodeId;
                if (connected) {
                    this->nodeInfo->isConnected = 1;
                } else {
                    this->nodeInfo->isConnected = 0;
                }
            }
    };

    class LDUdpSocket : public UdpLanSocketBase, public Pollable {
        protected:
            struct MacHash {
                std::size_t operator() (const MacAddress &t) const {
                    return *reinterpret_cast<const u32*>(t.raw + 2);
                }
            };
            virtual u32 getBroadcast() override;
            LANDiscovery *discovery;
        public:
            std::unordered_map<MacAddress, NetworkInfo, MacHash> scanResults;
            /* Our own IP at scan start, host byte order; 0 if unknown.
               Guarded by discovery->dataMutex, like scanResults. */
            u32 selfIp = 0;
        public:
            LDUdpSocket(int fd, LANDiscovery *discovery);
            int getFd() override {
                return UdpLanSocketBase::getFd();
            }
            int onRead() override;
            void onClose() override;
    };

    class LDTcpSocket : public TcpLanSocketBase, public Pollable {
        protected:
            LANDiscovery *discovery;
        public:
            LDTcpSocket(int fd, LANDiscovery *discovery) : TcpLanSocketBase(fd), discovery(discovery) {};
            int getFd() override {
                return TcpLanSocketBase::getFd();
            }
            int onRead() override;
            void onClose() override;
    };

    /* LDN discovery over the internet relay: a UdpLanSocket whose transport is
       a RelayTransport, so LANPacket framing carries Scan/ScanResp unchanged.
       Shares the udp socket's scanResults. */
    class RelayLanSocket : public UdpLanSocketBase, public Pollable {
        protected:
            relay::RelayTransport transport;
            LANDiscovery *discovery;
            virtual u32 getBroadcast() override { return 0x0A0DFFFFu; } /* 10.13.255.255 */
            virtual ssize_t recvfrom(void *buf, size_t len, struct sockaddr_in *addr) override;
            virtual int sendto(const void *buf, size_t len, struct sockaddr_in *addr) override;
        public:
            RelayLanSocket(LANDiscovery *discovery) : UdpLanSocketBase(-1, 11452), discovery(discovery) {}
            Result open() { return this->transport.Open(); }
            int getFd() override { return this->transport.GetFd(); }
            int onRead() override;
            /* Close the transport so a HUP'd relay socket leaves the poll set;
               also marks the session for rebuild (defined in the .cpp). */
            void onClose() override;
            void keepalive() { this->transport.SendKeepalive(); }
            /* Broadcast a LANPacket over the relay (sendto ignores the addr,
               so it reaches every other console). */
            int send(LANPacketType type, const void *data, size_t size) {
                return this->sendPacket(type, data, size);
            }
    };

    class LANDiscovery {
        public:
            static const int DefaultPort = 11452;
            /* How often (ms) the relay worker re-announces itself to the relay
               server. Must stay well under the server's idle timeout (60s) so
               an idle host is never forgotten. */
            static constexpr s64 RelayBeaconIntervalMs = 5000;
            /* Silence for ~6 missed 5s beats = peer presumed gone (host reaps
               the slot; station reports SignalLost). TUNABLE: raise if jittery
               paths get torn down. */
            static constexpr s64 RelayPeerTimeoutMs = 30000;
            /* Min gap between relay advertisements: the 5s beacon already
               reaches everyone, so don't also answer every scanner's Scan. */
            static constexpr s64 RelayAdvertiseMinIntervalMs = 2000;
            static const char *FakeSsid;
            typedef std::function<int(LANPacketType, const void *, size_t)> ReplyFunc;
            typedef std::function<void()> LanEventFunc;
            static const LanEventFunc EmptyFunc;
            DisconnectReason disconnect_reason;
        protected:
            friend class LDUdpSocket;
            friend class LDTcpSocket;
            friend class LanStation;
            friend class RelayLanSocket;
            // 0: udp 1: tcp 2: client
            os::Mutex pollMutex;
            // Guards data shared between the worker thread and IPC threads:
            // networkInfo, udp->scanResults, nodeChanges, nodeLastStates.
            // Recursive: updateNodes() is reached both with and without it held.
            // Lock order: pollMutex may be held when taking dataMutex, never the reverse.
            os::Mutex dataMutex;
            std::unique_ptr<LDUdpSocket> udp;
            std::unique_ptr<LDTcpSocket> tcp;
            /* Phase 1b: present only in relay mode (relay::IsEnabled()). */
            std::unique_ptr<RelayLanSocket> relay;
            std::array<LanStation, StationCountMax> stations;
            std::array<NodeLatestUpdate, NodeCountMax> nodeChanges;
            std::array<u8, NodeCountMax> nodeLastStates;
            static void Worker(void* args);
            NifmRequest request;
            int originalMtu;
            bool stop;
            bool initialized;
            NetworkInfo networkInfo;
            /* Station side: target network for the join. Sync is accepted only
               while joinActive and bssid-matched (a shared relay carries other
               sessions' SyncNetwork, and a scanning station must not be flipped
               connected by a stray broadcast). Guarded by dataMutex. */
            MacAddress joinBssid{};
            bool joinActive = false;
            /* Station side, relay joins only: host-liveness timestamp, whether
               this join went over the relay (TCP joins detect loss via socket
               close), and our advertised IP (echoed in heartbeats). Guarded by
               dataMutex. */
            os::Tick hostLastSeen = os::Tick(0);
            bool relayJoined = false;
            u32 relayJoinedIp = 0;
            /* Host side: when we last advertised over the relay, for the rate
               limit. Guarded by dataMutex. */
            os::Tick lastRelayAdvertise = os::Tick(0);
            /* What initialize() latched, so openAccessPoint/openStation can
               detect a toggle change or sleep teardown and rebuild (see
               refreshNetworkSession). */
            bool initRelay = false;
            bool initListening = true;
            bool needsReinit = false;
            Result refreshNetworkSession();
            u16 listenPort;
            os::ThreadType workerThread;
            CommState state;
            void worker();
            int loopPoll();
            void onSyncNetwork(NetworkInfo *info);
            void onConnect(int new_fd);
            /* Relay mode: a station joined by sending Connect over the relay
               (no per-station TCP socket). */
            void onRelayConnect(const NodeInfo *info);
            void onDisconnectFromHost();
            void onNetworkInfoChanged();

            void updateNodes();
            /* Publish the current peer set to the bsd:u mitm's broadcast
               fan-out. Call with dataMutex held. */
            void publishSessionRegistry();
            void resetStations();
            Result getFakeMac(MacAddress *mac);
            Result getNodeInfo(NodeInfo *node, const UserConfig *userConfig, u16 localCommunicationVersion);
            LanEventFunc lanEvent;
            std::unique_ptr<u8[]> stack;
        public:
            Result initialize(LanEventFunc lanEvent = EmptyFunc, bool listening = true);
            Result finalize();
            Result initNetworkInfo();
            Result scan(NetworkInfo *networkInfo, u16 *count, ScanFilter filter);
            Result setAdvertiseData(const u8 *data, uint16_t size);
            Result createNetwork(const SecurityConfig *securityConfig, const UserConfig *userConfig, const NetworkConfig *networkConfig);
            Result createNetworkPrivate(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig);
            Result destroyNetwork();
            Result connect(const NetworkInfo *networkInfo, UserConfig *userConfig, u16 localCommunicationVersion);
            Result connectPrivate(const SecurityParameterData *securityParameter, const UserConfig *userConfig, u16 localCommunicationVersion, const NetworkConfig *networkConfig);
            Result disconnect();
            Result getNetworkInfo(NetworkInfo *pOutNetwork);
            Result getNetworkInfo(NetworkInfo *pOutNetwork, NodeLatestUpdate *pOutUpdates, int bufferCount);
            Result openAccessPoint();
            Result closeAccessPoint();
            Result openStation();
            Result closeStation();
        public:
            LANDiscovery(u16 port = DefaultPort) :
                disconnect_reason(DisconnectReason::None),
                pollMutex(false),
                dataMutex(true),
                stations({{{1, this}, {2, this}, {3, this}, {4, this}, {5, this}, {6, this}, {7, this}}}),
                stop(false), initialized(false),
                networkInfo({}), listenPort(port),
                state(CommState::None)
            {
                this->stack = std::make_unique<u8[]>(os::ThreadStackAlignment + StackSize);
                LogFormat("LANDiscovery");
            };
            ~LANDiscovery();
            u16 getListenPort() const {
                return this->listenPort;
            }
            CommState getState() const {
                return this->state;
            };
            void setState(CommState v) {
                this->state = v;
                this->lanEvent();
            };
            int stationCount();
        protected:
            Result createNetworkImpl(const SecurityConfig *securityConfig, const SecurityParameterData *securityParameter, const UserConfig *userConfig, const NetworkConfig *networkConfig);
            Result setSocketOpts(int fd, bool isTcp);
            Result initTcp(bool listening);
            Result initUdp(bool listening);
            void initNodeStateChange();
            bool isNodeStateChanged();
    };
}
