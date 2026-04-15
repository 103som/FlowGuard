#include "FlowParser.h"

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

#include "JA4TlsParser.h"
#include <arpa/inet.h>

#include "TcpStreamReassembler.h"

namespace diploma {
namespace {

// CICIDS2017 labels were generated with CICFlowMeter-style biflows.
// Important semantics we try to mirror here:
// 1) The FIRST packet of a flow instance defines forward/backward direction.
// 2) TCP flows are split by timeout and are closed on the first FIN/RST packet
//    to mimic the original CICFlowMeter behavior used for the dataset.
// 3) UDP flows are split by timeout; first packet defines direction.
// 4) Each timeout/reopen creates a distinct flow_instance.
//
// See CIC documentation / repo notes on biflows and timeout handling, and the
// CICIDS2017 troubleshooting study describing first-FIN appendices.

constexpr uint64_t kCicids2017FlowTimeoutNs = 120ULL * 1'000'000'000ULL; // 120s

struct FlowBaseKey {
    std::string ip_a;
    std::string ip_b;
    uint16_t port_a = 0;
    uint16_t port_b = 0;
    uint8_t proto = 0;

    bool operator==(const FlowBaseKey& other) const = default;
};

struct FlowBaseKeyHash {
    size_t operator()(const FlowBaseKey& key) const noexcept {
        size_t h = 1469598103934665603ULL;

        auto mix = [&h](size_t v) {
            h ^= v;
            h *= 1099511628211ULL;
        };

        mix(std::hash<std::string>{}(key.ip_a));
        mix(std::hash<std::string>{}(key.ip_b));
        mix(std::hash<uint16_t>{}(key.port_a));
        mix(std::hash<uint16_t>{}(key.port_b));
        mix(std::hash<uint8_t>{}(key.proto));

        return h;
    }
};

struct FlowRuntimeState {
    uint64_t first_ts_ns = 0;
    TcpStreamReassembler client_stream;
    bool ja4_extracted = false;
};

struct DirectedKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t proto = 0;

    bool operator==(const DirectedKey& other) const = default;
};

struct DirectedKeyHash {
    size_t operator()(const DirectedKey& key) const noexcept {
        size_t h = 1469598103934665603ULL;

        auto mix = [&h](size_t v) {
            h ^= v;
            h *= 1099511628211ULL;
        };

        mix(std::hash<std::string>{}(key.src_ip));
        mix(std::hash<std::string>{}(key.dst_ip));
        mix(std::hash<uint16_t>{}(key.src_port));
        mix(std::hash<uint16_t>{}(key.dst_port));
        mix(std::hash<uint8_t>{}(key.proto));

        return h;
    }
};

struct MatchedFlow {
    FlowKey key;
    bool from_client = false;
};

uint64_t tsToNs(const timespec& ts) {
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

struct PacketMeta {
    uint64_t ts_ns = 0;
    uint32_t caplen = 0;
    uint32_t wirelen = 0;

    std::string orig_src_ip;
    std::string orig_dst_ip;
    uint16_t orig_src_port = 0;
    uint16_t orig_dst_port = 0;
    uint8_t proto = 0;

    bool is_tcp = false;
    bool is_udp = false;
    bool syn = false;
    bool ack = false;
    bool fin = false;
    bool rst = false;
    bool psh = false;
};

std::unique_ptr<pcpp::IFileReaderDevice> openReader(const std::string& path) {
    std::unique_ptr<pcpp::IFileReaderDevice> reader(
        pcpp::IFileReaderDevice::getReader(path)
    );

    if (!reader) {
        return nullptr;
    }

    if (!reader->open()) {
        return nullptr;
    }

    return reader;
}

static DirectedKey makeDirectedKey(
    const std::string& src_ip,
    const std::string& dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t proto
) {
    return DirectedKey{
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = proto,
    };
}

static FlowBaseKey toBaseKey(const FlowKey& key) {
    return FlowBaseKey{
        .ip_a = key.ip_a,
        .ip_b = key.ip_b,
        .port_a = key.port_a,
        .port_b = key.port_b,
        .proto = key.proto,
    };
}

static FlowKey makeFlowKey(const FlowBaseKey& base, uint64_t instance) {
    return FlowKey{
        .ip_a = base.ip_a,
        .ip_b = base.ip_b,
        .port_a = base.port_a,
        .port_b = base.port_b,
        .proto = base.proto,
        .flow_instance = instance,
    };
}

static bool packetIsFromAtoB(const PacketMeta& meta, const FlowKey& key) {
    return meta.orig_src_ip == key.ip_a &&
           meta.orig_src_port == key.port_a;
}

static FlowKey nextFlowInstance(
    const FlowBaseKey& base,
    std::unordered_map<FlowBaseKey, uint64_t, FlowBaseKeyHash>& next_instance_by_base
) {
    uint64_t& next_instance = next_instance_by_base[base];
    FlowKey key = makeFlowKey(base, next_instance);
    ++next_instance;
    return key;
}

static void registerFlowBidirectional(
    const FlowKey& flow_key,
    std::unordered_map<DirectedKey, FlowKey, DirectedKeyHash>& sessions
) {
    sessions[makeDirectedKey(
        flow_key.ip_a,
        flow_key.ip_b,
        flow_key.port_a,
        flow_key.port_b,
        flow_key.proto
    )] = flow_key;

    sessions[makeDirectedKey(
        flow_key.ip_b,
        flow_key.ip_a,
        flow_key.port_b,
        flow_key.port_a,
        flow_key.proto
    )] = flow_key;
}

static void unregisterFlowBidirectional(
    const FlowKey& flow_key,
    std::unordered_map<DirectedKey, FlowKey, DirectedKeyHash>& sessions
) {
    sessions.erase(makeDirectedKey(
        flow_key.ip_a,
        flow_key.ip_b,
        flow_key.port_a,
        flow_key.port_b,
        flow_key.proto
    ));

    sessions.erase(makeDirectedKey(
        flow_key.ip_b,
        flow_key.ip_a,
        flow_key.port_b,
        flow_key.port_a,
        flow_key.proto
    ));
}

static bool isFlowTimedOut(
    const FlowKey& flow_key,
    uint64_t packet_ts_ns,
    const std::unordered_map<FlowKey, FlowRuntimeState, FlowKeyHash>& runtime_state
) {
    auto it = runtime_state.find(flow_key);
    if (it == runtime_state.end()) {
        return false;
    }

    return packet_ts_ns > it->second.first_ts_ns &&
           (packet_ts_ns - it->second.first_ts_ns) > kCicids2017FlowTimeoutNs;
}

static FlowKey recreateTimedOutFlow(
    const FlowKey& old_flow_key,
    std::unordered_map<FlowBaseKey, uint64_t, FlowBaseKeyHash>& next_instance_by_base
) {
    return nextFlowInstance(toBaseKey(old_flow_key), next_instance_by_base);
}

static std::optional<MatchedFlow> matchTcpFlow(
    const PacketMeta& meta,
    std::unordered_map<DirectedKey, FlowKey, DirectedKeyHash>& tcp_sessions,
    std::unordered_map<FlowBaseKey, uint64_t, FlowBaseKeyHash>& next_instance_by_base
) {
    if (!meta.is_tcp) {
        return std::nullopt;
    }

    // SYN without ACK starts a fresh TCP biflow; first packet defines direction.
    if (meta.syn && !meta.ack) {
        FlowBaseKey base{
            .ip_a = meta.orig_src_ip,
            .ip_b = meta.orig_dst_ip,
            .port_a = meta.orig_src_port,
            .port_b = meta.orig_dst_port,
            .proto = meta.proto,
        };

        FlowKey flow_key = nextFlowInstance(base, next_instance_by_base);
        registerFlowBidirectional(flow_key, tcp_sessions);

        return MatchedFlow{
            .key = std::move(flow_key),
            .from_client = true,
        };
    }

    if (auto it = tcp_sessions.find(makeDirectedKey(
            meta.orig_src_ip,
            meta.orig_dst_ip,
            meta.orig_src_port,
            meta.orig_dst_port,
            meta.proto
        ));
        it != tcp_sessions.end()) {
        return MatchedFlow{
            .key = it->second,
            .from_client = packetIsFromAtoB(meta, it->second),
        };
    }

    // Midstream fallback: do NOT infer client/server from port numbers.
    // Start a new flow instance and let the first observed packet define direction,
    // just like CICFlowMeter biflow semantics.
    FlowBaseKey base{
        .ip_a = meta.orig_src_ip,
        .ip_b = meta.orig_dst_ip,
        .port_a = meta.orig_src_port,
        .port_b = meta.orig_dst_port,
        .proto = meta.proto,
    };

    FlowKey flow_key = nextFlowInstance(base, next_instance_by_base);
    registerFlowBidirectional(flow_key, tcp_sessions);

    return MatchedFlow{
        .key = std::move(flow_key),
        .from_client = true,
    };
}

static std::optional<MatchedFlow> matchUdpFlow(
    const PacketMeta& meta,
    std::unordered_map<DirectedKey, FlowKey, DirectedKeyHash>& udp_sessions,
    std::unordered_map<FlowBaseKey, uint64_t, FlowBaseKeyHash>& next_instance_by_base
) {
    if (!meta.is_udp) {
        return std::nullopt;
    }

    if (auto it = udp_sessions.find(makeDirectedKey(
            meta.orig_src_ip,
            meta.orig_dst_ip,
            meta.orig_src_port,
            meta.orig_dst_port,
            meta.proto
        ));
        it != udp_sessions.end()) {
        return MatchedFlow{
            .key = it->second,
            .from_client = packetIsFromAtoB(meta, it->second),
        };
    }

    FlowBaseKey base{
        .ip_a = meta.orig_src_ip,
        .ip_b = meta.orig_dst_ip,
        .port_a = meta.orig_src_port,
        .port_b = meta.orig_dst_port,
        .proto = meta.proto,
    };

    FlowKey flow_key = nextFlowInstance(base, next_instance_by_base);
    registerFlowBidirectional(flow_key, udp_sessions);

    return MatchedFlow{
        .key = std::move(flow_key),
        .from_client = true,
    };
}

static uint32_t tcpSequenceToHostOrder(const pcpp::tcphdr* hdr) {
    return ntohl(hdr->sequenceNumber);
}

std::optional<PacketMeta> parsePacketMeta(const pcpp::Packet& packet, const pcpp::RawPacket& raw_packet) {
    PacketMeta meta;
    meta.ts_ns = tsToNs(raw_packet.getPacketTimeStamp());
    meta.caplen = static_cast<uint32_t>(raw_packet.getRawDataLen());

    const int frame_len = raw_packet.getFrameLength();
    meta.wirelen = frame_len > 0 ? static_cast<uint32_t>(frame_len) : meta.caplen;

    if (auto* ip4 = packet.getLayerOfType<pcpp::IPv4Layer>()) {
        meta.orig_src_ip = ip4->getSrcIPv4Address().toString();
        meta.orig_dst_ip = ip4->getDstIPv4Address().toString();
        meta.proto = ip4->getIPv4Header()->protocol;
    } else if (auto* ip6 = packet.getLayerOfType<pcpp::IPv6Layer>()) {
        meta.orig_src_ip = ip6->getSrcIPv6Address().toString();
        meta.orig_dst_ip = ip6->getDstIPv6Address().toString();
        meta.proto = ip6->getIPv6Header()->nextHeader;
    } else {
        return std::nullopt;
    }

    if (meta.proto == 6) {
        auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
        if (tcp == nullptr) {
            return std::nullopt;
        }

        meta.orig_src_port = tcp->getSrcPort();
        meta.orig_dst_port = tcp->getDstPort();
        meta.is_tcp = true;

        const auto* hdr = tcp->getTcpHeader();
        meta.syn = hdr->synFlag != 0;
        meta.ack = hdr->ackFlag != 0;
        meta.fin = hdr->finFlag != 0;
        meta.rst = hdr->rstFlag != 0;
        meta.psh = hdr->pshFlag != 0;
    } else if (meta.proto == 17) {
        auto* udp = packet.getLayerOfType<pcpp::UdpLayer>();
        if (udp == nullptr) {
            return std::nullopt;
        }

        meta.orig_src_port = udp->getSrcPort();
        meta.orig_dst_port = udp->getDstPort();
        meta.is_udp = true;
    } else {
        return std::nullopt;
    }

    return meta;
}

} // namespace

FlowParser::FlowParser(const JA4TlsParser* ja4_parser)
    : ja4_parser_(ja4_parser) {
}

ParseResult FlowParser::parseFile(const std::string& path) const {
    ParseResult result;

    std::unordered_map<FlowKey, FlowRuntimeState, FlowKeyHash> runtime_state;
    std::unordered_map<FlowBaseKey, uint64_t, FlowBaseKeyHash> next_instance_by_base;
    std::unordered_map<DirectedKey, FlowKey, DirectedKeyHash> tcp_sessions;
    std::unordered_map<DirectedKey, FlowKey, DirectedKeyHash> udp_sessions;

    auto closeTcpFlow = [&](const FlowKey& flow_key) {
        unregisterFlowBidirectional(flow_key, tcp_sessions);
        runtime_state.erase(flow_key);
    };

    auto closeUdpFlow = [&](const FlowKey& flow_key) {
        unregisterFlowBidirectional(flow_key, udp_sessions);
        runtime_state.erase(flow_key);
    };

    auto reader = openReader(path);
    if (!reader) {
        return result;
    }

    pcpp::RawPacket raw_packet;
    while (reader->getNextPacket(raw_packet)) {
        ++result.total_packets;

        pcpp::Packet packet(&raw_packet);
        auto meta = parsePacketMeta(packet, raw_packet);
        if (!meta.has_value()) {
            continue;
        }

        ++result.parsed_packets;

        FlowKey flow_key;
        bool from_client = false;

        if (meta->is_tcp) {
            auto matched = matchTcpFlow(*meta, tcp_sessions, next_instance_by_base);
            if (!matched.has_value()) {
                continue;
            }

            flow_key = matched->key;
            from_client = matched->from_client;

            if (isFlowTimedOut(flow_key, meta->ts_ns, runtime_state)) {
                closeTcpFlow(flow_key);
                flow_key = recreateTimedOutFlow(flow_key, next_instance_by_base);
                registerFlowBidirectional(flow_key, tcp_sessions);
                from_client = packetIsFromAtoB(*meta, flow_key);
            }
        } else {
            auto matched = matchUdpFlow(*meta, udp_sessions, next_instance_by_base);
            if (!matched.has_value()) {
                continue;
            }

            flow_key = matched->key;
            from_client = matched->from_client;

            if (isFlowTimedOut(flow_key, meta->ts_ns, runtime_state)) {
                closeUdpFlow(flow_key);
                flow_key = recreateTimedOutFlow(flow_key, next_instance_by_base);
                registerFlowBidirectional(flow_key, udp_sessions);
                from_client = packetIsFromAtoB(*meta, flow_key);
            }
        }

        auto& st = result.flows[flow_key];
        auto& rt = runtime_state[flow_key];

        if (!st.initialized) {
            st.initialized = true;
            st.first_ts_ns = meta->ts_ns;
            st.client_is_a = true;

            rt.first_ts_ns = meta->ts_ns;
            rt.ja4_extracted = false;
            rt.client_stream.clear();
        }

        st.last_ts_ns = meta->ts_ns;
        st.packets_total += 1;
        st.bytes_cap_total += meta->caplen;
        st.bytes_wire_total += meta->wirelen;

        if (from_client) {
            st.packets_c2s += 1;
            st.bytes_cap_c2s += meta->caplen;
            st.bytes_wire_c2s += meta->wirelen;
        } else {
            st.packets_s2c += 1;
            st.bytes_cap_s2c += meta->caplen;
            st.bytes_wire_s2c += meta->wirelen;
        }

        if (meta->is_tcp) {
            st.tcp_syn_total += meta->syn ? 1 : 0;
            st.tcp_ack_total += meta->ack ? 1 : 0;
            st.tcp_fin_total += meta->fin ? 1 : 0;
            st.tcp_rst_total += meta->rst ? 1 : 0;
            st.tcp_psh_total += meta->psh ? 1 : 0;

            if (from_client && meta->syn && !meta->ack) {
                st.tcp_syn_c2s += 1;
            }

            if (!from_client && meta->syn && meta->ack) {
                st.tcp_synack_s2c += 1;
            }

            if (from_client && ja4_parser_ != nullptr && !rt.ja4_extracted) {
                auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
                if (tcp != nullptr) {
                    const uint8_t* payload = tcp->getLayerPayload();
                    const size_t payload_size = tcp->getLayerPayloadSize();

                    if (payload != nullptr && payload_size > 0) {
                        const uint32_t seq = tcpSequenceToHostOrder(tcp->getTcpHeader());

                        rt.client_stream.feed(seq, payload, payload_size);

                        auto hello = ja4_parser_->findClientHelloInStream(rt.client_stream.stream());
                        if (hello.has_value()) {
                            rt.ja4_extracted = true;
                            st.tls_client_hello_c2s = 1;

                            if (!st.ja4_client_hello_fields.has_value()) {
                                st.ja4_client_hello_fields = std::move(*hello);
                            }
                        }
                    }
                }
            }

            // To mimic the original CICFlowMeter behavior used in CICIDS2017,
            // terminate the TCP flow on the first FIN or RST packet.
            if (meta->rst || meta->fin) {
                closeTcpFlow(flow_key);
            }
        }
    }

    reader->close();
    return result;
}

} // namespace diploma