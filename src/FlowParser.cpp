#include "FlowParser.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
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

struct FlowRuntimeState {
    TcpStreamReassembler client_stream;
    bool ja4_extracted = false;
};

struct TcpStrictKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t proto = 6;

    bool operator==(const TcpStrictKey& other) const = default;
};

struct TcpStrictKeyHash {
    size_t operator()(const TcpStrictKey& key) const noexcept {
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

struct TcpLooseKey {
    std::string server_ip;
    uint16_t server_port = 0;
    uint16_t client_port = 0;
    uint8_t proto = 6;

    bool operator==(const TcpLooseKey& other) const = default;
};

struct TcpLooseKeyHash {
    size_t operator()(const TcpLooseKey& key) const noexcept {
        size_t h = 1469598103934665603ULL;

        auto mix = [&h](size_t v) {
            h ^= v;
            h *= 1099511628211ULL;
        };

        mix(std::hash<std::string>{}(key.server_ip));
        mix(std::hash<uint16_t>{}(key.server_port));
        mix(std::hash<uint16_t>{}(key.client_port));
        mix(std::hash<uint8_t>{}(key.proto));

        return h;
    }
};

struct MatchedTcpFlow {
    FlowKey key;
    bool from_client = false;
};

uint64_t tsToNs(const timespec& ts) {
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

void normalizeBidirectional(FlowKey& key) {
    const auto lhs = std::tie(key.ip_a, key.port_a);
    const auto rhs = std::tie(key.ip_b, key.port_b);

    if (rhs < lhs) {
        std::swap(key.ip_a, key.ip_b);
        std::swap(key.port_a, key.port_b);
    }
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

    FlowKey key;

    bool is_tcp = false;
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

bool packetSrcIsEndpointA(const PacketMeta& meta) {
    return meta.orig_src_ip == meta.key.ip_a &&
           meta.orig_src_port == meta.key.port_a;
}

static TcpStrictKey makeStrictKey(
    const std::string& src_ip,
    const std::string& dst_ip,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t proto
) {
    return TcpStrictKey{
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = proto,
    };
}

static TcpLooseKey makeLooseKey(
    const std::string& server_ip,
    uint16_t server_port,
    uint16_t client_port,
    uint8_t proto
) {
    return TcpLooseKey{
        .server_ip = server_ip,
        .server_port = server_port,
        .client_port = client_port,
        .proto = proto,
    };
}

static FlowKey makeCanonicalTcpFlowKey(
    const std::string& client_ip,
    const std::string& server_ip,
    uint16_t client_port,
    uint16_t server_port,
    uint8_t proto
) {
    return FlowKey{
        .ip_a = client_ip,
        .ip_b = server_ip,
        .port_a = client_port,
        .port_b = server_port,
        .proto = proto,
    };
}

static void registerTcpFlow(
    const FlowKey& flow_key,
    std::unordered_map<TcpStrictKey, FlowKey, TcpStrictKeyHash>& strict_tcp_sessions,
    std::unordered_map<TcpLooseKey, FlowKey, TcpLooseKeyHash>& loose_tcp_sessions
) {
    // strict: обе стороны полного 4-tuple
    strict_tcp_sessions[makeStrictKey(
        flow_key.ip_a,
        flow_key.ip_b,
        flow_key.port_a,
        flow_key.port_b,
        flow_key.proto
    )] = flow_key;

    strict_tcp_sessions[makeStrictKey(
        flow_key.ip_b,
        flow_key.ip_a,
        flow_key.port_b,
        flow_key.port_a,
        flow_key.proto
    )] = flow_key;

    // loose: server_ip + server_port + client_port
    loose_tcp_sessions[makeLooseKey(
        flow_key.ip_b,
        flow_key.port_b,
        flow_key.port_a,
        flow_key.proto
    )] = flow_key;
}

static std::optional<MatchedTcpFlow> matchTcpFlow(
    const PacketMeta& meta,
    std::unordered_map<TcpStrictKey, FlowKey, TcpStrictKeyHash>& strict_tcp_sessions,
    std::unordered_map<TcpLooseKey, FlowKey, TcpLooseKeyHash>& loose_tcp_sessions
) {
    if (!meta.is_tcp) {
        return std::nullopt;
    }

    // Новый TCP-сеанс: SYN без ACK — источник истины
    if (meta.syn && !meta.ack) {
        FlowKey flow_key = makeCanonicalTcpFlowKey(
            meta.orig_src_ip,
            meta.orig_dst_ip,
            meta.orig_src_port,
            meta.orig_dst_port,
            meta.proto
        );

        registerTcpFlow(flow_key, strict_tcp_sessions, loose_tcp_sessions);

        return MatchedTcpFlow{
            .key = std::move(flow_key),
            .from_client = true,
        };
    }

    // 1) Пробуем strict matching по полному текущему направленному 4-tuple
    if (auto it = strict_tcp_sessions.find(makeStrictKey(
            meta.orig_src_ip,
            meta.orig_dst_ip,
            meta.orig_src_port,
            meta.orig_dst_port,
            meta.proto
        ));
        it != strict_tcp_sessions.end()) {
        const bool from_client =
            meta.orig_src_ip == it->second.ip_a &&
            meta.orig_src_port == it->second.port_a;

        return MatchedTcpFlow{
            .key = it->second,
            .from_client = from_client,
        };
    }

    // 2) Fallback: packet выглядит как client -> server
    if (auto it = loose_tcp_sessions.find(makeLooseKey(
            meta.orig_dst_ip,
            meta.orig_dst_port,
            meta.orig_src_port,
            meta.proto
        ));
        it != loose_tcp_sessions.end()) {
        return MatchedTcpFlow{
            .key = it->second,
            .from_client = true,
        };
    }

    // 3) Fallback: packet выглядит как server -> client
    if (auto it = loose_tcp_sessions.find(makeLooseKey(
            meta.orig_src_ip,
            meta.orig_src_port,
            meta.orig_dst_port,
            meta.proto
        ));
        it != loose_tcp_sessions.end()) {
        return MatchedTcpFlow{
            .key = it->second,
            .from_client = false,
        };
    }

    // 4) Midstream fallback без SYN:
    // меньший порт считаем серверным
    if (meta.orig_dst_port < meta.orig_src_port) {
        FlowKey flow_key = makeCanonicalTcpFlowKey(
            meta.orig_src_ip,
            meta.orig_dst_ip,
            meta.orig_src_port,
            meta.orig_dst_port,
            meta.proto
        );

        registerTcpFlow(flow_key, strict_tcp_sessions, loose_tcp_sessions);

        return MatchedTcpFlow{
            .key = std::move(flow_key),
            .from_client = true,
        };
    }

    if (meta.orig_src_port < meta.orig_dst_port) {
        FlowKey flow_key = makeCanonicalTcpFlowKey(
            meta.orig_dst_ip,
            meta.orig_src_ip,
            meta.orig_dst_port,
            meta.orig_src_port,
            meta.proto
        );

        registerTcpFlow(flow_key, strict_tcp_sessions, loose_tcp_sessions);

        return MatchedTcpFlow{
            .key = std::move(flow_key),
            .from_client = false,
        };
    }

    return std::nullopt;
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

    meta.key.ip_a = meta.orig_src_ip;
    meta.key.ip_b = meta.orig_dst_ip;
    meta.key.proto = meta.proto;

    if (meta.proto == 6) {
        auto* tcp = packet.getLayerOfType<pcpp::TcpLayer>();
        if (tcp == nullptr) {
            return std::nullopt;
        }

        meta.orig_src_port = tcp->getSrcPort();
        meta.orig_dst_port = tcp->getDstPort();

        meta.key.port_a = meta.orig_src_port;
        meta.key.port_b = meta.orig_dst_port;

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

        meta.key.port_a = meta.orig_src_port;
        meta.key.port_b = meta.orig_dst_port;

        normalizeBidirectional(meta.key);
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
    std::unordered_map<TcpStrictKey, FlowKey, TcpStrictKeyHash> strict_tcp_sessions;
    std::unordered_map<TcpLooseKey, FlowKey, TcpLooseKeyHash> loose_tcp_sessions;

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
            auto matched = matchTcpFlow(*meta, strict_tcp_sessions, loose_tcp_sessions);
            if (!matched.has_value()) {
                continue;
            }

            flow_key = matched->key;
            from_client = matched->from_client;
        } else {
            flow_key = meta->key;
            from_client = packetSrcIsEndpointA(*meta);
        }

        auto& st = result.flows[flow_key];

        if (!st.initialized) {
            st.initialized = true;
            st.first_ts_ns = meta->ts_ns;

            // Для TCP canonical key всегда: a = client, b = server
            st.client_is_a = meta->is_tcp ? true : packetSrcIsEndpointA(*meta);
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

            auto& rt = runtime_state[flow_key];

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
        }
    }

    reader->close();
    return result;
}

} // namespace diploma