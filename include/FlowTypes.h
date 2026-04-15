#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace diploma {

struct TlsClientHelloFields {
    uint16_t legacy_version = 0;
    std::vector<uint16_t> cipher_suites;   // GREASE уже выкинут
    std::vector<uint16_t> extensions;      // GREASE уже выкинут
    bool has_sni = false;
    std::vector<std::string> alpn_protocols;
};

struct FlowKey {
    std::string ip_a;
    std::string ip_b;
    uint16_t port_a = 0;
    uint16_t port_b = 0;
    uint8_t proto = 0; // 6 = TCP, 17 = UDP

    bool operator==(const FlowKey& other) const = default;
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& key) const noexcept {
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

struct FlowStats {
    uint64_t first_ts_ns = 0;
    uint64_t last_ts_ns = 0;

    bool client_is_a = true;
    bool initialized = false;

    uint64_t packets_total = 0;
    uint64_t packets_c2s = 0;
    uint64_t packets_s2c = 0;

    uint64_t bytes_cap_total = 0;
    uint64_t bytes_cap_c2s = 0;
    uint64_t bytes_cap_s2c = 0;

    uint64_t bytes_wire_total = 0;
    uint64_t bytes_wire_c2s = 0;
    uint64_t bytes_wire_s2c = 0;

    uint64_t tcp_syn_total = 0;
    uint64_t tcp_syn_c2s = 0;
    uint64_t tcp_synack_s2c = 0;
    uint64_t tcp_ack_total = 0;
    uint64_t tcp_fin_total = 0;
    uint64_t tcp_rst_total = 0;
    uint64_t tcp_psh_total = 0;

    uint64_t tls_client_hello_c2s = 0;
    std::optional<TlsClientHelloFields> ja4_client_hello_fields;
};

struct ParseResult {
    uint64_t total_packets = 0;
    uint64_t parsed_packets = 0;
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows;
};

} // namespace diploma