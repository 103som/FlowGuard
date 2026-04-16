#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "FlowParser.h"
#include "JA4TlsParser.h"

namespace {

std::string toHex4(uint16_t value) {
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setfill('0') << std::setw(4) << value;
    return oss.str();
}

std::string joinHexVector(const std::vector<uint16_t>& values) {
    std::ostringstream oss;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            oss << ';';
        }
        oss << toHex4(values[i]);
    }
    return oss.str();
}

std::string joinStringVector(const std::vector<std::string>& values) {
    std::ostringstream oss;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            oss << ';';
        }
        oss << values[i];
    }
    return oss.str();
}

bool writeCsv(const std::string& output_path, const diploma::ParseResult& result) {
    std::ofstream out(output_path);
    if (!out) {
        return false;
    }

    out << "client_ip,server_ip,client_port,server_port,proto,"
           "packets_total,packets_c2s,packets_s2c,"
           "bytes_cap_total,bytes_cap_c2s,bytes_cap_s2c,"
           "bytes_wire_total,bytes_wire_c2s,bytes_wire_s2c,"
           "first_ts_ns,last_ts_ns,duration_ns,"
           "tcp_syn_total,tcp_syn_c2s,tcp_synack_s2c,"
           "tcp_ack_total,tcp_fin_total,tcp_rst_total,tcp_psh_total,"
           "tls_client_hello_c2s,"
           "ja4_legacy_version,ja4_cipher_suites_count,ja4_extensions_count,ja4_has_sni,"
           "ja4_alpn,ja4_cipher_suites,ja4_extensions,"
           "avg_wirelen_total\n";

    out << std::fixed << std::setprecision(3);

    for (const auto& [key, st] : result.flows) {
        const uint64_t duration_ns =
            (st.packets_total > 0 && st.last_ts_ns >= st.first_ts_ns)
                ? (st.last_ts_ns - st.first_ts_ns)
                : 0;

        const double avg_wirelen_total =
            st.packets_total > 0
                ? static_cast<double>(st.bytes_wire_total) / static_cast<double>(st.packets_total)
                : 0.0;

        const std::string client_ip = st.client_is_a ? key.ip_a : key.ip_b;
        const std::string server_ip = st.client_is_a ? key.ip_b : key.ip_a;
        const uint16_t client_port = st.client_is_a ? key.port_a : key.port_b;
        const uint16_t server_port = st.client_is_a ? key.port_b : key.port_a;

        std::string legacy_version = "-";
        std::string cipher_suites_count = "0";
        std::string extensions_count = "0";
        std::string has_sni = "0";
        std::string alpn = "-";
        std::string cipher_suites = "-";
        std::string extensions = "-";

        if (st.ja4_client_hello_fields.has_value()) {
            const auto& hello = *st.ja4_client_hello_fields;
            legacy_version = toHex4(hello.legacy_version);
            cipher_suites_count = std::to_string(hello.cipher_suites.size());
            extensions_count = std::to_string(hello.extensions.size());
            has_sni = hello.has_sni ? "1" : "0";
            alpn = hello.alpn_protocols.empty() ? "-" : joinStringVector(hello.alpn_protocols);
            cipher_suites = hello.cipher_suites.empty() ? "-" : joinHexVector(hello.cipher_suites);
            extensions = hello.extensions.empty() ? "-" : joinHexVector(hello.extensions);
        }

        out << client_ip << ','
            << server_ip << ','
            << client_port << ','
            << server_port << ','
            << static_cast<unsigned>(key.proto) << ','
            << st.packets_total << ','
            << st.packets_c2s << ','
            << st.packets_s2c << ','
            << st.bytes_cap_total << ','
            << st.bytes_cap_c2s << ','
            << st.bytes_cap_s2c << ','
            << st.bytes_wire_total << ','
            << st.bytes_wire_c2s << ','
            << st.bytes_wire_s2c << ','
            << st.first_ts_ns << ','
            << st.last_ts_ns << ','
            << duration_ns << ','
            << st.tcp_syn_total << ','
            << st.tcp_syn_c2s << ','
            << st.tcp_synack_s2c << ','
            << st.tcp_ack_total << ','
            << st.tcp_fin_total << ','
            << st.tcp_rst_total << ','
            << st.tcp_psh_total << ','
            << st.tls_client_hello_c2s << ','
            << legacy_version << ','
            << cipher_suites_count << ','
            << extensions_count << ','
            << has_sni << ','
            << alpn << ','
            << cipher_suites << ','
            << extensions << ','
            << avg_wirelen_total
            << '\n';
    }

    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <input.pcap|input.pcapng> [output.csv]\n";
        return 2;
    }

    const std::string input_path = argv[1];
    const std::string output_path = (argc == 3) ? argv[2] : "flows.csv";

    diploma::JA4TlsParser ja4_parser;
    diploma::FlowParser flow_parser(&ja4_parser);

    const diploma::ParseResult result = flow_parser.parseFile(input_path);

    if (result.total_packets == 0) {
        std::cerr << "Failed to open file or no packets were read: " << input_path << "\n";
        return 1;
    }

    if (!writeCsv(output_path, result)) {
        std::cerr << "Failed to write CSV: " << output_path << "\n";
        return 1;
    }

    std::cout << "Input file:      " << input_path << "\n";
    std::cout << "Output CSV:      " << output_path << "\n";
    std::cout << "Total packets:   " << result.total_packets << "\n";
    std::cout << "Parsed packets:  " << result.parsed_packets << "\n";
    std::cout << "Flows exported:  " << result.flows.size() << "\n";

    return 0;
}