#include "JA4TlsParser.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace diploma {
namespace {

class BytesReader {
public:
    BytesReader(const uint8_t* data, size_t size)
        : data_(data), size_(size) {}

    bool readUint8(uint8_t& out) {
        if (remaining() < 1) {
            return false;
        }
        out = data_[pos_++];
        return true;
    }

    bool readUint16(uint16_t& out) {
        if (remaining() < 2) {
            return false;
        }
        out = static_cast<uint16_t>(
            (static_cast<uint16_t>(data_[pos_]) << 8) |
            static_cast<uint16_t>(data_[pos_ + 1])
        );
        pos_ += 2;
        return true;
    }

    bool readUint24(uint32_t& out) {
        if (remaining() < 3) {
            return false;
        }
        out = (static_cast<uint32_t>(data_[pos_]) << 16) |
              (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
              static_cast<uint32_t>(data_[pos_ + 2]);
        pos_ += 3;
        return true;
    }

    bool skip(size_t n) {
        if (remaining() < n) {
            return false;
        }
        pos_ += n;
        return true;
    }

    const uint8_t* current() const {
        return data_ + pos_;
    }

    size_t remaining() const {
        return size_ - pos_;
    }

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
};

void parseSniExtension(const uint8_t* data, size_t size, TlsClientHelloFields& out) {
    BytesReader rd(data, size);

    uint16_t list_len = 0;
    if (!rd.readUint16(list_len) || rd.remaining() < list_len) {
        return;
    }

    BytesReader list_reader(rd.current(), list_len);

    while (list_reader.remaining() > 0) {
        uint8_t name_type = 0;
        uint16_t name_len = 0;

        if (!list_reader.readUint8(name_type) ||
            !list_reader.readUint16(name_len) ||
            list_reader.remaining() < name_len) {
            return;
        }

        if (name_type == 0 && name_len > 0) {
            out.has_sni = true;
        }

        if (!list_reader.skip(name_len)) {
            return;
        }
    }
}

void parseAlpnExtension(const uint8_t* data, size_t size, TlsClientHelloFields& out) {
    BytesReader rd(data, size);

    uint16_t list_len = 0;
    if (!rd.readUint16(list_len) || rd.remaining() < list_len) {
        return;
    }

    BytesReader list_reader(rd.current(), list_len);

    while (list_reader.remaining() > 0) {
        uint8_t proto_len = 0;
        if (!list_reader.readUint8(proto_len) || list_reader.remaining() < proto_len) {
            return;
        }

        out.alpn_protocols.emplace_back(
            reinterpret_cast<const char*>(list_reader.current()),
            proto_len
        );

        if (!list_reader.skip(proto_len)) {
            return;
        }
    }
}

} // namespace

bool JA4TlsParser::isGrease(uint16_t value) {
    const uint8_t hi = static_cast<uint8_t>(value >> 8);
    const uint8_t lo = static_cast<uint8_t>(value & 0xFF);
    return hi == lo && (lo & 0x0F) == 0x0A;
}

std::optional<TlsClientHelloFields> JA4TlsParser::parseClientHello(const pcpp::TcpLayer& tcp) const {
    return parseClientHello(
        tcp.getLayerPayload(),
        tcp.getLayerPayloadSize()
    );
}

std::optional<TlsClientHelloFields> JA4TlsParser::parseClientHello(const uint8_t* data, size_t size) const {
    auto body = extractClientHelloBodyFromTlsStream(data, size);
    if (!body.has_value()) {
        return std::nullopt;
    }

    return parseClientHelloBody(body->data(), body->size());
}

std::optional<TlsClientHelloFields> JA4TlsParser::findClientHelloInStream(
    const std::vector<uint8_t>& stream
) const {
    return findClientHelloInStream(stream.data(), stream.size());
}

std::optional<TlsClientHelloFields> JA4TlsParser::findClientHelloInStream(
    const uint8_t* data,
    size_t size
) const {
    if (data == nullptr || size < 9) {
        return std::nullopt;
    }

    for (size_t offset = 0; offset + 9 <= size; ++offset) {
        if (data[offset] != 0x16) { // TLS Handshake record
            continue;
        }

        if (data[offset + 1] != 0x03) { // legacy major version
            continue;
        }

        auto body = extractClientHelloBodyFromTlsStream(data + offset, size - offset);
        if (!body.has_value()) {
            continue;
        }

        auto parsed = parseClientHelloBody(body->data(), body->size());
        if (parsed.has_value()) {
            return parsed;
        }
    }

    return std::nullopt;
}

std::optional<std::vector<uint8_t>> JA4TlsParser::extractClientHelloBodyFromTlsStream(
    const uint8_t* data,
    size_t size
) const {
    if (data == nullptr || size < 9) {
        return std::nullopt;
    }

    size_t pos = 0;
    std::vector<uint8_t> handshake_bytes;

    bool handshake_header_parsed = false;
    uint32_t handshake_len = 0;

    while (pos + 5 <= size) {
        const uint8_t content_type = data[pos];
        const uint8_t record_ver_major = data[pos + 1];
        const uint8_t record_ver_minor = data[pos + 2];
        (void)record_ver_minor;

        const uint16_t record_len =
            static_cast<uint16_t>(
                (static_cast<uint16_t>(data[pos + 3]) << 8) |
                static_cast<uint16_t>(data[pos + 4])
            );

        const size_t record_total_len = 5 + static_cast<size_t>(record_len);
        if (pos + record_total_len > size) {
            return std::nullopt;
        }

        if (content_type != 0x16) { // not a Handshake record
            return std::nullopt;
        }

        if (record_ver_major != 0x03) {
            return std::nullopt;
        }

        const uint8_t* record_payload = data + pos + 5;
        handshake_bytes.insert(
            handshake_bytes.end(),
            record_payload,
            record_payload + record_len
        );

        if (!handshake_header_parsed && handshake_bytes.size() >= 4) {
            const uint8_t handshake_type = handshake_bytes[0];
            if (handshake_type != 0x01) { // ClientHello
                return std::nullopt;
            }

            handshake_len =
                (static_cast<uint32_t>(handshake_bytes[1]) << 16) |
                (static_cast<uint32_t>(handshake_bytes[2]) << 8) |
                static_cast<uint32_t>(handshake_bytes[3]);

            handshake_header_parsed = true;
        }

        if (handshake_header_parsed &&
            handshake_bytes.size() >= 4 + static_cast<size_t>(handshake_len)) {
            return std::vector<uint8_t>(
                handshake_bytes.begin() + 4,
                handshake_bytes.begin() + 4 + static_cast<size_t>(handshake_len)
            );
        }

        pos += record_total_len;
    }

    return std::nullopt;
}

std::optional<TlsClientHelloFields> JA4TlsParser::parseClientHelloBody(
    const uint8_t* data,
    size_t size
) const {
    if (data == nullptr || size < 34) {
        return std::nullopt;
    }

    BytesReader body(data, size);
    TlsClientHelloFields result;

    if (!body.readUint16(result.legacy_version)) {
        return std::nullopt;
    }

    if (!body.skip(32)) { // Random
        return std::nullopt;
    }

    uint8_t session_id_len = 0;
    if (!body.readUint8(session_id_len) || !body.skip(session_id_len)) {
        return std::nullopt;
    }

    uint16_t cipher_suites_len = 0;
    if (!body.readUint16(cipher_suites_len) ||
        (cipher_suites_len % 2 != 0) ||
        body.remaining() < cipher_suites_len) {
        return std::nullopt;
    }

    for (size_t i = 0; i < cipher_suites_len / 2; ++i) {
        uint16_t cipher = 0;
        if (!body.readUint16(cipher)) {
            return std::nullopt;
        }

        if (!isGrease(cipher)) {
            result.cipher_suites.push_back(cipher);
        }
    }

    uint8_t compression_methods_len = 0;
    if (!body.readUint8(compression_methods_len) || !body.skip(compression_methods_len)) {
        return std::nullopt;
    }

    if (body.remaining() == 0) {
        return result;
    }

    uint16_t extensions_len = 0;
    if (!body.readUint16(extensions_len) || body.remaining() < extensions_len) {
        return std::nullopt;
    }

    BytesReader extensions_reader(body.current(), extensions_len);

    while (extensions_reader.remaining() > 0) {
        uint16_t ext_type = 0;
        uint16_t ext_len = 0;

        if (!extensions_reader.readUint16(ext_type) ||
            !extensions_reader.readUint16(ext_len) ||
            extensions_reader.remaining() < ext_len) {
            return std::nullopt;
        }

        if (!isGrease(ext_type)) {
            result.extensions.push_back(ext_type);
        }

        const uint8_t* ext_data = extensions_reader.current();

        if (ext_type == 0x0000) {
            parseSniExtension(ext_data, ext_len, result);
        } else if (ext_type == 0x0010) {
            parseAlpnExtension(ext_data, ext_len, result);
        }

        if (!extensions_reader.skip(ext_len)) {
            return std::nullopt;
        }
    }

    return result;
}

} // namespace diploma