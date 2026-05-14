#include "JA4TlsParser.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

using diploma::JA4TlsParser;

namespace {

void putU8(std::vector<uint8_t>& out, uint8_t value) {
    out.push_back(value);
}

void putU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void putU24(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void appendVector(std::vector<uint8_t>& out, const std::vector<uint8_t>& bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void appendString(std::vector<uint8_t>& out, const std::string& value) {
    out.insert(out.end(), value.begin(), value.end());
}

void addExtension(std::vector<uint8_t>& extensions, uint16_t type, const std::vector<uint8_t>& data) {
    putU16(extensions, type);
    putU16(extensions, static_cast<uint16_t>(data.size()));
    appendVector(extensions, data);
}

std::vector<uint8_t> makeSniExtensionData(const std::string& hostname) {
    std::vector<uint8_t> data;

    const uint16_t serverNameEntryLen = static_cast<uint16_t>(1 + 2 + hostname.size());

    putU16(data, serverNameEntryLen);
    putU8(data, 0x00); // host_name
    putU16(data, static_cast<uint16_t>(hostname.size()));
    appendString(data, hostname);

    return data;
}

std::vector<uint8_t> makeAlpnExtensionData() {
    std::vector<uint8_t> protocolList;

    putU8(protocolList, 2);
    appendString(protocolList, "h2");

    putU8(protocolList, 8);
    appendString(protocolList, "http/1.1");

    std::vector<uint8_t> data;
    putU16(data, static_cast<uint16_t>(protocolList.size()));
    appendVector(data, protocolList);

    return data;
}

std::vector<uint8_t> makeClientHelloRecord() {
    std::vector<uint8_t> body;

    // ClientHello.legacy_version = TLS 1.2 legacy version.
    putU16(body, 0x0303);

    // random[32]
    for (int i = 0; i < 32; ++i) {
        putU8(body, 0x00);
    }

    // session_id length = 0
    putU8(body, 0x00);

    // cipher_suites: GREASE + TLS_AES_128_GCM_SHA256 + TLS_AES_256_GCM_SHA384
    std::vector<uint8_t> ciphers;
    putU16(ciphers, 0x0A0A); // GREASE
    putU16(ciphers, 0x1301);
    putU16(ciphers, 0x1302);

    putU16(body, static_cast<uint16_t>(ciphers.size()));
    appendVector(body, ciphers);

    // compression_methods: null
    putU8(body, 0x01);
    putU8(body, 0x00);

    std::vector<uint8_t> extensions;
    addExtension(extensions, 0x0A0A, {}); // GREASE
    addExtension(extensions, 0x0000, makeSniExtensionData("example.com"));
    addExtension(extensions, 0x0010, makeAlpnExtensionData());

    putU16(body, static_cast<uint16_t>(extensions.size()));
    appendVector(body, extensions);

    std::vector<uint8_t> handshake;
    putU8(handshake, 0x01); // ClientHello
    putU24(handshake, static_cast<uint32_t>(body.size()));
    appendVector(handshake, body);

    std::vector<uint8_t> record;
    putU8(record, 0x16);    // TLS Handshake record
    putU16(record, 0x0303); // TLS legacy record version
    putU16(record, static_cast<uint16_t>(handshake.size()));
    appendVector(record, handshake);

    return record;
}

} // namespace

TEST(JA4TlsParserTest, ParsesSyntheticClientHello) {
    JA4TlsParser parser;
    const auto record = makeClientHelloRecord();

    const auto parsed = parser.parseClientHello(record.data(), record.size());

    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(parsed->legacy_version, 0x0303);

    ASSERT_EQ(parsed->cipher_suites.size(), 2U);
    EXPECT_EQ(parsed->cipher_suites[0], 0x1301);
    EXPECT_EQ(parsed->cipher_suites[1], 0x1302);

    ASSERT_EQ(parsed->extensions.size(), 2U);
    EXPECT_EQ(parsed->extensions[0], 0x0000);
    EXPECT_EQ(parsed->extensions[1], 0x0010);

    EXPECT_TRUE(parsed->has_sni);

    ASSERT_EQ(parsed->alpn_protocols.size(), 2U);
    EXPECT_EQ(parsed->alpn_protocols[0], "h2");
    EXPECT_EQ(parsed->alpn_protocols[1], "http/1.1");
}

TEST(JA4TlsParserTest, FindsClientHelloInsideTcpStream) {
    JA4TlsParser parser;

    std::vector<uint8_t> stream = {0x00, 0x01, 0x02, 0x03};
    const auto record = makeClientHelloRecord();
    appendVector(stream, record);

    const auto parsed = parser.findClientHelloInStream(stream);

    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->has_sni);

    ASSERT_EQ(parsed->alpn_protocols.size(), 2U);
    EXPECT_EQ(parsed->alpn_protocols[0], "h2");
    EXPECT_EQ(parsed->alpn_protocols[1], "http/1.1");
}

TEST(JA4TlsParserTest, RejectsInvalidInput) {
    JA4TlsParser parser;

    const std::vector<uint8_t> empty;
    EXPECT_FALSE(parser.parseClientHello(empty.data(), empty.size()).has_value());

    const std::vector<uint8_t> notTls = {0x17, 0x03, 0x03, 0x00, 0x00};
    EXPECT_FALSE(parser.parseClientHello(notTls.data(), notTls.size()).has_value());

    const std::vector<uint8_t> truncated = {0x16, 0x03, 0x03, 0x00, 0x10, 0x01};
    EXPECT_FALSE(parser.parseClientHello(truncated.data(), truncated.size()).has_value());
}
