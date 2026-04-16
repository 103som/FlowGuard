#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <TcpLayer.h>

#include "FlowTypes.h"

namespace diploma {

    class JA4TlsParser {
    public:
        std::optional<TlsClientHelloFields> parseClientHello(const pcpp::TcpLayer& tcp) const;
        std::optional<TlsClientHelloFields> parseClientHello(const uint8_t* data, size_t size) const;

        std::optional<TlsClientHelloFields> findClientHelloInStream(const std::vector<uint8_t>& stream) const;
        std::optional<TlsClientHelloFields> findClientHelloInStream(const uint8_t* data, size_t size) const;

    private:
        static bool isGrease(uint16_t value);

        std::optional<std::vector<uint8_t>> extractClientHelloBodyFromTlsStream(
            const uint8_t* data,
            size_t size
        ) const;

        std::optional<TlsClientHelloFields> parseClientHelloBody(
            const uint8_t* data,
            size_t size
        ) const;
    };

} // namespace diploma