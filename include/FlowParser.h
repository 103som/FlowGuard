#pragma once

#include <string>

#include "FlowTypes.h"

namespace diploma {

    class JA4TlsParser;

    class FlowParser {
    public:
        explicit FlowParser(const JA4TlsParser* ja4_parser = nullptr);

        ParseResult parseFile(const std::string& path) const;

    private:
        const JA4TlsParser* ja4_parser_;
    };

} // namespace diploma