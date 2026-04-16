#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace diploma {

    class TcpStreamReassembler {
    public:
        void feed(uint32_t seq, const uint8_t* data, size_t len);

        const std::vector<uint8_t>& stream() const {
            return stream_;
        }

        bool empty() const {
            return stream_.empty();
        }

        void clear();

    private:
        void appendContiguous(const uint8_t* data, size_t len);
        void drainPending();

    private:
        bool initialized_ = false;
        uint32_t next_seq_ = 0;

        std::vector<uint8_t> stream_;
        std::map<uint32_t, std::vector<uint8_t>> pending_;
    };

} // namespace diploma