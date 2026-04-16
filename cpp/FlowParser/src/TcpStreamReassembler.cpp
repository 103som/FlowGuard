#include "TcpStreamReassembler.h"

namespace diploma {

    void TcpStreamReassembler::clear() {
        initialized_ = false;
        next_seq_ = 0;
        stream_.clear();
        pending_.clear();
    }

    void TcpStreamReassembler::appendContiguous(const uint8_t* data, size_t len) {
        if (data == nullptr || len == 0) {
            return;
        }

        stream_.insert(stream_.end(), data, data + len);
        next_seq_ += static_cast<uint32_t>(len);
    }

    void TcpStreamReassembler::drainPending() {
        while (!pending_.empty()) {
            auto it = pending_.begin();

            if (it->first > next_seq_) {
                break;
            }

            const uint32_t seg_seq = it->first;
            const auto& seg = it->second;

            const uint32_t overlap = next_seq_ - seg_seq;
            if (overlap >= seg.size()) {
                pending_.erase(it);
                continue;
            }

            appendContiguous(seg.data() + overlap, seg.size() - overlap);
            pending_.erase(it);
        }
    }

    void TcpStreamReassembler::feed(uint32_t seq, const uint8_t* data, size_t len) {
        if (data == nullptr || len == 0) {
            return;
        }

        if (!initialized_) {
            initialized_ = true;
            next_seq_ = seq;
            appendContiguous(data, len);
            drainPending();
            return;
        }

        if (seq == next_seq_) {
            appendContiguous(data, len);
            drainPending();
            return;
        }

        if (seq > next_seq_) {
            auto [it, inserted] = pending_.emplace(seq, std::vector<uint8_t>(data, data + len));
            if (!inserted && it->second.size() < len) {
                it->second.assign(data, data + len);
            }
            return;
        }

        // seq < next_seq_ : partial overlap / retransmit / duplicate
        const uint32_t overlap = next_seq_ - seq;
        if (overlap >= len) {
            return;
        }

        appendContiguous(data + overlap, len - overlap);
        drainPending();
    }

} // namespace diploma