#include "TcpStreamReassembler.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

using diploma::TcpStreamReassembler;

namespace {

void feedString(TcpStreamReassembler& reassembler, uint32_t seq, const std::string& payload) {
    reassembler.feed(
        seq,
        reinterpret_cast<const uint8_t*>(payload.data()),
        payload.size()
    );
}

std::string streamAsString(const TcpStreamReassembler& reassembler) {
    const auto& stream = reassembler.stream();
    return std::string(stream.begin(), stream.end());
}

} // namespace

TEST(TcpStreamReassemblerTest, AppendsSegmentsInOrder) {
    TcpStreamReassembler reassembler;

    feedString(reassembler, 100, "hello ");
    feedString(reassembler, 106, "world");

    EXPECT_EQ(streamAsString(reassembler), "hello world");
}

TEST(TcpStreamReassemblerTest, BuffersOutOfOrderSegmentsAndDrainsWhenGapIsFilled) {
    TcpStreamReassembler reassembler;

    feedString(reassembler, 100, "hello ");
    feedString(reassembler, 111, "!");
    feedString(reassembler, 106, "world");

    EXPECT_EQ(streamAsString(reassembler), "hello world!");
}

TEST(TcpStreamReassemblerTest, IgnoresFullyDuplicateSegment) {
    TcpStreamReassembler reassembler;

    feedString(reassembler, 10, "abc");
    feedString(reassembler, 10, "abc");

    EXPECT_EQ(streamAsString(reassembler), "abc");
}

TEST(TcpStreamReassemblerTest, HandlesPartialOverlap) {
    TcpStreamReassembler reassembler;

    feedString(reassembler, 100, "abc");
    feedString(reassembler, 102, "cde");

    EXPECT_EQ(streamAsString(reassembler), "abcde");
}

TEST(TcpStreamReassemblerTest, ClearResetsState) {
    TcpStreamReassembler reassembler;

    feedString(reassembler, 100, "abc");
    ASSERT_FALSE(reassembler.empty());

    reassembler.clear();

    EXPECT_TRUE(reassembler.empty());

    feedString(reassembler, 500, "xy");

    EXPECT_EQ(streamAsString(reassembler), "xy");
}

TEST(TcpStreamReassemblerTest, IgnoresNullAndEmptyPayloads) {
    TcpStreamReassembler reassembler;

    reassembler.feed(100, nullptr, 10);
    EXPECT_TRUE(reassembler.empty());

    const std::string payload = "abc";
    reassembler.feed(100, reinterpret_cast<const uint8_t*>(payload.data()), 0);
    EXPECT_TRUE(reassembler.empty());
}
