
#include "bp_cbor.h"
#include <inttypes.h>
#include <glib.h>
#include <epan/value_string.h>
#include <epan/wmem/wmem_allocator.h>
#include <epan/tvbuff.h>
#include <gtest/gtest.h>
#include <string>
#include <cstdlib>

class TvbStore {
 public:
    static TvbStore fromHex(const std::string &hexstr) {
        const auto len = hexstr.size();
        if ((len & 0x1) != 0) {
            throw std::logic_error("Hex string must be multiple of two digits");
        }

        std::string buf;
        for(std::size_t offset = 0; offset < len; offset += 2) {
            const auto val = int(::strtol(hexstr.substr(offset, 2).c_str(), nullptr, 16));
            buf.push_back(char(val));
        }
        return TvbStore(std::move(buf));
    }

    TvbStore(std::string &&src)
      : buf(std::move(src)) {
        tvb = ::tvb_new_real_data((const guint8 *)buf.data(), buf.size(), buf.size());
    }

    ~TvbStore() {
        ::tvb_free(tvb);
    }

    /// Backing buffer
    std::string buf;
    /// Front-facing interface
    tvbuff_t *tvb = nullptr;
};

class TestBpCbor : public testing::Test {
 protected:
    void SetUp() override {
        _alloc = wmem_allocator_new(WMEM_ALLOCATOR_STRICT);
    }
    void TearDown() override {
        wmem_destroy_allocator(_alloc);
        _alloc = nullptr;
    }

    wmem_allocator_t *_alloc = nullptr;
};

TEST_F(TestBpCbor, testTvbStore) {
    auto store = TvbStore(std::string("\x00\x01\x02\x03\x04", 5));

    ASSERT_EQ(5, tvb_captured_length(store.tvb));
    ASSERT_EQ(5, tvb_reported_length(store.tvb));
    EXPECT_EQ(2, tvb_get_guint8(store.tvb, 2));
}

TEST_F(TestBpCbor, testTvbStoreHex) {
    auto store = TvbStore::fromHex("0001020304");

    ASSERT_EQ(5, tvb_captured_length(store.tvb));
    ASSERT_EQ(5, tvb_reported_length(store.tvb));
    EXPECT_EQ(2, tvb_get_guint8(store.tvb, 2));
}

TEST_F(TestBpCbor, testDecodeHead0) {
    auto store = TvbStore::fromHex("05");
    auto head = bp_cbor_head_read(_alloc, store.tvb, 0);
    ASSERT_NE(nullptr, head);
    EXPECT_EQ(0, head->start);
    EXPECT_EQ(1, head->length);
    EXPECT_EQ(nullptr, head->error);
    EXPECT_EQ(0, head->type_major);
    EXPECT_EQ(5, head->type_minor);
    EXPECT_EQ(5, head->rawvalue);
}

TEST_F(TestBpCbor, testDecodeHead4) {
    auto store = TvbStore::fromHex("1A000186A0");
    auto head = bp_cbor_head_read(_alloc, store.tvb, 0);
    ASSERT_NE(nullptr, head);
    EXPECT_EQ(0, head->start);
    EXPECT_EQ(5, head->length);
    EXPECT_EQ(nullptr, head->error);
    EXPECT_EQ(0, head->type_major);
    EXPECT_EQ(26, head->type_minor);
    EXPECT_EQ(100000, head->rawvalue);
}

TEST_F(TestBpCbor, testSkipItem) {
    auto store = TvbStore::fromHex("82626869190D4801");
    gint offset = 0;
    auto indef = cbor_skip_next_item(_alloc, store.tvb, &offset);
    EXPECT_EQ(FALSE, indef);
    EXPECT_EQ(7, offset);
}

TEST_F(TestBpCbor, testRequirePositive) {
    auto store = TvbStore::fromHex("1A000186A0");
    gint offset = 0;
    auto chunk = bp_cbor_chunk_read(_alloc, store.tvb, &offset);
    ASSERT_NE(nullptr, chunk);
    EXPECT_EQ(5, offset);
    {
        auto value = cbor_require_uint64(_alloc, chunk);
        ASSERT_NE(nullptr, value);
        EXPECT_EQ(100000, *value);
    }
    {
        auto value = cbor_require_int64(_alloc, chunk);
        ASSERT_NE(nullptr, value);
        EXPECT_EQ(100000, *value);
    }
}

TEST_F(TestBpCbor, testRequireNegative) {
    auto store = TvbStore::fromHex("3A0001869F");
    gint offset = 0;
    auto chunk = bp_cbor_chunk_read(_alloc, store.tvb, &offset);
    ASSERT_NE(nullptr, chunk);
    EXPECT_EQ(5, offset);
    {
        auto value = cbor_require_uint64(_alloc, chunk);
        ASSERT_EQ(nullptr, value);
    }
    {
        auto value = cbor_require_int64(_alloc, chunk);
        ASSERT_NE(nullptr, value);
        EXPECT_EQ(-100000, *value);
    }
}
