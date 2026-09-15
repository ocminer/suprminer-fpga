/* Offline BS1 nonce policy tests. No device, bridge or pool is opened. */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "vu9p_bs1_policy.h"

/* Independent base-2^32 long arithmetic also works on 32-bit USB hosts.
 * Compilers with a native 128-bit integer cross-check this oracle as well. */
static uint64_t reference_hashes(uint64_t rate, uint32_t ms, uint64_t cap)
{
    uint32_t words[3], quotient[3];
    uint64_t n, remainder = 0, result;
    int i;
    n = (uint64_t)(uint32_t)rate * ms;
    words[0] = (uint32_t)n;
    n = (rate >> 32) * ms + (n >> 32);
    words[1] = (uint32_t)n;
    words[2] = (uint32_t)(n >> 32);
    n = (uint64_t)words[0] + 999;
    words[0] = (uint32_t)n;
    n = (uint64_t)words[1] + (n >> 32);
    words[1] = (uint32_t)n;
    words[2] += (uint32_t)(n >> 32);
    for (i = 2; i >= 0; --i) {
        n = (remainder << 32) | words[i];
        quotient[i] = (uint32_t)(n / 1000);
        remainder = n % 1000;
    }
    result = ((uint64_t)quotient[1] << 32) | quotient[0];
    if (quotient[2] || result > cap)
        result = cap;
#ifdef __SIZEOF_INT128__
    {
        __uint128_t wide = ((__uint128_t)rate * ms + 999) / 1000;
        assert(result == (wide > cap ? cap : (uint64_t)wide));
    }
#endif
    return result;
}

int main(void)
{
    const uint64_t capacity = UINT64_C(4294967296);
    const uint64_t rate = UINT64_C(300000000);
    const uint64_t limit = capacity - UINT64_C(60000000);
    const uint32_t lanes[] = {0, 2, 3, 32, UINT32_MAX};
    const uint64_t rates[] = {0, 1, 999, 1000, 1001, 300000000,
                             UINT64_MAX / 2, UINT64_MAX};
    const uint32_t intervals[] = {0, 1, 49, 50, 51, 52, 199, 200,
                                  1000, UINT32_MAX};
    const uint64_t caps[] = {0, 1, 999, 1000, 4294967296, UINT64_MAX};
    size_t i, j, k;

    assert(VU9P_FIXED_LANE_STRIDE == 1);
    assert(VU9P_NONCE_SPACE_HASHES == capacity);
    assert(vu9p_active_lanes_valid(1));
    assert(vu9p_active_lane_mask(1) == 1);
    assert(vu9p_production_build_id(1) == UINT32_C(0x5a3d0001));
    assert(vu9p_production_identity_matches(UINT32_C(0x5a3d0001), 1));
    assert(!vu9p_production_identity_matches(0, 1));
    assert(!vu9p_production_identity_matches(UINT32_C(0x5a3d0000), 1));
    assert(!vu9p_production_identity_matches(UINT32_C(0x5a3d0002), 1));
    assert(!vu9p_production_identity_matches(UINT32_MAX, 1));
    assert(vu9p_unique_epoch_capacity(1) == capacity);
    for (i = 0; i < sizeof(lanes) / sizeof(lanes[0]); ++i) {
        assert(!vu9p_active_lanes_valid(lanes[i]));
        assert(vu9p_active_lane_mask(lanes[i]) == 0);
        assert(vu9p_production_build_id(lanes[i]) == 0);
        assert(!vu9p_production_identity_matches(VU9P_BUILD_ID_BC3_BS1,
                                                lanes[i]));
        assert(vu9p_unique_epoch_capacity(lanes[i]) == 0);
        assert(vu9p_roll_limit(lanes[i], rate, 0, 200) == 0);
        assert(vu9p_unique_hashes_in_epoch(capacity, lanes[i]) == 0);
        assert(vu9p_classify_hash_counter(0, 1, lanes[i], rate, 0, 200)
               == VU9P_ROLL_INVALID_CONFIG);
    }

    assert(vu9p_transaction_timeout_ms(0) == 0);
    assert(vu9p_transaction_timeout_ms(50) == 0);
    assert(vu9p_transaction_timeout_ms(51) == 0);
    assert(vu9p_transaction_timeout_ms(52) == 1);
    assert(vu9p_transaction_timeout_ms(199) == 74);
    assert(vu9p_transaction_timeout_ms(200) == 75);
    for (i = 0; i < sizeof(intervals) / sizeof(intervals[0]); ++i) {
        uint64_t timeout = vu9p_transaction_timeout_ms(intervals[i]);
        if (timeout)
            assert(2 * timeout + VU9P_POLL_PERIOD_MS <= intervals[i]);
        for (j = 0; j < sizeof(rates) / sizeof(rates[0]); ++j)
            for (k = 0; k < sizeof(caps) / sizeof(caps[0]); ++k)
                assert(vu9p_hashes_for_ms_capped(rates[j], intervals[i],
                           caps[k]) == reference_hashes(rates[j], intervals[i],
                                                       caps[k]));
    }

    assert(vu9p_roll_limit(1, rate, 0, 200) == limit);
    assert(vu9p_roll_limit(1, rate, rate - 1, 200) == limit);
    assert(vu9p_roll_limit(1, rate, 400000000, 200)
           == capacity - UINT64_C(80000000));
    assert(vu9p_roll_limit(1, 1, 0, 52) == capacity - 1);
    assert(vu9p_roll_limit(1, 0, rate, 200) == 0);
    assert(vu9p_roll_limit(1, rate, 0, 51) == 0);
    assert(vu9p_roll_limit(1, capacity, 0, 1000) == 0);
    assert(vu9p_roll_limit(1, UINT64_MAX, 0, UINT32_MAX) == 0);
    assert(vu9p_roll_limit(1, rate, UINT64_MAX, 200) == 0);
    assert(vu9p_classify_hash_counter(0, 0, 1, rate, 0, 200)
           == VU9P_ROLL_CONTINUE);
    assert(vu9p_classify_hash_counter(limit - 2, limit - 1, 1, rate, 0, 200)
           == VU9P_ROLL_CONTINUE);
    assert(vu9p_classify_hash_counter(limit, limit, 1, rate, 0, 200)
           == VU9P_ROLL_THRESHOLD);
    assert(vu9p_classify_hash_counter(0, capacity, 1, rate, 0, 200)
           == VU9P_ROLL_THRESHOLD);
    assert(vu9p_classify_hash_counter(2, 1, 1, rate, 0, 200)
           == VU9P_ROLL_COUNTER_REGRESSION);
    assert(vu9p_classify_hash_counter(capacity, 0, 1, rate, 0, 200)
           == VU9P_ROLL_COUNTER_REGRESSION);
    assert(vu9p_classify_hash_counter(0, capacity + 1, 1, rate, 0, 200)
           == VU9P_ROLL_COUNTER_OVERRUN);
    assert(vu9p_classify_hash_counter(0, UINT64_MAX, 1, rate, 0, 200)
           == VU9P_ROLL_COUNTER_OVERRUN);
    assert(vu9p_classify_hash_counter(0, 0, 1, 0, 0, 200)
           == VU9P_ROLL_INVALID_CONFIG);
    assert(vu9p_unique_hashes_in_epoch(capacity - 1, 1) == capacity - 1);
    assert(vu9p_unique_hashes_in_epoch(capacity, 1) == capacity);
    assert(vu9p_unique_hashes_in_epoch(UINT64_MAX, 1) == capacity);
    assert(vu9p_add_unique_hashes(17, capacity + 1, 1) == 17 + capacity);
    assert(vu9p_add_unique_hashes(UINT64_MAX - capacity, capacity, 1)
           == UINT64_MAX);
    assert(vu9p_add_unique_hashes(UINT64_MAX - capacity + 1, capacity, 1)
           == UINT64_MAX);
    assert(vu9p_add_unique_hashes(UINT64_MAX, 1, 1) == UINT64_MAX);
    puts("PASS BS1 identity, 480 arithmetic cases, rollover and saturation");
    return 0;
}
