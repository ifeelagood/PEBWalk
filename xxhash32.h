#pragma once

#include <string>
#include <cstdint>
#include <bit>
#include <array>

namespace xxhash32 {
constexpr uint32_t PRIME32_1 = 0x9E3779B1U;
constexpr uint32_t PRIME32_2 = 0x85EBCA77U;
constexpr uint32_t PRIME32_3 = 0xC2B2AE3DU;
constexpr uint32_t PRIME32_4 = 0x27D4EB2FU;
constexpr uint32_t PRIME32_5 = 0x165667B1U;


constexpr uint8_t read_u8(const char* input, int pos) {
    return static_cast<uint8_t>(input[pos]);
}

inline constexpr uint32_t read_u32le(const char* input, uint32_t i) {
    const uint32_t b0 = read_u8(input, i + 0);
    const uint32_t b1 = read_u8(input, i + 1);
    const uint32_t b2 = read_u8(input, i + 2);
    const uint32_t b3 = read_u8(input, i + 3);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}


// rotl(x,r)
inline constexpr uint32_t rotl(const uint32_t x, const uint32_t r) {
    return (x << r) | (x >> (32 - r));
}

constexpr uint32_t xxh32_avalanche(uint32_t h32) {
    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;
    return h32;
}

constexpr uint32_t xxh32_finalize(const char* input, size_t N, uint32_t i, uint32_t h32) {
    // XXH_PROCESS4
    while ((N - i) >= 4) {
        h32 += read_u32le(input, i) * PRIME32_3;
        h32 = rotl(h32, 17) * PRIME32_4;
        i += 4;
    }
    // XXH_PROCESS1
    while ((N - i) > 0) {
        h32 += read_u8(input, i) * PRIME32_5;
        h32 = rotl(h32, 11) * PRIME32_1;
        i += 1;
    }
    return h32;
}

constexpr uint32_t xxh32_digest(
    const char* input, size_t N, uint32_t i,
    uint32_t v1, uint32_t v2, uint32_t v3, uint32_t v4
) {
    uint32_t h32 = 0;
    if (N >= 16) {
        h32 = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18);
    }
    else {
        h32 = v3 + PRIME32_5;
    }
    h32 += N;
    h32 = xxh32_finalize(input, N, i, h32);
    return xxh32_avalanche(h32);
}


// Function to process a single 4-byte block
inline constexpr uint32_t xxh32_round(uint32_t acc, const char* input, uint32_t i) {
    const uint32_t d = read_u32le(input, i);
    acc += d * PRIME32_2;
    acc = rotl(acc, 13) * PRIME32_1;
    return acc;
}

constexpr uint32_t xxh32(const char* input, size_t N, uint32_t seed) {
    uint32_t v1 = seed + PRIME32_1 + PRIME32_2;
    uint32_t v2 = seed + PRIME32_2;
    uint32_t v3 = seed;
    uint32_t v4 = seed - PRIME32_1;
    uint32_t i = 0;

    while (i + 16 <= N) {
        v1 = xxh32_round(v1, input, i + 0 * 4);
        v2 = xxh32_round(v2, input, i + 1 * 4);
        v3 = xxh32_round(v3, input, i + 2 * 4);
        v4 = xxh32_round(v4, input, i + 3 * 4);
        i += 16;
    }
    return xxh32_digest(input, N, i, v1, v2, v3, v4);
}

}

// Computes the xxHash32 at compile time
template <size_t N>
consteval uint32_t xxh32_consteval(const char(&input)[N], const uint32_t seed = 0) {
    return xxhash32::xxh32(input, N, seed);
}



uint32_t xxh32_runtime(const char* input, const uint32_t seed = 0);



// A note about passing cstyle arrays:
// - template argument size_t N for length works well for compile time eval ONLY, i.e. const T(&input)[N], as N must be known at compile time!
// - at runtime, size can be deduced using std::char_traits<char>::length
// - therefore, template argument will still work, we just need to make optional constexpr functions use const T* instead;