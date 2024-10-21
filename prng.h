#pragma once

#include <cstdint>

// adapted from https://gist.github.com/EvanMcBroom/ace2a9af19fb5e7b2451b1cd4c07bf96


// https://www.firstpr.com.au/dsp/rand31/p1192-park.pdf
constexpr uint32_t modulus = 0x7fffffff;
constexpr uint32_t lcg_a = 48271;


constexpr uint32_t prng(const uint32_t input) {
	return (input * lcg_a) % modulus;
}

template<size_t N>
constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
    auto value{ iv };
    for (size_t i = 0; i < N; i++) {
        // Xor 1st byte of seed with input byte
        value = (value & ((~0) << 8)) | ((value & 0xFF) ^ entropy[i]);
        // Rotate left 1 byte
        value = value << 8 | value >> ((sizeof(value) * 8) - 8);
    }
    // The seed is required to be less than the modulus and odd
    while (value > modulus) value = value >> 1;
    return value << 1 | 1;
}

// std::array alternative which also contains the seed
template <typename T, size_t N>
struct Encrypted {
    int seed;
	T data[N];
};


// encryption/decryption
template <typename T, size_t N>
constexpr auto crypt(const T(&input)[N], const uint32_t seed = 0) {
    Encrypted<T, N> blob{};
    blob.seed = seed;

    for (uint32_t i = 0, stream = seed; i < N; i++) {
        blob.data[i] = input[i] ^ stream;
        stream = prng(stream);
    }
    return blob;
}

/* 
- encryption is done at compile time
- _ however points to stack var, and must be done at runtime
- NOTE: disable edit and continue feature in visual studio for __LINE__ to be used in a constant expression
*/ 
#define make_encrypted_string(STRING) ([&] {                     \
    constexpr auto _{ crypt(STRING, seed(__FILE__, __LINE__)) }; \
    return std::string{ crypt(_.data, _.seed).data };            \
}())

#define make_encrypted_cstring(STRING) ([&] {                    \
    constexpr auto _{ crypt(STRING, seed(__FILE__, __LINE__)) }; \
    return std::string{ crypt(_.data, _.seed).data }.c_str();    \
}())

#define make_encrypted_wstring(STRING) ([&] {                     \
    constexpr auto _{ crypt(STRING, seed(__FILE__, __LINE__)) };  \
    return std::wstring{ crypt(_.data, _.seed).data };            \
}())