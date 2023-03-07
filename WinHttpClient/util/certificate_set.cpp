/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#include "certificate_set.h"
#include <cstddef>
#include <cstdint>

namespace whc
{
    /// Convert Variable-Length-Hexadecimal Number to std::array of uint8_t.
    // 0x0123456789ABCDEF... -> std::array<uint8_t, ...> { 0x01, 0x23, ..., 0xEF, ... }
    template <char z, char x, char... cs>
    static inline constexpr auto parse_byte_array_literal()
    {
        constexpr auto nibble = [](char input) -> uint8_t
        {
            if (input >= '0' && input <= '9') return input - '0';
            if (input >= 'A' && input <= 'F') return input - 'A' + 10;
            if (input >= 'a' && input <= 'f') return input - 'a' + 10;
            throw false;
        };

        static_assert(z == '0' && (x == 'x' || x == 'X') && sizeof...(cs) % 2 == 0);
        constexpr std::array<uint8_t, sizeof...(cs)> data{ nibble(cs)... };

        std::array<uint8_t, sizeof...(cs) / 2> result{};
        for (size_t i = 0; i < result.size(); i++)
            result[i] = static_cast<unsigned char>(data[i * 2] << 4 | data[i * 2 + 1]);

        return result;
    }

    template <char...cs>
    static inline constexpr auto operator"" _bin_as_array()
    {
        return parse_byte_array_literal<cs...>();
    }

    const certificate_signature_set* default_trusted_root_ca_certificates_set()
    {
        static const certificate_signature all[]
        {
            #define CERT_ENTRY(SHA1,MD5) { 0x ## SHA1 ## _bin_as_array, 0x ## MD5 ## _bin_as_array }
            #include "trusted_root_ca_certificates.txt"
            #undef CERT_ENTRY
        };
        static const certificate_signature_set c(std::begin(all), std::end(all));
        return &c;
    }
}
