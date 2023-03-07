/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <array>
#include <set>
#include <tuple>

namespace whc
{
    struct certificate_signature
    {
        std::array<uint8_t, 20> sha1;
        std::array<uint8_t, 16> md5;

        // operator <=>
        [[nodiscard]] auto tie() const noexcept { return std::tie(sha1, md5); }
        bool operator ==(const certificate_signature& rhs) const { return tie() == rhs.tie(); }
        bool operator !=(const certificate_signature& rhs) const { return tie() != rhs.tie(); }
        bool operator <(const certificate_signature& rhs) const { return tie() < rhs.tie(); }
        bool operator <=(const certificate_signature& rhs) const { return tie() <= rhs.tie(); }
        bool operator >(const certificate_signature& rhs) const { return tie() > rhs.tie(); }
        bool operator >=(const certificate_signature& rhs) const { return tie() >= rhs.tie(); }
    };

    using certificate_signature_set = std::set<certificate_signature>;

    const certificate_signature_set* default_trusted_root_ca_certificates_set();
}
