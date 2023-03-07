/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <optional>

#include "http_exception.h"

namespace whc
{
    struct uri;

    struct uri_view
    {
        uri_view() = default;

        template <class string_view, std::enable_if_t<std::is_convertible_v<string_view, std::string_view>>* = nullptr>
        uri_view(string_view&& src) { *this = parse(src); }

        std::string_view scheme{};
        std::string_view hostname{};
        std::uint16_t port{};
        std::string_view user{};
        std::string_view password{};
        std::string_view path{};
        std::string_view extra{};

        [[nodiscard]] static std::optional<uri_view> try_parse(std::string_view src); // returns std::nullopt on failed.
        [[nodiscard]] static uri_view parse(std::string_view src);                    // throws http_exception on failed.
        [[nodiscard]] uri to_uri() const;
        [[nodiscard]] std::string to_string(bool with_password = false) const;
    };

    struct uri
    {
        uri() = default;

        template <class string_view, std::enable_if_t<std::is_convertible_v<string_view, std::string_view>>* = nullptr>
        uri(string_view&& src) { *this = parse(src); }

        std::string scheme{};
        std::string hostname{};
        std::uint16_t port{};
        std::string user{};
        std::string password{};
        std::string path{};
        std::string extra{};

        [[nodiscard]] static std::optional<uri> try_parse(std::string_view src); // returns std::nullopt on failed.
        [[nodiscard]] static uri parse(std::string_view src);                    // throws http_exception on failed.
        [[nodiscard]] uri_view to_view() const;
        [[nodiscard]] std::string to_string(bool with_password = false) const;
        [[nodiscard]] operator uri_view() const { return to_view(); }
    };
}
