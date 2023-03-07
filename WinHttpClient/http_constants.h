/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <Windows.h>
#include <string_view>

namespace whc
{
    template <class tag>
    class http_constant_value_t
    {
    public:
        std::string_view value{};

        constexpr explicit http_constant_value_t(std::string_view value) : value(value) { }
        constexpr operator std::string_view() const noexcept { return value; }
    };

    namespace http_versions
    {
        struct http_constant_tag;
        using http_version = http_constant_value_t<http_constant_tag>;
        constexpr http_version AUTO{""};
        constexpr http_version HTTP1_1{"HTTP/1.1"};
        constexpr http_version HTTP2{"HTTP/2"};
    }

    namespace http_methods
    {
        struct http_constant_tag;
        using http_method = http_constant_value_t<http_constant_tag>;
        constexpr http_method HTTP_GET{"GET"};
        constexpr http_method HTTP_HEAD{"HEAD"};
        constexpr http_method HTTP_POST{"POST"};
        constexpr http_method HTTP_PUT{"PUT"};
        constexpr http_method HTTP_DELETE{"DELETE"};
        constexpr http_method HTTP_OPTIONS{"OPTIONS"};
    }

    using http_versions::http_version;
    using http_methods::http_method;
}
