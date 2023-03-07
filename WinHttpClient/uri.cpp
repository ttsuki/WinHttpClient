/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#include "uri.h"

#include <Windows.h>
#include <winhttp.h>
#include <optional>
#include <stdexcept>
#include <algorithm>

#include "util/to_wstring.h"

namespace whc
{
    std::optional<uri_view> uri_view::try_parse(std::string_view src)
    {
        // assume ascii character only.
        if (std::any_of(src.begin(), src.end(), [](char c) { return c & ~0x7F; }))
            return std::nullopt; // throw std::invalid_argument("only ascii supported.");

        std::wstring input = to_wstring(src);
        const wchar_t* const p = input.data();

        ::URL_COMPONENTS uc{};
        uc.dwStructSize = sizeof(uc);
        uc.dwSchemeLength = 1;
        uc.dwHostNameLength = 1;
        uc.dwUserNameLength = 1;
        uc.dwPasswordLength = 1;
        uc.dwUrlPathLength = 1;
        uc.dwExtraInfoLength = 1;

        if (::WinHttpCrackUrl(p, static_cast<DWORD>(src.size()), 0, &uc))
        {
            std::optional<uri_view> result = std::nullopt;
            result.emplace();
            if (uc.lpszScheme) result->scheme = src.substr(uc.lpszScheme - p, uc.dwSchemeLength);
            if (uc.lpszHostName) result->hostname = src.substr(uc.lpszHostName - p, uc.dwHostNameLength);
            if (uc.nPort) result->port = uc.nPort;
            if (uc.lpszUserName) result->user = src.substr(uc.lpszUserName - p, uc.dwUserNameLength);
            if (uc.lpszPassword) result->password = src.substr(uc.lpszPassword - p, uc.dwPasswordLength);
            if (uc.lpszUrlPath) result->path = src.substr(uc.lpszUrlPath - p, uc.dwUrlPathLength);
            if (uc.lpszExtraInfo) result->extra = src.substr(uc.lpszExtraInfo - p, uc.dwExtraInfoLength);
            return result;
        }

        return std::nullopt; // failed
    }

    uri_view uri_view::parse(std::string_view src)
    {
        if (auto parsed = try_parse(src))
            return *parsed;
        else
            throw http_exception(http_request_result_code::invalid_url, static_cast<http_request_error_code>(GetLastError()));
    }

    uri uri_view::to_uri() const
    {
        uri result{};
        result.scheme = this->scheme;
        result.hostname = this->hostname;
        result.port = this->port;
        result.user = this->user;
        result.password = this->password;
        result.path = this->path;
        result.extra = this->extra;
        return result;
    }

    std::string uri_view::to_string(bool with_password) const
    {
        std::string result{};
        result.reserve(scheme.size() + user.size() + password.size() + hostname.size() + path.size() + extra.size() + 16);
        result += scheme;
        result += "://";
        if (!user.empty())
        {
            result += user;
            if (with_password && !password.empty())
            {
                result += ":";
                result += password;
            }
            result += "@";
        }
        result += hostname;
        result += ":";
        result += std::to_string(port);
        result += path;
        result += extra;
        return result;
    }

    std::optional<uri> uri::try_parse(std::string_view src)
    {
        if (auto t = uri_view::try_parse(src))
            return t->to_uri();
        return std::nullopt;
    }

    uri uri::parse(std::string_view src)
    {
        if (auto parsed = try_parse(src))
            return *parsed;
        else
            throw http_exception(http_request_result_code::invalid_url, static_cast<http_request_error_code>(GetLastError()));
    }

    uri_view uri::to_view() const
    {
        uri_view view{};
        view.scheme = this->scheme;
        view.hostname = this->hostname;
        view.port = this->port;
        view.user = this->user;
        view.password = this->password;
        view.path = this->path;
        view.extra = this->extra;
        return view;
    }

    std::string uri::to_string(bool with_password) const
    {
        return to_view().to_string(with_password);
    }
}
