/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#include "win_http_client.h"

#include <Windows.h>
#include <winhttp.h>

#pragma comment(lib,"Winhttp.lib")
#pragma comment(lib,"Crypt32.lib")

#include <cstddef>
#include <cstdint>
#include <memory>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

#include "./util/winver.h"
#include "./util/to_wstring.h"
#include "./win_crypt_cert_view.h"
#include "./http_exception.h"

namespace whc::win_http
{
#ifdef _DEBUG
#define ASSERT(...) ([](auto&& r) { if (!r && IsDebuggerPresent()) DebugBreak(); return r; }(__VA_ARGS__))
#else
#define ASSERT(...) ([](auto&& r) { return r; }(__VA_ARGS__))
#endif

    static inline shared_internet_handle wrap_internet_handle_as_shared(
        HINTERNET h,
        std::function<void(HINTERNET)> deleter = [](HINTERNET h) { if (h) { ::WinHttpCloseHandle(h); } })
    {
        return shared_internet_handle(h, std::move(deleter));
    }

    http_session_handle open_http_session(
        std::string_view http_user_agent,
        const http_session_options& options)
    {
        DWORD flags = 0;
        //if (options.async_mode) flags |= WINHTTP_FLAG_ASYNC;

        http_session_handle session_handle{};
        if (!options.proxy_server.has_value())
        {
            if (windows_version::current() >= windows_version{6, 3, 0})
            {
                // Opens handle with automatic proxy
                session_handle = wrap_internet_handle_as_shared(
                    ::WinHttpOpen(
                        to_wstring(http_user_agent).c_str(),
                        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                        WINHTTP_NO_PROXY_NAME,
                        WINHTTP_NO_PROXY_BYPASS,
                        flags));
            }
            else
            {
                // Opens handle with Internet Explorer proxy setting
                WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ie{};
                BOOL ok = WinHttpGetIEProxyConfigForCurrentUser(&ie);
                session_handle = wrap_internet_handle_as_shared(
                    ::WinHttpOpen(
                        to_wstring(http_user_agent).c_str(),
                        ok && ie.lpszProxy ? WINHTTP_ACCESS_TYPE_NAMED_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                        ok && ie.lpszProxy ? ie.lpszProxy : WINHTTP_NO_PROXY_NAME,
                        ok && ie.lpszProxyBypass ? ie.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS,
                        flags));
                if (ie.lpszAutoConfigUrl) GlobalFree(ie.lpszAutoConfigUrl);
                if (ie.lpszProxy) GlobalFree(ie.lpszProxy);
                if (ie.lpszProxyBypass) GlobalFree(ie.lpszProxyBypass);
            }
        }
        else
        {
            // Opens handle with given proxy
            session_handle = wrap_internet_handle_as_shared(
                ::WinHttpOpen(
                    to_wstring(http_user_agent).c_str(),
                    !options.proxy_server->empty() ? WINHTTP_ACCESS_TYPE_NAMED_PROXY : WINHTTP_ACCESS_TYPE_NO_PROXY,
                    !options.proxy_server->empty() ? to_wstring(*options.proxy_server).c_str() : WINHTTP_NO_PROXY_NAME,
                    WINHTTP_NO_PROXY_BYPASS,
                    flags));
        }

        if (!session_handle)
            throw http_exception(http_request_result_code::failed_to_setup_session, static_cast<http_request_error_code>(GetLastError()));

        // setup session
        {
            DWORD secure_protocol_flags = 0;
            if (options.enable_tls12) secure_protocol_flags |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            if (windows_version::current() >= winvers::win11_21H2 && options.enable_tls13) secure_protocol_flags |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
            if (!::WinHttpSetOption(session_handle.get(), WINHTTP_OPTION_SECURE_PROTOCOLS, &secure_protocol_flags, sizeof(secure_protocol_flags)))
                throw http_exception(http_request_result_code::failed_to_setup_session, static_cast<http_request_error_code>(GetLastError()));
        }

        // setup session
        {
            DWORD decompression_flags = 0;
            decompression_flags |= WINHTTP_DECOMPRESSION_FLAG_ALL;
            if (!::WinHttpSetOption(session_handle.get(), WINHTTP_OPTION_DECOMPRESSION, &decompression_flags, sizeof(decompression_flags)))
                throw http_exception(http_request_result_code::failed_to_setup_session, static_cast<http_request_error_code>(GetLastError()));
        }

        // setup session
        if (windows_version::current() >= winvers::win10_1607)
        {
            DWORD http_protocol_flags = 0;
            if (options.enable_http2) http_protocol_flags |= WINHTTP_PROTOCOL_FLAG_HTTP2;
            if (!::WinHttpSetOption(session_handle.get(), WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, &http_protocol_flags, sizeof(http_protocol_flags)))
                throw http_exception(http_request_result_code::failed_to_setup_session, static_cast<http_request_error_code>(GetLastError()));
        }

        return session_handle;
    }

    http_connection_handle open_http_connection(
        http_session_handle session,
        std::string_view hostname,
        uint16_t port,
        const http_connection_options& option)
    {
        (void)option; // reserved to future use

        // Connects to server.
        shared_internet_handle connection = wrap_internet_handle_as_shared(
            ::WinHttpConnect(
                session.get(),
                /* server	*/ to_wstring(hostname).c_str(),
                /* port     */ port,
                /* reserved */ 0));

        return connection;
    }

    http_request_handle open_http_request(
        http_connection_handle connection,
        http_method method,
        uri_view uri,
        const http_request_options& option)
    {
        DWORD request_flags = 0;
        request_flags |= uri.scheme == "https" ? WINHTTP_FLAG_SECURE : 0;

        http_request_handle request_handle = wrap_internet_handle_as_shared(
            ::WinHttpOpenRequest(
                connection.get(),
                /* verb		*/ to_wstring(method).c_str(),
                /* path		*/ (to_wstring(uri.path) + to_wstring(uri.extra)).c_str(),
                /* version	*/ !option.version.value.empty() ? to_wstring(option.version).c_str() : nullptr,
                /* referer	*/ WINHTTP_NO_REFERER,
                /* accept	*/ WINHTTP_DEFAULT_ACCEPT_TYPES,
                /* flags	*/ request_flags));

        if (!request_handle)
            throw http_exception(http_request_result_code::failed_to_setup_request, static_cast<http_request_error_code>(GetLastError()));

        DWORD disable_feature_flags = 0;
        disable_feature_flags |= WINHTTP_DISABLE_COOKIES;
        disable_feature_flags |= WINHTTP_DISABLE_REDIRECTS;
        disable_feature_flags |= WINHTTP_DISABLE_AUTHENTICATION;
        if (!::WinHttpSetOption(request_handle.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disable_feature_flags, sizeof(disable_feature_flags)))
            throw http_exception(http_request_result_code::failed_to_setup_request, static_cast<http_request_error_code>(GetLastError()));

        DWORD enable_feature_flags = 0;
        enable_feature_flags |= WINHTTP_ENABLE_SSL_REVOCATION;
        if (!::WinHttpSetOption(request_handle.get(), WINHTTP_OPTION_ENABLE_FEATURE, &enable_feature_flags, sizeof(enable_feature_flags)))
            throw http_exception(http_request_result_code::failed_to_setup_request, static_cast<http_request_error_code>(GetLastError()));

        if (option.ignore_certificate_error)
        {
            DWORD security_flags = 0;
            security_flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
            security_flags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
            security_flags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            if (!::WinHttpSetOption(request_handle.get(), WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags)))
                throw http_exception(http_request_result_code::failed_to_setup_request, static_cast<http_request_error_code>(GetLastError()));
        }

        return request_handle;
    }

    void send_http_request(
        http_request_handle request,
        const http_header_collection& header)
    {
        auto request_header_string = to_wstring(header.to_http_header_string());
        if (!::WinHttpSendRequest(
            request.get(),
            /* header   */ request_header_string.c_str(), static_cast<DWORD>(request_header_string.size()),
            /* optional */ nullptr, 0,
            /* total    */ WINHTTP_IGNORE_REQUEST_TOTAL_LENGTH,
            /* context  */ NULL))
            throw http_exception(http_request_result_code::failed_to_send_request, static_cast<http_request_error_code>(GetLastError()));
    }

    std::shared_ptr<win_crypt::certificate_chain_context_view> get_server_certificates(
        http_request_handle request)
    {
        PCCERT_CONTEXT cert_context = nullptr;
        DWORD size = static_cast<DWORD>(sizeof(cert_context));

        if (!::WinHttpQueryOption(request.get(), WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert_context, &size))
            throw http_exception(http_request_result_code::fault, static_cast<http_request_error_code>(GetLastError()));

        return win_crypt::allocate_chain_context_view_from(std::shared_ptr<const CERT_CONTEXT>{cert_context, &::CertFreeCertificateContext});
    }

    size_t write_http_request_body(
        http_request_handle request,
        const void* data,
        size_t data_length)
    {
        const std::byte* ptr = static_cast<const std::byte*>(data);
        while (data_length)
        {
            DWORD sending = static_cast<DWORD>(std::min<size_t>(data_length, 262144));
            DWORD sent{};
            if (!::WinHttpWriteData(request.get(), ptr, sending, &sent))
                throw http_exception(http_request_result_code::failed_to_send_request, static_cast<http_request_error_code>(GetLastError()));
            data_length -= sent;
            ptr += sent;
        }
        return data_length;
    }

    http_response_handle receive_http_response(
        http_request_handle request)
    {
        if (!WinHttpReceiveResponse(request.get(), /* reserved */ nullptr))
            throw http_exception(http_request_result_code::failed_to_receive_response, static_cast<http_request_error_code>(GetLastError()));

        return static_cast<http_response_handle>(request);
    }

    static std::optional<std::string> query_http_information_as_string_from_request(HINTERNET hRequest, DWORD dwInfoLevel)
    {
        DWORD dwBufLen = 0;
        if (!::WinHttpQueryHeaders(
                hRequest, dwInfoLevel,
                WINHTTP_HEADER_NAME_BY_INDEX,
                WINHTTP_NO_OUTPUT_BUFFER,
                &dwBufLen,
                WINHTTP_NO_HEADER_INDEX)
            && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            std::wstring buffer((dwBufLen + 1) / sizeof(wchar_t), L'\0');
            if (::WinHttpQueryHeaders(
                hRequest,
                dwInfoLevel,
                WINHTTP_HEADER_NAME_BY_INDEX,
                buffer.data(), &dwBufLen,
                WINHTTP_NO_HEADER_INDEX))
            {
                // force convert to 8bit
                std::optional<std::string> s(std::in_place);
                for (auto sc : buffer)
                    if (ASSERT(!(sc & ~0x7F))) s->push_back(static_cast<std::string::value_type>(sc & 0x7F));
                    else s->push_back('?');
                return s;
            }
        }
        ASSERT(false);
        return std::nullopt;
    }

    static std::optional<DWORD> query_http_information_as_number_from_request(HINTERNET hRequest, DWORD dwInfoLevel)
    {
        DWORD buffer{};
        DWORD dwBufLen = sizeof(buffer);
        if (::WinHttpQueryHeaders(
            hRequest,
            dwInfoLevel | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &buffer, &dwBufLen,
            WINHTTP_NO_HEADER_INDEX))
            return buffer;
        return std::nullopt;
    }

    int get_http_response_status_code(
        http_response_handle response)
    {
        if (auto code = query_http_information_as_number_from_request(response.get(), WINHTTP_QUERY_STATUS_CODE))
            return static_cast<int>(*code);
        else
            throw http_exception(http_request_result_code::failed_to_receive_response, static_cast<http_request_error_code>(GetLastError()));
    }

    static http_header_collection http_header_collection_from_asciiz_string(std::string_view asciiz)
    {
        http_header_collection parsed;

        auto trim = [](std::string_view str) -> std::string_view
        {
            const char* const t = "\t\r\n ";
            auto beg = str.find_first_not_of(t);
            return beg != std::string_view::npos
                       ? str.substr(beg, str.find_last_not_of(t) + 1 - beg)
                       : str.substr(0, 0);
        };

        std::string_view::size_type p = 0;
        while (true)
        {
            std::string_view line;
            {
                auto q = asciiz.find('\0', p);
                if (q == std::string_view::npos) { q = asciiz.size(); }
                if (p == q) { break; }
                line = asciiz.substr(p, q - p);
                p = q + 1;
            }

            auto colon = line.find(':');
            if (colon == std::string_view::npos)
            {
                parsed.emplace_back("Status", std::string(line));
                continue;
            }

            auto key = trim(line.substr(0, colon));
            auto value = trim(line.substr(colon + 1));
            parsed.emplace_back(key, value);
        }

        return parsed;
    }

    http_header_collection get_http_request_headers(http_response_handle response)
    {
        if (auto headers_str = query_http_information_as_string_from_request(response.get(), WINHTTP_QUERY_FLAG_REQUEST_HEADERS | WINHTTP_QUERY_RAW_HEADERS))
            return http_header_collection_from_asciiz_string(*headers_str);
        else
            throw http_exception(http_request_result_code::failed_to_receive_response, static_cast<http_request_error_code>(GetLastError()));
    }

    http_header_collection get_http_response_headers(http_response_handle response)
    {
        if (auto headers_str = query_http_information_as_string_from_request(response.get(), WINHTTP_QUERY_RAW_HEADERS))
            return http_header_collection_from_asciiz_string(*headers_str);
        else
            throw http_exception(http_request_result_code::failed_to_receive_response, static_cast<http_request_error_code>(GetLastError()));
    }

    size_t read_http_response_body(http_response_handle response, void* data, size_t length)
    {
        DWORD received = 0;
        if (!::WinHttpReadData(response.get(), data, static_cast<DWORD>(length), &received))
            throw http_exception(http_request_result_code::failed_to_receive_response, static_cast<http_request_error_code>(GetLastError()));
        return received;
    }
}
