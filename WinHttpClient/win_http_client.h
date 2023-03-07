/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "./http_constants.h"
#include "./http_header.h"
#include "./uri.h"

#include "./win_crypt_cert_view.h"

namespace whc::win_http
{
    using HINTERNET = void*; // from <winhttp.h>

    using unique_internet_handle = std::unique_ptr<std::remove_pointer_t<HINTERNET>, std::function<void(HINTERNET)>>;
    using shared_internet_handle = std::shared_ptr<std::remove_pointer_t<HINTERNET>>;

    using http_session_handle = shared_internet_handle;
    using http_connection_handle = shared_internet_handle;
    using http_request_handle = shared_internet_handle;
    using http_response_handle = shared_internet_handle;

    /// Represents a HTTP session option
    struct http_session_options
    {
        std::optional<std::string> proxy_server = std::nullopt;
        bool enable_tls12 = true;
        bool enable_tls13 = true;
        bool enable_http2 = true;
    };

    /// Opens new HTTP session
    [[nodiscard]]
    http_session_handle open_http_session(
        std::string_view http_user_agent,
        const http_session_options& options = {});

    /// Represents a HTTP connection option
    struct http_connection_options
    {
        // reserved
    };

    /// Opens HTTP connection on given session
    [[nodiscard]]
    http_connection_handle open_http_connection(
        http_session_handle session,
        std::string_view hostname,
        uint16_t port,
        const http_connection_options& options = {});

    /// Represents a HTTP request option
    struct http_request_options
    {
        http_version version = http_versions::HTTP1_1;
        bool ignore_certificate_error = false;
    };

    /// Opens new HTTP request on given connection
    [[nodiscard]]
    http_request_handle open_http_request(
        http_connection_handle connection,
        http_method method,
        uri_view uri,
        const http_request_options& option = {});

    /// Sends HTTP request
    void send_http_request(
        http_request_handle request,
        const http_header_collection& header = http_header_collection{});

    /// Gets server certificate chain
    [[nodiscard]]
    std::shared_ptr<win_crypt::certificate_chain_context_view> get_server_certificates(
        http_request_handle request);

    /// Send HTTP request body
    [[nodiscard]]
    size_t write_http_request_body(
        http_request_handle request,
        const void* data,
        size_t data_length);

    /// Receives HTTP response
    [[nodiscard]]
    http_response_handle receive_http_response(
        http_request_handle request);

    /// Gets HTTP response status code
    [[nodiscard]]
    int get_http_response_status_code(
        http_response_handle response);

    /// Gets HTTP request headers
    [[nodiscard]]
    http_header_collection get_http_request_headers(
        http_response_handle response);

    /// Gets HTTP response headers
    [[nodiscard]]
    http_header_collection get_http_response_headers(
        http_response_handle response);

    /// Receives HTTP response body
    [[nodiscard]]
    size_t read_http_response_body(
        http_response_handle response,
        void* data,
        size_t length);
}
