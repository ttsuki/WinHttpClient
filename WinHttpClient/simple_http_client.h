/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <memory>
#include <string>
#include <string_view>
#include <functional>

#include "http_constants.h"
#include "http_exception.h"
#include "http_header.h"
#include "uri.h"

namespace whc::simple
{
    namespace http_versions = whc::http_versions;
    namespace http_methods = whc::http_methods;

    /// HTTP request message
    struct http_request_message
    {
        /// Headers
        http_header_collection request_headers{};

        /// Reads request body and returns read bytes or 0 if reached to end of body.
        std::function<size_t(void* buffer, size_t length)> read_request_body{};
    };

    /// HTTP response message
    struct http_response_message
    {
        /// Status code
        int http_status_code{};

        /// Headers
        http_header_collection response_headers{};

        /// Reads response body and returns read bytes or 0 if reached to end of body.
        std::function<size_t(void* buffer, size_t length)> read_response_body{};
    };

    /// Makes http_request_message from data.
    [[nodiscard]] http_request_message make_request_message(
        std::string_view content_type,
        const void* data, size_t length,
        http_header_collection additional_headers = {});

    /// Makes http_request_message from string_view.
    [[nodiscard]] http_request_message make_request_message(
        std::string_view content_type,
        std::string_view data,
        http_header_collection additional_headers = {});

    /// Reads out whole response message.
    [[nodiscard]] std::string read_out_response_body_as_string(
        http_response_message& response,
        size_t max_size = 16777216);

    /// Simple HTTP client
    class http_client
    {
    public:
        // ctor
        http_client(std::string_view user_agent_string);

        /// Executes a HTTP request and opens response stream.
        /// @throws http_exception on failed to request
        [[nodiscard]] http_response_message execute_http_request(
            uri_view uri,
            http_method method = http_methods::HTTP_GET,
            const http_request_message& request = {}) const;

    private:
        std::shared_ptr<void> session_handle_{};
    };
}
