/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#include "simple_http_client.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <functional>
#include <algorithm>
#include <utility>

#include "http_constants.h"
#include "http_exception.h"
#include "http_header.h"
#include "uri.h"

#include "win_crypt_cert_view.h"
#include "win_http_client.h"

namespace whc::simple
{
    http_request_message make_request_message(std::string_view content_type, const void* data, size_t length, http_header_collection additional_headers)
    {
        additional_headers.emplace_back("Content-Type", content_type);
        additional_headers.emplace_back("Content-Length", std::to_string(length));

        // copy of data
        auto body = std::vector<std::byte>(static_cast<const std::byte*>(data), static_cast<const std::byte*>(data) + length);

        return http_request_message{
            std::move(additional_headers),
            [body = std::move(body), cursor = size_t{}](void* buffer, size_t length) mutable -> size_t
            {
                size_t r = std::min<size_t>(body.size() - cursor, length);
                std::memcpy(buffer, body.data() + cursor, r);
                cursor += r;
                return r;
            }
        };
    }

    http_request_message make_request_message(std::string_view content_type, std::string_view data, http_header_collection additional_headers)
    {
        return make_request_message(content_type, data.data(), data.length(), std::move(additional_headers));
    }

    std::string read_out_response_body_as_string(http_response_message& response, size_t max_size)
    {
        size_t expected_response_body_length = 0;
        if (auto it = response.response_headers.find("Content-Length"); it != response.response_headers.end())
            expected_response_body_length = std::clamp<size_t>(std::strtoll(it->second.c_str(), nullptr, 10), 0, max_size);

        std::string result(expected_response_body_length + 1, '\0');
        size_t cursor = 0;
        while (true)
        {
            size_t r = response.read_response_body(result.data() + cursor, result.size() - cursor);
            cursor += r;
            if (cursor == result.size())
                result.resize(std::min<size_t>(result.size() * 2, max_size));

            if (r == 0) break;
            if (cursor == max_size) break;
        }
        result.resize(cursor);
        return result;
    }

    http_client::http_client(std::string_view user_agent_string)
        : session_handle_(win_http::open_http_session(user_agent_string))
    {
        //
    }

    http_response_message http_client::execute_http_request(uri_view uri, http_method method, const http_request_message& request) const
    {
        // Checks url.
        if (auto& s = uri.scheme; s != "http" && s != "https")
            throw http_exception(http_request_result_code::invalid_url, static_cast<http_request_error_code>(12006));

        // Opens connection
        win_http::http_connection_handle connection_handle = win_http::open_http_connection(session_handle_, uri.hostname, uri.port);

        // Opens request
        win_http::http_request_handle request_handle = win_http::open_http_request(connection_handle, method, uri, win_http::http_request_options{http_versions::AUTO});

        // Sends request
        win_http::send_http_request(request_handle, request.request_headers);

        // Sends request body
        if (request.read_request_body)
        {
            uint64_t request_body_size = ~uint64_t{};
            if (auto it = request.request_headers.find("Content-Length"); it != request.request_headers.end())
                request_body_size = std::atoll(it->second.c_str());

            std::vector<std::byte> buffer(static_cast<size_t>(std::min<uint64_t>(request_body_size, 262144)));
            while (request_body_size)
            {
                size_t to_read = static_cast<size_t>(std::min<uint64_t>(request_body_size, buffer.size()));
                size_t to_send = request.read_request_body(buffer.data(), to_read);
                (void)win_http::write_http_request_body(request_handle, buffer.data(), to_send);
                request_body_size -= to_send;
                if (to_send == 0) break;
            }
        }

        // Receives response
        win_http::http_response_handle response_handle = win_http::receive_http_response(request_handle);

        http_response_message response_message{};
        response_message.http_status_code = win_http::get_http_response_status_code(response_handle);
        response_message.response_headers = win_http::get_http_response_headers(response_handle);
        response_message.read_response_body = [response_handle](void* buffer, size_t length) -> size_t
        {
            return win_http::read_http_response_body(response_handle, buffer, length);
        };

        return response_message;
    }
}
