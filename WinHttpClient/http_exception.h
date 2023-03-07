/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>

namespace whc
{
    /// Represents error category
    enum class http_request_result_code : int
    {
        inprogress = 0,

        ok = 1,

        fault = -32768,
        canceled,
        invalid_url,
        failed_to_setup_session,
        failed_to_setup_connection,
        failed_to_setup_request,
        failed_to_send_request,
        failed_to_receive_response,
        http_status_code_not_ok,
    };

    /// Represents detail error code (native error code from GetLastError())
    enum class http_request_error_code : unsigned long
    {
        none = 0,
        invalid_parameter = 87,
    };

    const char* to_string(http_request_result_code r);
    std::string to_string(http_request_error_code d);
    std::string to_string(http_request_result_code r, http_request_error_code d);

    struct http_exception : std::runtime_error
    {
        http_request_result_code result{};
        http_request_error_code error{};

        http_exception(http_request_result_code result, http_request_error_code error)
            : std::runtime_error(to_string(result, error))
            , result(result)
            , error(error) { }
    };
}
