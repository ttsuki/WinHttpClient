/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#include "http_exception.h"

#include <Windows.h>
#include <winhttp.h>

namespace whc
{
    const char* to_string(http_request_result_code r)
    {
        switch (r)
        {
        // @formatter:off
#define     HTTP_REQUEST_RESULT_STRING_CASE(v) case http_request_result_code::v: return #v
            HTTP_REQUEST_RESULT_STRING_CASE(inprogress);
            HTTP_REQUEST_RESULT_STRING_CASE(ok);
            HTTP_REQUEST_RESULT_STRING_CASE(fault);
            HTTP_REQUEST_RESULT_STRING_CASE(canceled);
            HTTP_REQUEST_RESULT_STRING_CASE(invalid_url);
            HTTP_REQUEST_RESULT_STRING_CASE(failed_to_setup_session);
            HTTP_REQUEST_RESULT_STRING_CASE(failed_to_setup_connection);
            HTTP_REQUEST_RESULT_STRING_CASE(failed_to_setup_request);
            HTTP_REQUEST_RESULT_STRING_CASE(failed_to_send_request);
            HTTP_REQUEST_RESULT_STRING_CASE(failed_to_receive_response);
            HTTP_REQUEST_RESULT_STRING_CASE(http_status_code_not_ok);
#undef      HTTP_REQUEST_RESULT_STRING_CASE
        // @formatter:on
        }
        return "???";
    }

    std::string to_string(http_request_error_code d)
    {
        std::string s;

        if (d != http_request_error_code{})
        {
            std::string buffer(1024, '\0');
            DWORD c = FormatMessageA(
                FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                GetModuleHandleA("winhttp.dll"),
                static_cast<DWORD>(d),
                MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                NULL);
            buffer.resize(c);
            while (!buffer.empty() && buffer.back() == ' ') buffer.pop_back();

            s.reserve(s.size() + c + 32);
            s += "(";
            s += std::to_string(static_cast<DWORD>(d));
            s += ":";
            s += buffer;
            s += ")";
        }

        return s;
    }

    std::string to_string(http_request_result_code r, http_request_error_code d)
    {
        return to_string(r) + to_string(d);
    }
}
