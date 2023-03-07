/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <string>
#include <string_view>

namespace whc
{
    static inline std::wstring to_wstring(std::string_view src)
    {
        return std::wstring{src.begin(), src.end()};
    }
}
