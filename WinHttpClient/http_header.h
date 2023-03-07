/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <algorithm>

namespace whc
{
    using http_header_key = std::string;
    using http_header_value = std::string;
    using http_header_line = std::pair<http_header_key, http_header_value>;

    class http_header_collection final : std::vector<http_header_line>
    {
    public:
        using base_container_type = std::vector<http_header_line>;
        using base_container_type::value_type;
        using base_container_type::size_type;
        using base_container_type::difference_type;
        using base_container_type::allocator_type;
        using base_container_type::reference;
        using base_container_type::pointer;
        using base_container_type::iterator;
        using base_container_type::const_reference;
        using base_container_type::const_pointer;
        using base_container_type::const_iterator;

        http_header_collection() = default;
        http_header_collection(const http_header_collection& other) = default;
        http_header_collection(http_header_collection&& other) noexcept = default;
        http_header_collection& operator=(const http_header_collection& other) = default;
        http_header_collection& operator=(http_header_collection&& other) noexcept = default;
        ~http_header_collection() = default;

        using base_container_type::vector;
        using base_container_type::assign;
        using base_container_type::at;
        using base_container_type::operator[];
        using base_container_type::front;
        using base_container_type::back;
        using base_container_type::data;
        using base_container_type::begin;
        using base_container_type::end;
        using base_container_type::empty;
        using base_container_type::reserve;
        using base_container_type::shrink_to_fit;
        using base_container_type::size;
        using base_container_type::clear;
        using base_container_type::insert;
        using base_container_type::emplace;
        using base_container_type::erase;
        using base_container_type::push_back;
        using base_container_type::emplace_back;
        using base_container_type::pop_back;

        [[nodiscard]] iterator find(std::string_view key)
        {
            return std::find_if(begin(), end(), [key](const_reference line) { return line.first == key; });
        }

        [[nodiscard]] const_iterator find(std::string_view key) const
        {
            return std::find_if(begin(), end(), [key](const_reference line) { return line.first == key; });
        }

        [[nodiscard]] std::string to_http_header_string() const
        {
            size_t expected_total_length{};
            for (const auto& [k, v] : *this) expected_total_length += k.size() + 2 + v.size() + 2;

            std::string result{};
            result.reserve(expected_total_length);
            for (const auto& [k, v] : *this) result.append(k).append(": ").append(v).append("\r\n");

            return result;
        }
    };
}
