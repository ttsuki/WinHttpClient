/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#pragma once

#include <cstddef>
#include <iterator>
#include <optional>

namespace whc
{
    template <class source_type, class dest_type>
    struct transform_iterator
    {
        const source_type* pp;
        using value_type = dest_type;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;
        using iterator_category = std::random_access_iterator_tag;
        explicit transform_iterator(const source_type* pp) : pp{pp} {}
        bool operator==(const transform_iterator& other) const { return pp == other.pp; }
        bool operator!=(const transform_iterator& other) const { return pp != other.pp; }
        transform_iterator operator++(int) { return transform_iterator{std::exchange(pp, pp + 1)}; }
        transform_iterator& operator++() { return *this = transform_iterator{pp + 1}; }
        dest_type operator*() const noexcept(noexcept(dest_type(*pp))) { return dest_type(*pp); }
        //std::optional<dest_type> tmp;
        //const dest_type* operator->() const { return &(tmp.emplace(operator*())); }
    };
}
