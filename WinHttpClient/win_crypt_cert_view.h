/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#pragma once

#include <ctime>
#include <string>
#include <array>
#include <functional>
#include <memory>
#include <stdexcept>

#include "./util/transform_iterator.h"

// form wincrypt.h
typedef struct _CERT_INFO CERT_INFO;
typedef struct _CERT_CONTEXT CERT_CONTEXT;
typedef struct _CERT_TRUST_STATUS CERT_TRUST_STATUS;
typedef struct _CERT_REVOCATION_INFO CERT_REVOCATION_INFO;
typedef struct _CERT_CHAIN_ELEMENT CERT_CHAIN_ELEMENT;
typedef struct _CERT_SIMPLE_CHAIN CERT_SIMPLE_CHAIN;
typedef struct _CERT_CHAIN_CONTEXT CERT_CHAIN_CONTEXT;

namespace whc::win_crypt
{
    class certificate_name_view
    {
        const CERT_CONTEXT* certificate{};
        unsigned flag{};

    public:
        certificate_name_view(const CERT_CONTEXT* certificate, unsigned flag);
        [[nodiscard]] std::wstring get_attribute(const char* oid) const;

        [[nodiscard]] std::wstring common_name() const { return get_attribute("2.5.4.3"); }        // CN
        [[nodiscard]] std::wstring country() const { return get_attribute("2.5.4.6"); }            // C
        [[nodiscard]] std::wstring organization() const { return get_attribute("2.5.4.10"); }      // O
        [[nodiscard]] std::wstring organization_unit() const { return get_attribute("2.5.4.11"); } // OU
    };

    // a certificate
    class certificate_view
    {
        const CERT_CONTEXT* certificate{};

    public:
        certificate_view(const CERT_CONTEXT* cert) : certificate{cert} { }
        [[nodiscard]] const CERT_CONTEXT* get_CERT_CONTEXT() const { return certificate; }
        [[nodiscard]] const std::basic_string_view<std::byte> encoded_certificate() const;
        [[nodiscard]] certificate_name_view subject() const;
        [[nodiscard]] certificate_name_view issuer() const;
        [[nodiscard]] std::time_t not_before() const;
        [[nodiscard]] std::time_t not_after() const;
        [[nodiscard]] bool time_valid() const;
        [[nodiscard]] std::array<uint8_t, 16> certificate_md5_hash() const;
        [[nodiscard]] std::array<uint8_t, 20> certificate_sha1_hash() const;
    };

    // a certificate
    class certificate_chain_element_view : private certificate_view
    {
        const CERT_CHAIN_ELEMENT* element{};

    public:
        certificate_chain_element_view(const CERT_CHAIN_ELEMENT* cert);
        [[nodiscard]] const CERT_CHAIN_ELEMENT* get_CERT_CHAIN_ELEMENT() const { return element; }
        [[nodiscard]] bool can_trust() const;
        [[nodiscard]] const CERT_TRUST_STATUS* trust_status() const;
        [[nodiscard]] const CERT_REVOCATION_INFO* revocation_info() const;

        [[nodiscard]] const certificate_view* certificate() const { return this; }
        using certificate_view::get_CERT_CONTEXT;
        using certificate_view::encoded_certificate;
        using certificate_view::subject;
        using certificate_view::issuer;
        using certificate_view::not_before;
        using certificate_view::not_after;
        using certificate_view::time_valid;
        using certificate_view::certificate_md5_hash;
        using certificate_view::certificate_sha1_hash;
    };

    // a chain of certificates
    class certificate_simple_chain_view
    {
        const CERT_SIMPLE_CHAIN* chain{};

    public:
        certificate_simple_chain_view(const CERT_SIMPLE_CHAIN* chain);
        [[nodiscard]] const CERT_SIMPLE_CHAIN* get_CERT_SIMPLE_CHAIN() const { return chain; }
        [[nodiscard]] bool can_trust() const;
        [[nodiscard]] const CERT_TRUST_STATUS* trust_status() const;

        using const_iterator = transform_iterator<const CERT_CHAIN_ELEMENT*, certificate_chain_element_view>;
        [[nodiscard]] size_t size() const noexcept;
        [[nodiscard]] certificate_chain_element_view at(size_t i) const;
        [[nodiscard]] const_iterator begin() const noexcept;
        [[nodiscard]] const_iterator end() const noexcept;
        [[nodiscard]] std::reverse_iterator<const_iterator> rbegin() const noexcept { return std::reverse_iterator{end()}; }
        [[nodiscard]] std::reverse_iterator<const_iterator> rend() const noexcept { return std::reverse_iterator{begin()}; }
    };

    // an array of certificates chains
    class certificate_chain_context_view
    {
        const CERT_CHAIN_CONTEXT* context{};

    public:
        certificate_chain_context_view(const CERT_CHAIN_CONTEXT* chain) : context(chain) { }
        [[nodiscard]] const CERT_CHAIN_CONTEXT* get_CERT_CHAIN_CONTEXT() const { return context; }
        [[nodiscard]] bool can_trust() const;
        [[nodiscard]] const CERT_TRUST_STATUS* trust_status() const;

        using const_iterator = transform_iterator<const CERT_SIMPLE_CHAIN*, certificate_simple_chain_view>;
        [[nodiscard]] size_t size() const noexcept;
        [[nodiscard]] certificate_simple_chain_view at(size_t i) const;
        [[nodiscard]] const_iterator begin() const noexcept;
        [[nodiscard]] const_iterator end() const noexcept;
    };

    std::shared_ptr<certificate_chain_context_view> allocate_chain_context_view_from(std::shared_ptr<const CERT_CONTEXT> cert_context);
}
