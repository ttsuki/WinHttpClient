/// @file
/// @author Copyright (c) 2023 ttsuki
/// This software is released under the MIT License.
#include "win_crypt_cert_view.h"

#include <Windows.h>
#include <wincrypt.h>
#include <chrono>

#include <string>
#include <array>
#include <functional>
#include <memory>
#include <stdexcept>

namespace whc::win_crypt
{
    [[nodiscard]] static std::wstring get_name_string_from_certificate(const CERT_CONTEXT* certificate, DWORD type, DWORD flags, const void* type_para)
    {
        DWORD sz = ::CertGetNameStringW(certificate, type, flags, const_cast<void*>(type_para), nullptr, 0);

        std::wstring ret(sz, L'\0');
        sz = ::CertGetNameStringW(certificate, type, flags, const_cast<void*>(type_para), ret.data(), sz);
        ret.resize(sz - 1);
        return ret;
    }

    [[nodiscard]] std::optional<size_t> get_property_from_certificate(const CERT_CONTEXT* certificate, DWORD id, void* buffer, size_t buffer_length)
    {
        DWORD len = static_cast<DWORD>(buffer_length);
        if (::CertGetCertificateContextProperty(certificate, id, &buffer, &len))
            return static_cast<size_t>(len);
        return std::nullopt;
    }

    template <class T, std::enable_if_t<std::is_trivial_v<T>>* = nullptr>
    [[nodiscard]] std::optional<T> get_property_from_certificate(const CERT_CONTEXT* certificate, DWORD id)
    {
        if (T t{}; whc::win_crypt::get_property_from_certificate(certificate, id, &t, sizeof(t))) return t;
        else return std::nullopt;
    }

    certificate_name_view::certificate_name_view(const CERT_CONTEXT* certificate, unsigned flag): certificate(certificate), flag(flag) {}
    std::wstring certificate_name_view::get_attribute(const char* oid) const { return get_name_string_from_certificate(certificate, CERT_NAME_ATTR_TYPE, flag, oid); }

    const std::basic_string_view<std::byte> certificate_view::encoded_certificate() const { return {reinterpret_cast<const std::byte*>(certificate->pbCertEncoded), certificate->cbCertEncoded}; }
    certificate_name_view certificate_view::subject() const { return certificate_name_view{certificate, 0}; }
    certificate_name_view certificate_view::issuer() const { return certificate_name_view{certificate, CERT_NAME_ISSUER_FLAG}; }
    std::time_t certificate_view::not_before() const { return static_cast<std::time_t>((static_cast<uint64_t>(certificate->pCertInfo->NotBefore.dwHighDateTime) << 32 | certificate->pCertInfo->NotBefore.dwLowDateTime) / 10000000 - 11644473600); }
    std::time_t certificate_view::not_after() const { return static_cast<std::time_t>((static_cast<uint64_t>(certificate->pCertInfo->NotAfter.dwHighDateTime) << 32 | certificate->pCertInfo->NotAfter.dwLowDateTime) / 10000000 - 11644473600); }
    bool certificate_view::time_valid() const { return ::CertVerifyTimeValidity(nullptr, const_cast<CERT_INFO*>(certificate->pCertInfo)) == 0; }
    std::array<uint8_t, 16> certificate_view::certificate_md5_hash() const { return *get_property_from_certificate<std::array<uint8_t, 16>>(certificate, CERT_MD5_HASH_PROP_ID); }
    std::array<uint8_t, 20> certificate_view::certificate_sha1_hash() const { return *get_property_from_certificate<std::array<uint8_t, 20>>(certificate, CERT_SHA1_HASH_PROP_ID); }

    certificate_chain_element_view::certificate_chain_element_view(const CERT_CHAIN_ELEMENT* cert) : certificate_view(cert->pCertContext), element(cert) { }
    bool certificate_chain_element_view::can_trust() const { return element->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR; }
    const CERT_TRUST_STATUS* certificate_chain_element_view::trust_status() const { return &element->TrustStatus; }
    const CERT_REVOCATION_INFO* certificate_chain_element_view::revocation_info() const { return element->pRevocationInfo; }

    certificate_simple_chain_view::certificate_simple_chain_view(const CERT_SIMPLE_CHAIN* chain): chain(chain) { }
    bool certificate_simple_chain_view::can_trust() const { return chain->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR; }
    const CERT_TRUST_STATUS* certificate_simple_chain_view::trust_status() const { return &chain->TrustStatus; }

    size_t certificate_simple_chain_view::size() const noexcept { return chain->cElement; }
    certificate_chain_element_view certificate_simple_chain_view::at(size_t i) const { return i < size() ? certificate_chain_element_view{chain->rgpElement[i]} : throw std::out_of_range("index"); }
    certificate_simple_chain_view::const_iterator certificate_simple_chain_view::begin() const noexcept { return const_iterator{chain->rgpElement + 0}; }
    certificate_simple_chain_view::const_iterator certificate_simple_chain_view::end() const noexcept { return const_iterator{chain->rgpElement + size()}; }

    bool certificate_chain_context_view::can_trust() const { return context->TrustStatus.dwErrorStatus == CERT_TRUST_NO_ERROR; }
    const CERT_TRUST_STATUS* certificate_chain_context_view::trust_status() const { return &context->TrustStatus; }
    size_t certificate_chain_context_view::size() const noexcept { return context ? context->cChain : 0; }
    certificate_simple_chain_view certificate_chain_context_view::at(size_t i) const { return i < size() ? certificate_simple_chain_view{context->rgpChain[i]} : throw std::out_of_range("index"); }
    certificate_chain_context_view::const_iterator certificate_chain_context_view::begin() const noexcept { return context ? const_iterator{context->rgpChain + 0} : const_iterator{nullptr}; }
    certificate_chain_context_view::const_iterator certificate_chain_context_view::end() const noexcept { return context ? const_iterator{context->rgpChain + size()} : const_iterator{nullptr}; }

    std::shared_ptr<certificate_chain_context_view> allocate_chain_context_view_from(std::shared_ptr<const CERT_CONTEXT> cert_context)
    {
        constexpr std::array<const char*, 3> usages = {szOID_PKIX_KP_SERVER_AUTH, szOID_SERVER_GATED_CRYPTO, szOID_SGC_NETSCAPE};
        CERT_CHAIN_PARA chain_para = {};
        chain_para.cbSize = sizeof(CERT_CHAIN_PARA);
        chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
        chain_para.RequestedUsage.Usage.cUsageIdentifier = static_cast<DWORD>(usages.size());
        chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = const_cast<char**>(usages.data());

        if (PCCERT_CHAIN_CONTEXT p = nullptr;
            ::CertGetCertificateChain(
                HCCE_CURRENT_USER,
                cert_context.get(),
                nullptr /* = now */,
                cert_context->hCertStore,
                &chain_para,
                CERT_CHAIN_CACHE_END_CERT,
                nullptr,
                &p) && p)
        {
            std::unique_ptr<const CERT_CHAIN_CONTEXT, decltype(&::CertFreeCertificateChain)> cert_chain_context{p, &::CertFreeCertificateChain};

            auto view = std::make_unique<certificate_chain_context_view>(cert_chain_context.get());
            auto v = view.get();

            return std::shared_ptr<certificate_chain_context_view>{
                v,
                [cert_context = std::move(cert_context), cert_chain_context = std::move(cert_chain_context), view = std::move(view)](auto)
                {
                    (void)view;
                    (void)cert_chain_context;
                    (void)cert_context;
                }
            };
        }
        return nullptr;
    }
}
