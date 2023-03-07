/// @file
/// @author Copyright (c) 2022 ttsuki
/// This software is released under the MIT License.
#pragma once
#include <Windows.h>
#include <tuple>

namespace whc
{
    struct windows_version
    {
        DWORD major;
        DWORD minor;
        DWORD build_number;

        // operator <=>
        auto tie() const noexcept { return std::tie(major, minor, build_number); }
        bool operator ==(const windows_version& rhs) const noexcept { return this->tie() == rhs.tie(); }
        bool operator !=(const windows_version& rhs) const noexcept { return this->tie() != rhs.tie(); }
        bool operator <(const windows_version& rhs) const noexcept { return this->tie() < rhs.tie(); }
        bool operator <=(const windows_version& rhs) const noexcept { return this->tie() <= rhs.tie(); }
        bool operator >(const windows_version& rhs) const noexcept { return this->tie() > rhs.tie(); }
        bool operator >=(const windows_version& rhs) const noexcept { return this->tie() >= rhs.tie(); }

        // gets current version
        [[nodiscard]] static windows_version current()
        {
            static ::RTL_OSVERSIONINFOW v = []
            {
                ::RTL_OSVERSIONINFOW result{};
                result.dwOSVersionInfoSize = static_cast<DWORD>(sizeof(::RTL_OSVERSIONINFOW));

                if (::HMODULE m = ::LoadLibraryW(L"ntdll.dll"))
                {
                    if (auto f = reinterpret_cast<long(__stdcall*)(::PRTL_OSVERSIONINFOW)>(::GetProcAddress(m, "RtlGetVersion")))
                    {
                        f(&result);
                    }
                    ::FreeLibrary(m);
                }
                return result;
            }();

            return windows_version{
                v.dwMajorVersion,
                v.dwMinorVersion,
                v.dwBuildNumber,
            };
        }
    };

    namespace winvers
    {
        constexpr windows_version win7 = {6, 1, 0};
        constexpr windows_version win8 = {6, 2, 0};
        constexpr windows_version win8_1 = {6, 3, 0};
        constexpr windows_version win10_1507 = {10, 0, 10240};
        constexpr windows_version win10_1511 = {10, 0, 10586};
        constexpr windows_version win10_1607 = {10, 0, 14393};
        constexpr windows_version win10_1703 = {10, 0, 15063};
        constexpr windows_version win10_1709 = {10, 0, 16299};
        constexpr windows_version win10_1803 = {10, 0, 17134};
        constexpr windows_version win10_1809 = {10, 0, 17763};
        constexpr windows_version win10_1903 = {10, 0, 18362};
        constexpr windows_version win10_1909 = {10, 0, 18363};
        constexpr windows_version win10_2004 = {10, 0, 19041};
        constexpr windows_version win10_20H2 = {10, 0, 19042};
        constexpr windows_version win10_21H1 = {10, 0, 19043};
        constexpr windows_version win10_21H2 = {10, 0, 19044};
        constexpr windows_version win10_22H2 = {10, 0, 19045};
        constexpr windows_version win11_21H2 = {10, 0, 22000};
        constexpr windows_version win11_22H2 = {10, 0, 22621};
    }
}
