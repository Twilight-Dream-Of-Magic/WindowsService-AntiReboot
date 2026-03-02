#pragma once
#include <windows.h>
#include <string>
#include <algorithm>
#include <cwctype>
#include <vector>

namespace guard::str
{
    inline std::wstring ToLower(std::wstring s)
    {
        std::transform(s.begin(), s.end(), s.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
        return s;
    }

    inline bool ContainsInsensitive(const std::wstring& haystack, const std::wstring& needle)
    {
        return ToLower(haystack).find(ToLower(needle)) != std::wstring::npos;
    }

    inline std::wstring ToWideFromAnsi(const char* s)
    {
        if (!s) return L"";

        auto convert = [&](UINT cp, DWORD flags) -> std::wstring {
            int len = MultiByteToWideChar(cp, flags, s, -1, nullptr, 0);
            if (len <= 0) return L"";
            std::wstring out(static_cast<size_t>(len), L'\0');
            if (MultiByteToWideChar(cp, flags, s, -1, out.data(), len) <= 0) return L"";
            if (!out.empty() && out.back() == L'\0') out.pop_back();
            return out;
        };

        // Prefer UTF-8 when the input is valid UTF-8; otherwise fall back to the system ACP.
        std::wstring out = convert(CP_UTF8, MB_ERR_INVALID_CHARS);
        if (out.empty())
            out = convert(CP_ACP, 0);
        if (!out.empty() && out.back() == L'\0') out.pop_back();
        return out;
    }

    inline std::wstring GetModulePath(HMODULE module)
    {
        // Support paths longer than MAX_PATH (best-effort).
        std::vector<wchar_t> buf(512);
        for (;;)
        {
            DWORD n = GetModuleFileNameW(module, buf.data(), static_cast<DWORD>(buf.size()));
            if (n == 0) return L"";
            if (n < buf.size() - 1)
                return std::wstring(buf.data(), n);
            buf.resize(buf.size() * 2);
            if (buf.size() > 32768)
                return std::wstring(buf.data(), n);
        }
    }

    inline std::wstring GetCurrentProcessPath()
    {
        return GetModulePath(nullptr);
    }

    inline std::wstring FileNamePart(const std::wstring& path)
    {
        size_t pos = path.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    }

    inline DWORD CurrentSessionId()
    {
        DWORD sid = 0;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &sid))
            return 0;
        return sid;
    }

    inline std::wstring CurrentUserName()
    {
        DWORD sz = 0;
        GetUserNameW(nullptr, &sz);
        if (sz == 0) sz = 256;
        std::vector<wchar_t> buf(sz);
        if (GetUserNameW(buf.data(), &sz))
        {
            if (sz > 0 && buf[sz - 1] == L'\0') sz--;
            return std::wstring(buf.data(), sz);
        }
        return L"";
    }
}

