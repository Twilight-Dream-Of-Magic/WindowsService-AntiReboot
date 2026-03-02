#pragma once
#include <windows.h>
#include <shlobj.h>
#include <string>

namespace guard::paths
{
    inline std::wstring ProgramDataDir()
    {
        wchar_t buf[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, buf)))
            return std::wstring(buf);
        DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, static_cast<DWORD>(std::size(buf)));
        if (n > 0 && n < std::size(buf))
            return std::wstring(buf, n);
        return L"C:\\ProgramData";
    }

    inline std::wstring RootDir()
    {
        return ProgramDataDir() + L"\\ShutdownGuard";
    }

    inline std::wstring LogsDir()
    {
        return RootDir() + L"\\logs";
    }

    inline std::wstring ConfigPath()
    {
        return RootDir() + L"\\guard.ini";
    }

    inline bool EnsureDir(const std::wstring& dir)
    {
        if (dir.empty()) return false;
        if (CreateDirectoryW(dir.c_str(), nullptr))
            return true;
        DWORD err = GetLastError();
        return (err == ERROR_ALREADY_EXISTS);
    }

    inline void EnsureLayout()
    {
        EnsureDir(RootDir());
        EnsureDir(LogsDir());
    }
}

