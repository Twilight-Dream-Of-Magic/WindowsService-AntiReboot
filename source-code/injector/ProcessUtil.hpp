#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace guard::inject
{
    bool EnablePrivilege(const wchar_t* privName);
    std::vector<DWORD> FindPidsByImageName(const std::wstring& imageName);
    bool InjectLoadLibraryW(DWORD pid, const std::wstring& dllPath, DWORD& outWin32Error);
}

