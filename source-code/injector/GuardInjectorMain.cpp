#include <windows.h>
#include <string>
#include <vector>

#include "injector/ProcessUtil.hpp"
#include "common/IniConfig.hpp"
#include "common/SimpleLogger.hpp"
#include "common/WinPaths.hpp"

namespace
{
    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\injector.log");
        return logger;
    }

    std::vector<std::wstring> SplitTargets(const std::wstring& rawTargets)
    {
        std::vector<std::wstring> targets;
        std::wstring currentToken;
        for (wchar_t c : rawTargets)
        {
            if (c == L';' || c == L',' || c == L'|')
            {
                if (!currentToken.empty()) targets.push_back(currentToken);
                currentToken.clear();
            }
            else if (c != L' ' && c != L'\t' && c != L'\r' && c != L'\n')
            {
                currentToken.push_back(c);
            }
        }
        if (!currentToken.empty()) targets.push_back(currentToken);
        return targets;
    }

    std::wstring CurrentExeDir()
    {
        wchar_t pathBuffer[MAX_PATH] = {};
        DWORD pathLength = GetModuleFileNameW(nullptr, pathBuffer, MAX_PATH);
        std::wstring pathString = (pathLength > 0) ? std::wstring(pathBuffer, pathLength) : L"";
        size_t pos = pathString.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? L"." : pathString.substr(0, pos);
    }

    std::wstring DefaultDllPath()
    {
        return CurrentExeDir() + L"\\ShutdownGuardHook.dll";
    }

    std::wstring UnquoteWrapped(std::wstring s)
    {
        if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"')
            return s.substr(1, s.size() - 2);
        return s;
    }
}

int wmain(int argc, wchar_t** argv)
{
    guard::paths::EnsureLayout();
    guard::inject::EnablePrivilege(SE_DEBUG_NAME);

    std::wstring dllPath;
    std::wstring rawTargets;
    DWORD targetPid = 0;

    for (int i = 1; i < argc; ++i)
    {
        std::wstring argument = argv[i];
        if (argument == L"--dll" && i + 1 < argc) dllPath = UnquoteWrapped(argv[++i]);
        else if (argument == L"--targets" && i + 1 < argc) rawTargets = UnquoteWrapped(argv[++i]);
        else if (argument == L"--pid" && i + 1 < argc) targetPid = static_cast<DWORD>(_wtoi(argv[++i]));
    }

    const std::wstring configFilePath = guard::paths::ConfigPath();
    if (dllPath.empty())
        dllPath = UnquoteWrapped(guard::cfg::ReadIniString(configFilePath, L"Injection", L"DllPath", DefaultDllPath().c_str()));
    if (rawTargets.empty())
        rawTargets = UnquoteWrapped(guard::cfg::ReadIniString(configFilePath, L"Injection", L"Targets", L"explorer.exe;cmd.exe;powershell.exe;pwsh.exe;shutdown.exe;schtasks.exe;WmiPrvSE.exe;RuntimeBroker.exe;rundll32.exe"));

    DWORD fileAttributes = GetFileAttributesW(dllPath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES)
    {
        Log().Write(L"[injector] dll not found: " + dllPath);
        return 2;
    }

    if (targetPid != 0)
    {
        DWORD lastError = 0;
        bool success = guard::inject::InjectLoadLibraryW(targetPid, dllPath, lastError);
        Log().Write(success ? L"[injector] injected pid=" + std::to_wstring(targetPid) : L"[injector] inject failed pid=" + std::to_wstring(targetPid) + L" err=" + std::to_wstring(lastError));
        return success ? 0 : 1;
    }

    auto targets = SplitTargets(rawTargets);
    int failures = 0;

    for (const auto& targetImageName : targets)
    {
        auto pids = guard::inject::FindPidsByImageName(targetImageName);
        for (DWORD processId : pids)
        {
            if (processId == GetCurrentProcessId()) continue;
            DWORD lastError = 0;
            bool success = guard::inject::InjectLoadLibraryW(processId, dllPath, lastError);
            if (!success) failures++;
            Log().Write(success ? L"[injector] injected " + targetImageName + L" pid=" + std::to_wstring(processId)
                           : L"[injector] inject failed " + targetImageName + L" pid=" + std::to_wstring(processId) + L" err=" + std::to_wstring(lastError));
        }
    }

    // Return failures count (clamped) for more actionable automation.
    if (failures <= 0) return 0;
    return (failures > 250) ? 250 : failures;
}

// Some toolchains default to GUI subsystem and require a WinMain entry point.
// Delegate to wmain to keep a single argument-parsing implementation.
int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    return wmain(__argc, __wargv);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR, int nCmdShow)
{
    return wWinMain(hInst, hPrev, nullptr, nCmdShow);
}

