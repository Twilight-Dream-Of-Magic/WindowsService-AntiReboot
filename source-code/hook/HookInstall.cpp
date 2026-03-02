#include "HookInstall.hpp"

#include <windows.h>
#include <winternl.h>
#include <shellapi.h>
#include <string>
#include <atomic>
#include <vector>

#include "common/SimpleLogger.hpp"
#include "common/StrUtil.hpp"
#include "common/WinPaths.hpp"
#include "common/IniConfig.hpp"
#include "shared/GuardProtocol.hpp"
#include "hook/HookIpcClient.hpp"

#include "MinHook.h"

namespace
{
    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\hook.log");
        return logger;
    }

    bool EqualsIgnoreCase(const std::wstring& left, const wchar_t* right)
    {
        return _wcsicmp(left.c_str(), right) == 0;
    }

    std::wstring BaseNameOrSelf(const std::wstring& pathOrName)
    {
        std::wstring baseName = guard::str::FileNamePart(pathOrName);
        return baseName.empty() ? pathOrName : baseName;
    }

    std::vector<std::wstring> ParseCommandLineArgs(const std::wstring& commandLine)
    {
        std::vector<std::wstring> args;
        if (commandLine.empty()) return args;

        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(commandLine.c_str(), &argc);
        if (!argv || argc <= 0) return args;

        args.reserve(static_cast<size_t>(argc));
        for (int i = 0; i < argc; ++i)
            args.emplace_back(argv[i] ? argv[i] : L"");
        LocalFree(argv);
        return args;
    }

    bool ContainsTokenIgnoreCase(const std::vector<std::wstring>& args, const wchar_t* token)
    {
        for (const auto& arg : args)
        {
            if (!arg.empty() && _wcsicmp(arg.c_str(), token) == 0)
                return true;
        }
        return false;
    }

    bool IsShutdownExecutable(const std::wstring& pathOrName)
    {
        if (pathOrName.empty()) return false;
        const std::wstring baseName = BaseNameOrSelf(pathOrName);
        return EqualsIgnoreCase(baseName, L"shutdown.exe") || EqualsIgnoreCase(baseName, L"shutdown");
    }

    bool IsPowerShellExecutable(const std::wstring& pathOrName)
    {
        if (pathOrName.empty()) return false;
        const std::wstring baseName = BaseNameOrSelf(pathOrName);
        return EqualsIgnoreCase(baseName, L"powershell.exe")
            || EqualsIgnoreCase(baseName, L"powershell")
            || EqualsIgnoreCase(baseName, L"pwsh.exe")
            || EqualsIgnoreCase(baseName, L"pwsh");
    }

    bool HasShutdownActionFlag(const std::vector<std::wstring>& args)
    {
        using namespace guard::proto;
        for (std::size_t i = 0; i < kShutdownishFlagCount; ++i)
        {
            if (ContainsTokenIgnoreCase(args, kShutdownishFlags[i]))
                return true;
        }
        return false;
    }

    std::wstring ToLowerAsciiCopy(std::wstring s)
    {
        for (auto& c : s)
        {
            if (c >= L'A' && c <= L'Z')
                c = static_cast<wchar_t>(c + (L'a' - L'A'));
        }
        return s;
    }

    bool ContainsPowerShellShutdownVerb(const std::wstring& commandLine)
    {
        const std::wstring loweredCommand = ToLowerAsciiCopy(commandLine);
        // Cover common direct restart/shutdown cmdlets used by bypass scripts.
        return (loweredCommand.find(L"restart-computer") != std::wstring::npos)
            || (loweredCommand.find(L"stop-computer") != std::wstring::npos);
    }

    DWORD ResolveHookTimeoutHintMs()
    {
        static std::atomic<DWORD> cachedTimeoutMs{ guard::proto::kDefaultHookTimeoutMs };
        static std::atomic<ULONGLONG> nextRefreshTick{ 0 };

        const ULONGLONG nowTick = GetTickCount64();
        const ULONGLONG refreshTick = nextRefreshTick.load(std::memory_order_relaxed);
        if (nowTick >= refreshTick)
        {
            const std::wstring configPath = guard::paths::ConfigPath();
            DWORD timeoutMs = guard::cfg::ReadIniDword(configPath, L"Behavior", L"HookTimeoutMs", guard::proto::kDefaultHookTimeoutMs);
            if (timeoutMs < guard::proto::kDefaultHookTimeoutMs)
                timeoutMs = guard::proto::kDefaultHookTimeoutMs;
            cachedTimeoutMs.store(timeoutMs, std::memory_order_relaxed);
            nextRefreshTick.store(nowTick + 2'000ULL, std::memory_order_relaxed);
        }

        return cachedTimeoutMs.load(std::memory_order_relaxed);
    }

// Some MinGW/LLVM-mingw headers may not provide SHUTDOWN_ACTION.
#ifndef _SHUTDOWN_ACTION_DEFINED
    typedef enum _SHUTDOWN_ACTION
    {
        ShutdownNoReboot = 0,
        ShutdownReboot = 1,
        ShutdownPowerOff = 2
    } SHUTDOWN_ACTION;
#define _SHUTDOWN_ACTION_DEFINED 1
#endif

    // NtSetSystemPowerState (ntdll, undocumented): power off / sleep / hibernate. MinGW may not have POWER_ACTION/SYSTEM_POWER_STATE.
#ifndef _POWER_ACTION_DEFINED
    typedef enum _POWER_ACTION
    {
        PowerActionNone = 0,
        PowerActionReserved,
        PowerActionSleep,
        PowerActionHibernate,
        PowerActionShutdown,
        PowerActionShutdownReset,
        PowerActionShutdownOff,
        PowerActionWarmEject
    } POWER_ACTION;
#define _POWER_ACTION_DEFINED 1
#endif
#ifndef _SYSTEM_POWER_STATE_DEFINED
    typedef enum _SYSTEM_POWER_STATE
    {
        PowerSystemUnspecified = 0,
        PowerSystemWorking = 1,
        PowerSystemSleeping1 = 2,
        PowerSystemSleeping2 = 3,
        PowerSystemSleeping3 = 4,
        PowerSystemHibernate = 5,
        PowerSystemShutdown = 6,
        PowerSystemMaximum = 7
    } SYSTEM_POWER_STATE;
#define _SYSTEM_POWER_STATE_DEFINED 1
#endif

    using guard::proto::ApiId;
    using guard::proto::GuardRequest;
    using guard::proto::RequestType;

    // Populate common metadata fields for audit & policy decisions.
    // 填入共通字段：用于审计/决策（pid/tid/session/user/process path...）。
    void FillCommon(GuardRequest& request, ApiId api, RequestType type)
    {
        guard::proto::Init(request);
        request.timeoutHintMs = ResolveHookTimeoutHintMs();
        request.apiId = api;
        request.requestType = type;
        request.processId = GetCurrentProcessId();
        request.threadId = GetCurrentThreadId();
        request.sessionId = guard::str::CurrentSessionId();

        std::wstring processPath = guard::str::GetCurrentProcessPath();
        std::wstring imageName = guard::str::FileNamePart(processPath);
        std::wstring userName = guard::str::CurrentUserName();

        wcsncpy_s(request.processPath, processPath.c_str(), _TRUNCATE);
        wcsncpy_s(request.imageName, imageName.c_str(), _TRUNCATE);
        wcsncpy_s(request.userName, userName.c_str(), _TRUNCATE);
    }

    // "shutdown-ish" command detector used only for CreateProcess/ShellExecute pathways.
    // shutdown-ish 侦测只用于 ProcessCreate/ShellExecute 路径；真正的关机 API 走 ShutdownApiCall 直接拦截。
    bool IsShutdownishCommand(const std::wstring& app, const std::wstring& cmdLine)
    {
        // If explicit app points to shutdown.exe, treat as shutdown-ish unless it's an abort.
        if (IsShutdownExecutable(app))
        {
            const auto args = ParseCommandLineArgs(cmdLine);
            if (ContainsTokenIgnoreCase(args, L"/a")) return false;
            return args.empty() ? true : HasShutdownActionFlag(args);
        }

        // If explicit app is powershell/pwsh and command contains restart/stop-computer, treat as shutdown-ish.
        if (IsPowerShellExecutable(app) && ContainsPowerShellShutdownVerb(cmdLine))
            return true;

        // Otherwise parse cmdLine and check first token (exe).
        const auto args = ParseCommandLineArgs(cmdLine);
        if (!args.empty() && IsShutdownExecutable(args[0]))
        {
            if (ContainsTokenIgnoreCase(args, L"/a")) return false;
            return HasShutdownActionFlag(args);
        }

        if (!args.empty() && IsPowerShellExecutable(args[0]) && ContainsPowerShellShutdownVerb(cmdLine))
            return true;

        // Also catch indirection via cmd.exe /c shutdown ... or cmd.exe /c powershell ... Restart-Computer
        if (!args.empty() && EqualsIgnoreCase(guard::str::FileNamePart(args[0]), L"cmd.exe"))
        {
            for (size_t i = 1; i < args.size(); ++i)
            {
                if (IsShutdownExecutable(args[i]))
                {
                    if (ContainsTokenIgnoreCase(args, L"/a")) return false;
                    return HasShutdownActionFlag(args);
                }
                if (IsPowerShellExecutable(args[i]) && ContainsPowerShellShutdownVerb(cmdLine))
                    return true;
            }
        }

        return false;
    }

    // ===== originals =====
    using PFN_ExitWindowsEx = BOOL(WINAPI*)(UINT, DWORD);
    using PFN_InitiateShutdownW = DWORD(WINAPI*)(LPWSTR, LPWSTR, DWORD, DWORD, DWORD);
    using PFN_InitiateShutdownA = DWORD(WINAPI*)(LPSTR, LPSTR, DWORD, DWORD, DWORD);
    using PFN_InitiateSystemShutdownExW = BOOL(WINAPI*)(LPWSTR, LPWSTR, DWORD, BOOL, BOOL, DWORD);
    using PFN_InitiateSystemShutdownExA = BOOL(WINAPI*)(LPSTR, LPSTR, DWORD, BOOL, BOOL, DWORD);
    using PFN_InitiateSystemShutdownW = BOOL(WINAPI*)(LPWSTR, LPWSTR, DWORD, BOOL, BOOL);
    using PFN_InitiateSystemShutdownA = BOOL(WINAPI*)(LPSTR, LPSTR, DWORD, BOOL, BOOL);
    using PFN_NtShutdownSystem = NTSTATUS(NTAPI*)(SHUTDOWN_ACTION);
    using PFN_NtSetSystemPowerState = NTSTATUS(NTAPI*)(POWER_ACTION, SYSTEM_POWER_STATE, ULONG);
    using PFN_SetSuspendState = BOOLEAN(WINAPI*)(BOOLEAN, BOOLEAN, BOOLEAN);
    using PFN_CreateProcessW = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    using PFN_CreateProcessA = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    using PFN_ShellExecuteExW = BOOL(WINAPI*)(SHELLEXECUTEINFOW*);
    using PFN_ShellExecuteExA = BOOL(WINAPI*)(SHELLEXECUTEINFOA*);

    PFN_ExitWindowsEx True_ExitWindowsEx = nullptr;
    PFN_InitiateShutdownW True_InitiateShutdownW = nullptr;
    PFN_InitiateShutdownA True_InitiateShutdownA = nullptr;
    PFN_InitiateSystemShutdownExW True_InitiateSystemShutdownExW = nullptr;
    PFN_InitiateSystemShutdownExA True_InitiateSystemShutdownExA = nullptr;
    PFN_InitiateSystemShutdownW True_InitiateSystemShutdownW = nullptr;
    PFN_InitiateSystemShutdownA True_InitiateSystemShutdownA = nullptr;
    PFN_NtShutdownSystem True_NtShutdownSystem = nullptr;
    PFN_NtSetSystemPowerState True_NtSetSystemPowerState = nullptr;
    PFN_SetSuspendState True_SetSuspendState = nullptr;
    PFN_CreateProcessW True_CreateProcessW = nullptr;
    PFN_CreateProcessA True_CreateProcessA = nullptr;
    PFN_ShellExecuteExW True_ShellExecuteExW = nullptr;
    PFN_ShellExecuteExA True_ShellExecuteExA = nullptr;

    // Track MinHook lifetime to avoid calling disable/uninit when init failed.
    // 追蹤 MinHook 是否初始化成功，避免未初始化就 Remove 造成不穩定。
    std::atomic<bool> g_minHookInitialized{ false };

    // ===== hooks =====
    BOOL WINAPI Hook_ExitWindowsEx(UINT uFlags, DWORD dwReason)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::ExitWindowsEx, RequestType::ShutdownApiCall);
        request.desiredActionFlags = uFlags;

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] ExitWindowsEx msg=" + guard::hook::LastServiceMessage());
            return FALSE;
        }
        return True_ExitWindowsEx(uFlags, dwReason);
    }

    DWORD WINAPI Hook_InitiateShutdownW(LPWSTR machine, LPWSTR message, DWORD grace, DWORD flags, DWORD reason)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::InitiateShutdownW, RequestType::ShutdownApiCall);
        request.desiredActionFlags = flags;
        if (message) wcsncpy_s(request.commandLine, message, _TRUNCATE);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] InitiateShutdownW");
            return ERROR_ACCESS_DENIED;
        }
        return True_InitiateShutdownW(machine, message, grace, flags, reason);
    }

    DWORD WINAPI Hook_InitiateShutdownA(LPSTR machine, LPSTR message, DWORD grace, DWORD flags, DWORD reason)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::InitiateShutdownA, RequestType::ShutdownApiCall);
        request.desiredActionFlags = flags;
        auto wideMessage = guard::str::ToWideFromAnsi(message);
        if (!wideMessage.empty()) wcsncpy_s(request.commandLine, wideMessage.c_str(), _TRUNCATE);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] InitiateShutdownA");
            return ERROR_ACCESS_DENIED;
        }
        return True_InitiateShutdownA(machine, message, grace, flags, reason);
    }

    BOOL WINAPI Hook_InitiateSystemShutdownExW(LPWSTR machine, LPWSTR msg, DWORD timeout, BOOL force, BOOL reboot, DWORD reason)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::InitiateSystemShutdownExW, RequestType::ShutdownApiCall);
        request.desiredActionFlags = (reboot ? 0x1u : 0u) | (force ? 0x2u : 0u);
        if (msg) wcsncpy_s(request.commandLine, msg, _TRUNCATE);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] InitiateSystemShutdownExW");
            return FALSE;
        }
        return True_InitiateSystemShutdownExW(machine, msg, timeout, force, reboot, reason);
    }

    BOOL WINAPI Hook_InitiateSystemShutdownExA(LPSTR machine, LPSTR msg, DWORD timeout, BOOL force, BOOL reboot, DWORD reason)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::InitiateSystemShutdownExA, RequestType::ShutdownApiCall);
        request.desiredActionFlags = (reboot ? 0x1u : 0u) | (force ? 0x2u : 0u);
        auto wideMessage = guard::str::ToWideFromAnsi(msg);
        if (!wideMessage.empty()) wcsncpy_s(request.commandLine, wideMessage.c_str(), _TRUNCATE);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] InitiateSystemShutdownExA");
            return FALSE;
        }
        return True_InitiateSystemShutdownExA(machine, msg, timeout, force, reboot, reason);
    }

    BOOL WINAPI Hook_InitiateSystemShutdownW(LPWSTR machine, LPWSTR msg, DWORD timeout, BOOL force, BOOL reboot)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::InitiateSystemShutdownW, RequestType::ShutdownApiCall);
        request.desiredActionFlags = (reboot ? 0x1u : 0u) | (force ? 0x2u : 0u);
        if (msg) wcsncpy_s(request.commandLine, msg, _TRUNCATE);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] InitiateSystemShutdownW");
            return FALSE;
        }
        return True_InitiateSystemShutdownW(machine, msg, timeout, force, reboot);
    }

    BOOL WINAPI Hook_InitiateSystemShutdownA(LPSTR machine, LPSTR msg, DWORD timeout, BOOL force, BOOL reboot)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::InitiateSystemShutdownA, RequestType::ShutdownApiCall);
        request.desiredActionFlags = (reboot ? 0x1u : 0u) | (force ? 0x2u : 0u);
        auto wideMessage = guard::str::ToWideFromAnsi(msg);
        if (!wideMessage.empty()) wcsncpy_s(request.commandLine, wideMessage.c_str(), _TRUNCATE);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] InitiateSystemShutdownA");
            return FALSE;
        }
        return True_InitiateSystemShutdownA(machine, msg, timeout, force, reboot);
    }

    NTSTATUS NTAPI Hook_NtShutdownSystem(SHUTDOWN_ACTION action)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::NtShutdownSystem, RequestType::ShutdownApiCall);
        request.desiredActionFlags = static_cast<DWORD>(action);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] NtShutdownSystem");
            return static_cast<NTSTATUS>(0xC0000022L); // STATUS_ACCESS_DENIED
        }
        return True_NtShutdownSystem(action);
    }

    NTSTATUS NTAPI Hook_NtSetSystemPowerState(POWER_ACTION systemAction, SYSTEM_POWER_STATE minSystemState, ULONG flags)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::NtSetSystemPowerState, RequestType::ShutdownApiCall);
        request.desiredActionFlags = static_cast<DWORD>(systemAction);

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(L"[BLOCK] NtSetSystemPowerState action=" + std::to_wstring(static_cast<int>(systemAction)));
            return static_cast<NTSTATUS>(0xC0000022L); // STATUS_ACCESS_DENIED
        }
        return True_NtSetSystemPowerState(systemAction, minSystemState, flags);
    }

    BOOLEAN WINAPI Hook_SetSuspendState(BOOLEAN bHibernate, BOOLEAN bForce, BOOLEAN bWakeupEventsDisabled)
    {
        GuardRequest request{};
        FillCommon(request, ApiId::SetSuspendState, RequestType::ShutdownApiCall);
        request.desiredActionFlags = bHibernate ? 0x1u : 0u;

        if (!guard::hook::DecideOrDeny(request))
        {
            Log().Write(bHibernate ? L"[BLOCK] SetSuspendState(hibernate)" : L"[BLOCK] SetSuspendState(sleep)");
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        return True_SetSuspendState(bHibernate, bForce, bWakeupEventsDisabled);
    }

    BOOL WINAPI Hook_CreateProcessW(
        LPCWSTR appName, LPWSTR cmdLine,
        LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
        BOOL inherit, DWORD flags,
        LPVOID env, LPCWSTR cwd,
        LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
    {
        std::wstring applicationName = appName ? appName : L"";
        std::wstring commandLine = cmdLine ? cmdLine : L"";

        if (IsShutdownishCommand(applicationName, commandLine))
        {
            GuardRequest request{};
            FillCommon(request, ApiId::CreateProcessW, RequestType::ProcessCreateAttempt);
            if (!applicationName.empty()) wcsncpy_s(request.imageName, guard::str::FileNamePart(applicationName).c_str(), _TRUNCATE);
            if (!commandLine.empty()) wcsncpy_s(request.commandLine, commandLine.c_str(), _TRUNCATE);
            if (!guard::hook::DecideOrDeny(request))
            {
                Log().Write(L"[BLOCK] CreateProcessW shutdown-ish");
                return FALSE;
            }
        }

        return True_CreateProcessW(appName, cmdLine, pa, ta, inherit, flags, env, cwd, si, pi);
    }

    BOOL WINAPI Hook_CreateProcessA(
        LPCSTR appName, LPSTR cmdLine,
        LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
        BOOL inherit, DWORD flags,
        LPVOID env, LPCSTR cwd,
        LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
    {
        std::wstring applicationName = guard::str::ToWideFromAnsi(appName);
        std::wstring commandLine = guard::str::ToWideFromAnsi(cmdLine);

        if (IsShutdownishCommand(applicationName, commandLine))
        {
            GuardRequest request{};
            FillCommon(request, ApiId::CreateProcessA, RequestType::ProcessCreateAttempt);
            if (!applicationName.empty()) wcsncpy_s(request.imageName, guard::str::FileNamePart(applicationName).c_str(), _TRUNCATE);
            if (!commandLine.empty()) wcsncpy_s(request.commandLine, commandLine.c_str(), _TRUNCATE);
            if (!guard::hook::DecideOrDeny(request))
            {
                Log().Write(L"[BLOCK] CreateProcessA shutdown-ish");
                return FALSE;
            }
        }

        return True_CreateProcessA(appName, cmdLine, pa, ta, inherit, flags, env, cwd, si, pi);
    }

    BOOL WINAPI Hook_ShellExecuteExW(SHELLEXECUTEINFOW* shellExecuteInfo)
    {
        if (shellExecuteInfo)
        {
            std::wstring filePath = shellExecuteInfo->lpFile ? shellExecuteInfo->lpFile : L"";
            std::wstring parameters = shellExecuteInfo->lpParameters ? shellExecuteInfo->lpParameters : L"";
            std::wstring commandLine = filePath + L" " + parameters;

            if (IsShutdownishCommand(filePath, commandLine))
            {
                GuardRequest request{};
                FillCommon(request, ApiId::ShellExecuteExW, RequestType::ShellExecuteAttempt);
                wcsncpy_s(request.imageName, guard::str::FileNamePart(filePath).c_str(), _TRUNCATE);
                wcsncpy_s(request.commandLine, commandLine.c_str(), _TRUNCATE);
                if (!guard::hook::DecideOrDeny(request))
                {
                    Log().Write(L"[BLOCK] ShellExecuteExW shutdown-ish");
                    SetLastError(ERROR_ACCESS_DENIED);
                    return FALSE;
                }
            }
        }
        return True_ShellExecuteExW(shellExecuteInfo);
    }

    BOOL WINAPI Hook_ShellExecuteExA(SHELLEXECUTEINFOA* shellExecuteInfo)
    {
        if (shellExecuteInfo)
        {
            std::wstring filePath = guard::str::ToWideFromAnsi(shellExecuteInfo->lpFile);
            std::wstring parameters = guard::str::ToWideFromAnsi(shellExecuteInfo->lpParameters);
            std::wstring commandLine = filePath + L" " + parameters;

            if (IsShutdownishCommand(filePath, commandLine))
            {
                GuardRequest request{};
                FillCommon(request, ApiId::ShellExecuteExA, RequestType::ShellExecuteAttempt);
                wcsncpy_s(request.imageName, guard::str::FileNamePart(filePath).c_str(), _TRUNCATE);
                wcsncpy_s(request.commandLine, commandLine.c_str(), _TRUNCATE);
                if (!guard::hook::DecideOrDeny(request))
                {
                    Log().Write(L"[BLOCK] ShellExecuteExA shutdown-ish");
                    SetLastError(ERROR_ACCESS_DENIED);
                    return FALSE;
                }
            }
        }
        return True_ShellExecuteExA(shellExecuteInfo);
    }

    template <typename T>
    bool HookOne(LPCWSTR module, LPCSTR proc, T hook, T* original)
    {
        HMODULE moduleHandle = GetModuleHandleW(module);
        if (!moduleHandle) moduleHandle = LoadLibraryW(module);
        if (!moduleHandle) return false;
        FARPROC procAddress = GetProcAddress(moduleHandle, proc);
        if (!procAddress) return false;
        LPVOID target = reinterpret_cast<LPVOID>(procAddress);
        if (MH_CreateHook(target, reinterpret_cast<LPVOID>(hook), reinterpret_cast<LPVOID*>(original)) != MH_OK)
            return false;
        if (MH_EnableHook(target) != MH_OK)
            return false;
        return true;
    }
}

namespace guard::hook
{
    bool InstallHooks()
    {
        guard::paths::EnsureLayout();

        if (MH_Initialize() != MH_OK)
        {
            Log().Write(L"[hook] MH_Initialize failed");
            return false;
        }
        g_minHookInitialized.store(true);

        int hooksInstalledCount = 0;
        hooksInstalledCount += HookOne(L"user32.dll", "ExitWindowsEx", Hook_ExitWindowsEx, &True_ExitWindowsEx) ? 1 : 0;

        hooksInstalledCount += HookOne(L"advapi32.dll", "InitiateShutdownW", Hook_InitiateShutdownW, &True_InitiateShutdownW) ? 1 : 0;
        hooksInstalledCount += HookOne(L"advapi32.dll", "InitiateShutdownA", Hook_InitiateShutdownA, &True_InitiateShutdownA) ? 1 : 0;

        hooksInstalledCount += HookOne(L"advapi32.dll", "InitiateSystemShutdownExW", Hook_InitiateSystemShutdownExW, &True_InitiateSystemShutdownExW) ? 1 : 0;
        hooksInstalledCount += HookOne(L"advapi32.dll", "InitiateSystemShutdownExA", Hook_InitiateSystemShutdownExA, &True_InitiateSystemShutdownExA) ? 1 : 0;

        hooksInstalledCount += HookOne(L"advapi32.dll", "InitiateSystemShutdownW", Hook_InitiateSystemShutdownW, &True_InitiateSystemShutdownW) ? 1 : 0;
        hooksInstalledCount += HookOne(L"advapi32.dll", "InitiateSystemShutdownA", Hook_InitiateSystemShutdownA, &True_InitiateSystemShutdownA) ? 1 : 0;

        hooksInstalledCount += HookOne(L"ntdll.dll", "NtShutdownSystem", Hook_NtShutdownSystem, &True_NtShutdownSystem) ? 1 : 0;
        hooksInstalledCount += HookOne(L"ntdll.dll", "NtSetSystemPowerState", Hook_NtSetSystemPowerState, &True_NtSetSystemPowerState) ? 1 : 0;

        hooksInstalledCount += HookOne(L"powrprof.dll", "SetSuspendState", Hook_SetSuspendState, &True_SetSuspendState) ? 1 : 0;

        hooksInstalledCount += HookOne(L"kernel32.dll", "CreateProcessW", Hook_CreateProcessW, &True_CreateProcessW) ? 1 : 0;
        hooksInstalledCount += HookOne(L"kernel32.dll", "CreateProcessA", Hook_CreateProcessA, &True_CreateProcessA) ? 1 : 0;

        hooksInstalledCount += HookOne(L"shell32.dll", "ShellExecuteExW", Hook_ShellExecuteExW, &True_ShellExecuteExW) ? 1 : 0;
        hooksInstalledCount += HookOne(L"shell32.dll", "ShellExecuteExA", Hook_ShellExecuteExA, &True_ShellExecuteExA) ? 1 : 0;

        Log().Write(L"[hook] installed hooks=" + std::to_wstring(hooksInstalledCount));
        return (hooksInstalledCount > 0);
    }

    void RemoveHooks()
    {
        if (!g_minHookInitialized.exchange(false))
            return;
        // 若 InstallHooks 中 MH_Initialize 成功但所有 HookOne 皆失敗，hooksInstalledCount==0 仍會設 g_minHookInitialized；
        // 此處 MH_DisableHook(MH_ALL_HOOKS) + MH_Uninitialize 依 MinHook 文件為合法，無需額外判斷。
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        // 不在此处写日志：RemoveHooks 常由 DllMain(DLL_PROCESS_DETACH) 调用，此时 loader lock 仍可能被持有，文件 I/O 有死锁/崩溃风险。
    }
}

