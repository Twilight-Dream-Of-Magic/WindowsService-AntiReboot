#include <windows.h>
#include <atomic>
#include <string>
#include <vector>
#include <iostream>
#include <optional>
#include <thread>
#include <tlhelp32.h>
#include <fstream>
#include <cstring>

#include <wtsapi32.h>
#include <userenv.h>
#include <shlobj.h>
#include <sddl.h>
#include <wincred.h>

#include <accctrl.h>
#include <aclapi.h>

#include "service/GuardPipeServer.hpp"
#include "service/GuardProcessWatcher.hpp"
#include "common/SimpleLogger.hpp"
#include "common/WinPaths.hpp"
#include "common/IniConfig.hpp"

namespace
{
    constexpr wchar_t kServiceName[] = L"ShutdownGuard";
    constexpr wchar_t kTaskUiName[] = L"ShutdownGuard\\UI";
    constexpr wchar_t kTaskInjectorName[] = L"ShutdownGuard\\Injector";
    constexpr DWORD kCtrlPrepareUninstallStopWatcher = 129;

    // Service-wide state (globals kept minimal; Windows SCM callbacks are C-style).
    // 服务全局状态（Windows SCM 回调偏 C 风格，这里保持最小集合）
    guard::service::GuardPipeServer* g_pipeServer = nullptr;
    SERVICE_STATUS_HANDLE g_serviceStatusHandle = nullptr;
    SERVICE_STATUS g_serviceStatus{};

    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\service_main.log");
        return logger;
    }

    void SetStatus(DWORD state, DWORD win32ExitCode = NO_ERROR, DWORD waitHintMs = 0);

    // (uninstall/cleanup helpers removed; this project no longer exposes uninstall capability in the service binary)

    bool IsElevated()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            return false;
        TOKEN_ELEVATION elev{};
        DWORD returnedLength = 0;
        BOOL success = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &returnedLength);
        CloseHandle(token);
        return success && elev.TokenIsElevated;
    }

    std::wstring GetExePath()
    {
        wchar_t pathBuffer[MAX_PATH] = {};
        DWORD pathLength = GetModuleFileNameW(nullptr, pathBuffer, MAX_PATH);
        return (pathLength > 0) ? std::wstring(pathBuffer, pathLength) : L"";
    }

    std::wstring ExeDir()
    {
        std::wstring p = GetExePath();
        size_t pos = p.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
    }

    std::wstring JoinPath(const std::wstring& dir, const std::wstring& name)
    {
        if (dir.empty()) return name;
        if (dir.back() == L'\\' || dir.back() == L'/') return dir + name;
        return dir + L"\\" + name;
    }

    std::wstring DefaultInstallDir()
    {
        wchar_t pathBuffer[MAX_PATH] = {};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, SHGFP_TYPE_CURRENT, pathBuffer)))
            return std::wstring(pathBuffer) + L"\\ShutdownGuard";
        return L"C:\\Program Files\\ShutdownGuard";
    }

    bool EnsureDir(const std::wstring& dir)
    {
        if (dir.empty()) return false;
        if (CreateDirectoryW(dir.c_str(), nullptr))
            return true;
        DWORD lastError = GetLastError();
        return (lastError == ERROR_ALREADY_EXISTS);
    }

    bool ApplyInstallDirAclUnlocked(const std::wstring& dir)
    {
        // Unlocked = Administrators can operate/delete.
        if (dir.empty()) 
            return false;

        PSID sidSystem = nullptr;
        PSID sidAdmins = nullptr;
        PSID sidAuthUsers = nullptr;

        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY builtinAuth = SECURITY_NT_AUTHORITY;

        if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &sidSystem))
            return false;

        if (!AllocateAndInitializeSid(&builtinAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &sidAdmins))
        {
            FreeSid(sidSystem);
            return false;
        }

        if (!AllocateAndInitializeSid(&ntAuth, 1, SECURITY_AUTHENTICATED_USER_RID, 0, 0, 0, 0, 0, 0, 0, &sidAuthUsers))
        {
            FreeSid(sidAdmins);
            FreeSid(sidSystem);
            return false;
        }

        EXPLICIT_ACCESSW explicitAccessEntries[3]{};

        explicitAccessEntries[0].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[0].grfAccessMode = SET_ACCESS;
        explicitAccessEntries[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        explicitAccessEntries[0].Trustee.ptstrName = static_cast<LPWSTR>(sidSystem);

        explicitAccessEntries[1].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[1].grfAccessMode = SET_ACCESS;
        explicitAccessEntries[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[1].Trustee.ptstrName = static_cast<LPWSTR>(sidAdmins);

        explicitAccessEntries[2].grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE;
        explicitAccessEntries[2].grfAccessMode = SET_ACCESS;
        explicitAccessEntries[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[2].Trustee.ptstrName = static_cast<LPWSTR>(sidAuthUsers);

        PACL newDacl = nullptr;
        DWORD aclResult = SetEntriesInAclW(static_cast<ULONG>(std::size(explicitAccessEntries)), explicitAccessEntries, nullptr, &newDacl);

        FreeSid(sidAuthUsers);
        FreeSid(sidAdmins);
        FreeSid(sidSystem);

        if (aclResult != ERROR_SUCCESS || !newDacl)
            return false;

        // Protect DACL to stop inheriting stale denies.
        DWORD setSecurityResult = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(dir.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr,
            newDacl,
            nullptr
        );

        LocalFree(newDacl);
        return (setSecurityResult == ERROR_SUCCESS);
    }

    bool ApplyInstallDirAclLocked(const std::wstring& dir)
    {
        // Locked = Administrators can't delete or change ACL/owner. SYSTEM can.
        // Also deny normal Users write/delete.
        if (dir.empty()) return false;

        PSID adminsSid = nullptr;
        PSID systemSid = nullptr;
        PSID usersSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

        // BUILTIN\Administrators
        if (!AllocateAndInitializeSid(&ntAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0, &adminsSid))
            return false;

        // NT AUTHORITY\SYSTEM
        if (!AllocateAndInitializeSid(&ntAuth, 1,
                SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0, &systemSid))
        {
            FreeSid(adminsSid);
            return false;
        }

        // BUILTIN\Users
        if (!AllocateAndInitializeSid(&ntAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
                0, 0, 0, 0, 0, 0, &usersSid))
        {
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        // 4 ACEs: deny Users write/delete, deny Admins delete/WRITE_DAC/WRITE_OWNER,
        // allow Admins read+execute, allow SYSTEM full.
        EXPLICIT_ACCESSW explicitAccessEntries[4] = {};

        explicitAccessEntries[0].grfAccessMode = DENY_ACCESS;
        explicitAccessEntries[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[0].grfAccessPermissions =
            DELETE |
            FILE_DELETE_CHILD |
            FILE_WRITE_DATA |
            FILE_APPEND_DATA |
            FILE_WRITE_EA |
            FILE_WRITE_ATTRIBUTES |
            FILE_ADD_FILE |
            FILE_ADD_SUBDIRECTORY;
        explicitAccessEntries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[0].Trustee.ptstrName = (LPWSTR)usersSid;

        explicitAccessEntries[1].grfAccessMode = DENY_ACCESS;
        explicitAccessEntries[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[1].grfAccessPermissions =
            DELETE |
            FILE_DELETE_CHILD |
            WRITE_DAC |
            WRITE_OWNER;
        explicitAccessEntries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[1].Trustee.ptstrName = (LPWSTR)adminsSid;

        explicitAccessEntries[2].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[2].grfAccessPermissions =
            FILE_GENERIC_READ |
            FILE_GENERIC_EXECUTE |
            SYNCHRONIZE |
            READ_CONTROL;
        explicitAccessEntries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[2].Trustee.ptstrName = (LPWSTR)adminsSid;

        explicitAccessEntries[3].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[3].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[3].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[3].Trustee.TrusteeType = TRUSTEE_IS_USER;
        explicitAccessEntries[3].Trustee.ptstrName = (LPWSTR)systemSid;

        PACL newDacl = nullptr;
        // Build ACL from the policy ACE list only, to avoid carrying stale permissive entries.
        DWORD aclResult = SetEntriesInAclW(static_cast<ULONG>(std::size(explicitAccessEntries)), explicitAccessEntries, nullptr, &newDacl);
        if (aclResult != ERROR_SUCCESS || !newDacl)
        {
            FreeSid(usersSid);
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        DWORD setResult = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(dir.c_str()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            systemSid,
            nullptr,
            newDacl,
            nullptr
        );

        if (setResult == ERROR_ACCESS_DENIED || setResult == ERROR_PRIVILEGE_NOT_HELD)
        {
            // Keep the DACL protection even when owner transfer is not permitted in current context.
            setResult = SetNamedSecurityInfoW(
                const_cast<LPWSTR>(dir.c_str()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                newDacl,
                nullptr
            );
        }

        LocalFree(newDacl);
        FreeSid(usersSid);
        FreeSid(systemSid);
        FreeSid(adminsSid);
        return setResult == ERROR_SUCCESS;
    }

    bool CopyFileIfExists(const std::wstring& src, const std::wstring& dst)
    {
        DWORD attr = GetFileAttributesW(src.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
            return false;
        return CopyFileW(src.c_str(), dst.c_str(), FALSE) != FALSE;
    }

    bool InstallFilesToDir(const std::wstring& installDir, std::wstring& outServiceExePath)
    {
        if (!EnsureDir(installDir))
            return false;

        const std::wstring srcDir = ExeDir();
        const std::wstring srcService = JoinPath(srcDir, L"ShutdownGuard.exe");
        const std::wstring srcUi = JoinPath(srcDir, L"ShutdownGuardUI.exe");
        const std::wstring srcInjector = JoinPath(srcDir, L"ShutdownGuardInjector.exe");
        const std::wstring srcHook = JoinPath(srcDir, L"ShutdownGuardHook.dll");

        const std::wstring dstService = JoinPath(installDir, L"ShutdownGuard.exe");
        const std::wstring dstUi = JoinPath(installDir, L"ShutdownGuardUI.exe");
        const std::wstring dstInjector = JoinPath(installDir, L"ShutdownGuardInjector.exe");
        const std::wstring dstHook = JoinPath(installDir, L"ShutdownGuardHook.dll");

        // If already running from install dir, skip self copy but still ensure sidecars.
        const std::wstring self = GetExePath();
        if (_wcsicmp(self.c_str(), dstService.c_str()) != 0)
        {
            if (!CopyFileIfExists(srcService, dstService))
                return false;
        }

        CopyFileIfExists(srcUi, dstUi);
        CopyFileIfExists(srcInjector, dstInjector);
        CopyFileIfExists(srcHook, dstHook);

        // Install defaults to locked ACL (Admins can't delete/override ACL; SYSTEM can).
        if (!ApplyInstallDirAclLocked(installDir))
        {
            Log().Write(L"[install] failed to apply locked ACL: " + installDir);
            return false;
        }

        outServiceExePath = dstService;
        return true;
    }

    bool SetRunKey(const wchar_t* valueName, const std::wstring& commandLine)
    {
        HKEY registryKey = nullptr;
        DWORD disposition = 0;
        LONG registryStatus = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, nullptr, 0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            nullptr,
            &registryKey,
            &disposition
        );
        if (registryStatus != ERROR_SUCCESS) return false;

        registryStatus = RegSetValueExW(
            registryKey,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(commandLine.c_str()),
            static_cast<DWORD>((commandLine.size() + 1) * sizeof(wchar_t))
        );
        RegCloseKey(registryKey);
        return (registryStatus == ERROR_SUCCESS);
    }

    void DeleteRunKey(const wchar_t* valueName)
    {
        HKEY registryKey = nullptr;
        LONG registryStatus = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            KEY_SET_VALUE | KEY_WOW64_64KEY,
            &registryKey
        );
        if (registryStatus != ERROR_SUCCESS) return;
        RegDeleteValueW(registryKey, valueName);
        RegCloseKey(registryKey);
    }

    bool RunSchtasksCommand(const std::wstring& args, DWORD timeoutMs, DWORD& outExitCode)
    {
        outExitCode = static_cast<DWORD>(-1);
        std::wstring commandLine = L"cmd.exe /c schtasks " + args;
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};

        BOOL ok = CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr, nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr, nullptr,
            &startupInfo,
            &processInfo
        );
        if (!ok)
            return false;

        DWORD waitResult = WaitForSingleObject(processInfo.hProcess, timeoutMs);
        if (waitResult == WAIT_OBJECT_0)
            GetExitCodeProcess(processInfo.hProcess, &outExitCode);
        else
            TerminateProcess(processInfo.hProcess, 1);

        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return waitResult == WAIT_OBJECT_0;
    }

    void SetLogonTasksEnabledBestEffort(bool enabled)
    {
        const std::wstring action = enabled ? L"/ENABLE" : L"/DISABLE";
        DWORD uiExitCode = static_cast<DWORD>(-1);
        DWORD injectorExitCode = static_cast<DWORD>(-1);

        const bool uiOk = RunSchtasksCommand(
            L"/Change /TN \"" + std::wstring(kTaskUiName) + L"\" " + action,
            30'000,
            uiExitCode);
        const bool injectorOk = RunSchtasksCommand(
            L"/Change /TN \"" + std::wstring(kTaskInjectorName) + L"\" " + action,
            30'000,
            injectorExitCode);

        Log().Write(
            std::wstring(L"[helper-startup] schtasks ")
            + (enabled ? L"enable " : L"disable ")
            + L"UI(ok=" + std::to_wstring(uiOk ? 1 : 0) + L", exit=" + std::to_wstring(uiExitCode)
            + L") Injector(ok=" + std::to_wstring(injectorOk ? 1 : 0) + L", exit=" + std::to_wstring(injectorExitCode) + L")");
    }

    void SetGuardHelperStartupEntriesBestEffort(bool enabled, const std::wstring& installDir)
    {
        if (enabled)
        {
            const std::wstring uiPath = JoinPath(installDir.empty() ? ExeDir() : installDir, L"ShutdownGuardUI.exe");
            const std::wstring injectorPath = JoinPath(installDir.empty() ? ExeDir() : installDir, L"ShutdownGuardInjector.exe");
            const bool uiRunKeyOk = SetRunKey(L"ShutdownGuardUI", L"\"" + uiPath + L"\"");
            const bool injectorRunKeyOk = SetRunKey(L"ShutdownGuardInjector", L"\"" + injectorPath + L"\"");
            Log().Write(L"[helper-startup] set run key UI=" + std::to_wstring(uiRunKeyOk ? 1 : 0)
                + L" Injector=" + std::to_wstring(injectorRunKeyOk ? 1 : 0));
        }
        else
        {
            DeleteRunKey(L"ShutdownGuardUI");
            DeleteRunKey(L"ShutdownGuardInjector");
            Log().Write(L"[helper-startup] deleted run key UI/Injector");
        }

        // Logon tasks may or may not exist depending on installer path/version. Keep best-effort.
        SetLogonTasksEnabledBestEffort(enabled);
    }

    void TerminateGuardHelperProcessesBestEffort()
    {
        constexpr const wchar_t* kNames[] = { L"ShutdownGuardUI.exe", L"ShutdownGuardInjector.exe" };
        const DWORD selfProcessId = GetCurrentProcessId();

        HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (processSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            Log().Write(L"[helper-stop] snapshot failed err=" + std::to_wstring(GetLastError()));
            return;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (!Process32FirstW(processSnapshotHandle, &processEntry))
        {
            CloseHandle(processSnapshotHandle);
            return;
        }

        do
        {
            if (processEntry.th32ProcessID == selfProcessId)
                continue;

            bool target = false;
            for (const wchar_t* name : kNames)
            {
                if (_wcsicmp(processEntry.szExeFile, name) == 0)
                {
                    target = true;
                    break;
                }
            }
            if (!target)
                continue;

            HANDLE processHandle = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, processEntry.th32ProcessID);
            if (!processHandle)
            {
                Log().Write(L"[helper-stop] OpenProcess failed pid=" + std::to_wstring(processEntry.th32ProcessID)
                    + L" err=" + std::to_wstring(GetLastError()));
                continue;
            }

            if (!TerminateProcess(processHandle, 0))
            {
                Log().Write(L"[helper-stop] TerminateProcess failed pid=" + std::to_wstring(processEntry.th32ProcessID)
                    + L" err=" + std::to_wstring(GetLastError()));
            }
            else
            {
                WaitForSingleObject(processHandle, 3000);
                Log().Write(L"[helper-stop] terminated " + std::wstring(processEntry.szExeFile)
                    + L" pid=" + std::to_wstring(processEntry.th32ProcessID));
            }

            CloseHandle(processHandle);
        } while (Process32NextW(processSnapshotHandle, &processEntry));

        CloseHandle(processSnapshotHandle);
    }

    bool IsProcessRunningInSession(const std::wstring& imageName, DWORD sessionId)
    {
        HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (processSnapshotHandle == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        bool found = false;
        if (Process32FirstW(processSnapshotHandle, &processEntry))
        {
            do
            {
                if (_wcsicmp(processEntry.szExeFile, imageName.c_str()) == 0)
                {
                    DWORD sid = 0xFFFFFFFF;
                    if (ProcessIdToSessionId(processEntry.th32ProcessID, &sid) && sid == sessionId)
                    {
                        found = true;
                        break;
                    }
                }
            } while (Process32NextW(processSnapshotHandle, &processEntry));
        }

        CloseHandle(processSnapshotHandle);
        return found;
    }

    bool LaunchInSession(DWORD sessionId, const std::wstring& exePath, const std::wstring& args, bool visible)
    {
        HANDLE userTokenHandle = nullptr;
        if (!WTSQueryUserToken(sessionId, &userTokenHandle) || !userTokenHandle)
            return false;

        HANDLE primaryTokenHandle = nullptr;
        BOOL success = DuplicateTokenEx(
            userTokenHandle,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primaryTokenHandle
        );
        CloseHandle(userTokenHandle);
        if (!success || !primaryTokenHandle)
            return false;

        LPVOID env = nullptr;
        if (!CreateEnvironmentBlock(&env, primaryTokenHandle, FALSE))
            env = nullptr;

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = visible ? SW_SHOWNORMAL : SW_HIDE;

        PROCESS_INFORMATION pi{};

        std::wstring cmd = L"\"" + exePath + L"\"";
        if (!args.empty())
            cmd += L" " + args;

        DWORD flags = CREATE_UNICODE_ENVIRONMENT;
        if (!visible) flags |= CREATE_NO_WINDOW;

        success = CreateProcessAsUserW(
            primaryTokenHandle,
            nullptr,
            cmd.data(),
            nullptr,
            nullptr,
            FALSE,
            flags,
            env,
            nullptr,
            &si,
            &pi
        );

        if (env) DestroyEnvironmentBlock(env);
        CloseHandle(primaryTokenHandle);

        if (!success)
            return false;

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    bool LaunchAsServiceAccount(const std::wstring& exePath, const std::wstring& args, bool visible)
    {
        std::wstring cmd = L"\"" + exePath + L"\"";
        if (!args.empty())
            cmd += L" " + args;

        std::vector<wchar_t> cmdLine(cmd.begin(), cmd.end());
        cmdLine.push_back(L'\0');

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = visible ? SW_SHOWNORMAL : SW_HIDE;

        PROCESS_INFORMATION pi{};
        DWORD flags = visible ? 0 : CREATE_NO_WINDOW;
        BOOL ok = CreateProcessW(
            exePath.c_str(),
            cmdLine.data(),
            nullptr,
            nullptr,
            FALSE,
            flags,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        if (!ok)
            return false;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }

    // Watchdog responsibility boundary:
    // 1) keep helper processes alive (UI/Injector),
    // 2) do NOT make allow/deny policy decisions,
    // 3) do NOT bypass pipe arbitration.
    // Policy always belongs to GuardPipeServer so behavior stays consistent/auditable.
    void WatchdogLoop()
    {
        guard::paths::EnsureLayout();
        const std::wstring configPath = guard::paths::ConfigPath();

        const std::wstring uiExecutablePath = JoinPath(ExeDir(), L"ShutdownGuardUI.exe");
        const std::wstring injectorExecutablePath = JoinPath(ExeDir(), L"ShutdownGuardInjector.exe");

        ULONGLONG lastInjectorTick = 0;
        ULONGLONG uiRestartWindowStartTick = 0;
        DWORD uiStartsInRestartWindow = 0;
        ULONGLONG uiRestartCooldownUntilTick = 0;
        ULONGLONG injectorCooldownUntilTick = 0;

        while (g_serviceStatus.dwCurrentState == SERVICE_RUNNING)
        {
            DWORD enabled = guard::cfg::ReadIniDword(configPath, L"Watchdog", L"Enabled", 1);
            DWORD intervalMs = guard::cfg::ReadIniDword(configPath, L"Watchdog", L"IntervalMs", 5000);
            DWORD injectorEveryMs = guard::cfg::ReadIniDword(configPath, L"Watchdog", L"InjectorEveryMs", 5000);

            if (intervalMs < 1000) intervalMs = 1000;
            if (injectorEveryMs < 1000) injectorEveryMs = 1000;

            if (enabled == 0)
            {
                Sleep(intervalMs);
                continue;
            }

            DWORD sessionId = WTSGetActiveConsoleSessionId();
            if (sessionId == 0xFFFFFFFF)
            {
                Sleep(intervalMs);
                continue;
            }

            if (!IsProcessRunningInSession(L"ShutdownGuardUI.exe", sessionId))
            {
                const ULONGLONG nowTick = GetTickCount64();
                if (uiRestartCooldownUntilTick != 0 && nowTick < uiRestartCooldownUntilTick)
                {
                    // During cooldown, do nothing.
                }
                else
                {
                    DWORD attr = GetFileAttributesW(uiExecutablePath.c_str());
                    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
                    {
                        if (LaunchInSession(sessionId, uiExecutablePath, L"", true))
                        {
                            // Rate-limit UI restarts to avoid tight loops/log storms if UI crashes.
                            // UI 重启限速：避免 UI 崩溃时 watchdog 进入紧循环、爆 CPU/爆日志。
                            if (uiRestartWindowStartTick == 0 || (nowTick - uiRestartWindowStartTick) > 60'000)
                            {
                                uiRestartWindowStartTick = nowTick;
                                uiStartsInRestartWindow = 0;
                            }
                            uiStartsInRestartWindow++;
                            if (uiStartsInRestartWindow > 3)
                            {
                                uiRestartCooldownUntilTick = nowTick + 30'000;
                                Log().Write(L"[watchdog] UI restart too frequent, cooldown 30s session=" + std::to_wstring(sessionId));
                            }
                            Log().Write(L"[watchdog] started UI session=" + std::to_wstring(sessionId));
                        }
                        else
                        {
                            // Brief cooldown after failure to avoid repeated failing launches.
                            uiRestartCooldownUntilTick = nowTick + 10'000;
                            Log().Write(L"[watchdog] failed start UI session=" + std::to_wstring(sessionId) + L" err=" + std::to_wstring(GetLastError()));
                        }
                    }
                    else
                    {
                        Log().Write(L"[watchdog] UI exe not found: " + uiExecutablePath);
                    }
                }
            }

            const ULONGLONG nowTick = GetTickCount64();
            if (lastInjectorTick == 0 || (nowTick - lastInjectorTick) >= injectorEveryMs)
            {
                if (injectorCooldownUntilTick != 0 && nowTick < injectorCooldownUntilTick)
                {
                    // skip during cooldown
                }
                else
                {
                    DWORD attr = GetFileAttributesW(injectorExecutablePath.c_str());
                    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
                    {
                        // Run injector in service context (SYSTEM) so it can inject elevated targets as well.
                        // 这比用户 token 启动更稳，避免高完整性进程注入失败导致漏拦截。
                        if (LaunchAsServiceAccount(injectorExecutablePath, L"", false))
                        {
                            lastInjectorTick = nowTick;
                            Log().Write(L"[watchdog] ran injector (service account) session=" + std::to_wstring(sessionId));
                        }
                        else
                        {
                            injectorCooldownUntilTick = nowTick + 10'000;
                            Log().Write(L"[watchdog] failed run injector (service account) session=" + std::to_wstring(sessionId) + L" err=" + std::to_wstring(GetLastError()));
                        }
                    }
                    else
                    {
                        Log().Write(L"[watchdog] injector exe not found: " + injectorExecutablePath);
                    }
                }
            }

            // Allow timely exit on service stop: sleep in small chunks.
            DWORD slept = 0;
            while (slept < intervalMs && g_serviceStatus.dwCurrentState == SERVICE_RUNNING)
            {
                Sleep(200);
                slept += 200;
            }
        }
    }

    void SetStatus(DWORD state, DWORD win32ExitCode, DWORD waitHintMs)
    {
        g_serviceStatus.dwCurrentState = state;
        g_serviceStatus.dwWin32ExitCode = win32ExitCode;
        g_serviceStatus.dwWaitHint = waitHintMs;
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);
    }

    void EnsureDefaultConfig()
    {
        guard::paths::EnsureLayout();
        const std::wstring ini = guard::paths::ConfigPath();
        DWORD attr = GetFileAttributesW(ini.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES) return;

        guard::cfg::WriteIniString(ini, L"General", L"Mode", L"block");
        guard::cfg::WriteIniString(ini, L"Behavior", L"HookTimeoutMs", L"30000");
        guard::cfg::WriteIniString(ini, L"Behavior", L"DenyIfServiceDown", L"1");
        guard::cfg::WriteIniString(ini, L"Behavior", L"UninstallAllowAll", L"0");
        guard::cfg::WriteIniString(ini, L"Auth", L"TokenSeconds", L"300");
        guard::cfg::WriteIniString(ini, L"Auth", L"Iterations", L"200000");
    }

    void RecoverSecureBehaviorDefaultsBestEffort(const wchar_t* logSuffix)
    {
        const std::wstring ini = guard::paths::ConfigPath();
        (void)guard::cfg::WriteIniString(ini, L"Behavior", L"UninstallAllowAll", L"0");
        (void)guard::cfg::WriteIniString(ini, L"Behavior", L"DenyIfServiceDown", L"1");
        (void)guard::cfg::WriteIniString(ini, L"General", L"Mode", L"block");
        if (logSuffix && *logSuffix)
            Log().Write(std::wstring(L"[service] ") + logSuffix);
    }

    void NormalizeRuntimeBehaviorOnServiceStart()
    {
        const std::wstring ini = guard::paths::ConfigPath();
        // If previous uninstall crashed midway and left stop-mode enabled, restore secure runtime defaults.
        // 若上次卸载中断导致 stop-mode 残留，服务启动时自动恢复为正常防护策略。
        const DWORD uninstallAllowAll = guard::cfg::ReadIniDword(ini, L"Behavior", L"UninstallAllowAll", 0);
        if (uninstallAllowAll != 0)
        {
            RecoverSecureBehaviorDefaultsBestEffort(L"recovered from stale stop-mode (UninstallAllowAll=1)");
        }
    }

    DWORD WINAPI ServiceCtrlHandlerEx(DWORD control, DWORD /*eventType*/, LPVOID /*eventData*/, LPVOID /*context*/)
    {
        switch (control)
        {
        case kCtrlPrepareUninstallStopWatcher:
            Log().Write(L"[service] prepare-uninstall control received; watcher stop requested");
            guard::service::RequestWatcherStop();
            return NO_ERROR;
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_PRESHUTDOWN:
            Log().Write(L"[service] control stop/shutdown/preshutdown received");
            SetStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            if (g_pipeServer) g_pipeServer->Stop();
            SetStatus(SERVICE_STOPPED);
            return NO_ERROR;
        default:
            return NO_ERROR;
        }
    }

    void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/)
    {
        EnsureDefaultConfig();
        NormalizeRuntimeBehaviorOnServiceStart();
        guard::service::ResetWatcherStopRequest();

        g_serviceStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceCtrlHandlerEx, nullptr);
        if (!g_serviceStatusHandle) return;

        g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN;
        g_serviceStatus.dwCurrentState = SERVICE_START_PENDING;
        g_serviceStatus.dwWin32ExitCode = NO_ERROR;
        g_serviceStatus.dwCheckPoint = 0;
        g_serviceStatus.dwWaitHint = 5000;
        SetServiceStatus(g_serviceStatusHandle, &g_serviceStatus);

        guard::service::GuardPipeServer server;
        g_pipeServer = &server;
        server.Start();

        Log().Write(L"[service] started");
        SetStatus(SERVICE_RUNNING);

        // Watchdog runs in background: keeps UI up + periodically runs injector.
        std::thread watchdog(WatchdogLoop);
        watchdog.detach();

        // WMI process watcher: on new target process (cmd, powershell, etc.) inject immediately.
        std::wstring injectorPath = JoinPath(ExeDir(), L"ShutdownGuardInjector.exe");
        guard::service::RunProcessWatcherThread(injectorPath.c_str());

        // Service main thread can just sleep; pipe server runs in background thread.
        while (g_serviceStatus.dwCurrentState == SERVICE_RUNNING)
        {
            Sleep(1000);
        }

        g_pipeServer = nullptr;
    }

    std::optional<std::wstring> GetArgValue(const std::vector<std::wstring>& args, const std::wstring& key)
    {
        for (size_t i = 0; i < args.size(); ++i)
        {
            if (args[i] == key && i + 1 < args.size())
                return args[i + 1];
        }
        return std::nullopt;
    }

    bool HasArg(const std::vector<std::wstring>& args, const std::wstring& key)
    {
        for (const auto& a : args)
            if (a == key) return true;
        return false;
    }

    std::wstring ReadPasswordFromStdin()
    {
        std::wstring pw;
        std::getline(std::wcin, pw);
        while (!pw.empty() && (pw.back() == L'\r' || pw.back() == L'\n'))
            pw.pop_back();
        return pw;
    }

    std::wstring ReadPasswordFromFile(const std::wstring& path)
    {
        char readBuffer[512] = {};
        DWORD bytesRead = 0;
        HANDLE fileHandle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE) return L"";
        BOOL success = ReadFile(fileHandle, readBuffer, sizeof(readBuffer) - 1, &bytesRead, nullptr);
        CloseHandle(fileHandle);
        if (!success || bytesRead == 0) return L"";
        readBuffer[bytesRead] = '\0';
        while (bytesRead > 0 && (readBuffer[bytesRead - 1] == '\r' || readBuffer[bytesRead - 1] == '\n' || readBuffer[bytesRead - 1] == ' ' || readBuffer[bytesRead - 1] == '\t'))
            readBuffer[--bytesRead] = '\0';
        size_t start = 0;
        while (start < static_cast<size_t>(bytesRead) && (readBuffer[start] == ' ' || readBuffer[start] == '\t'))
            ++start;
        if (start > 0) { memmove(readBuffer, readBuffer + start, bytesRead - start + 1); bytesRead -= static_cast<DWORD>(start); }
        if (bytesRead >= 3 && static_cast<unsigned char>(readBuffer[0]) == 0xEF && static_cast<unsigned char>(readBuffer[1]) == 0xBB && static_cast<unsigned char>(readBuffer[2]) == 0xBF)
        {
            bytesRead -= 3;
            memmove(readBuffer, readBuffer + 3, static_cast<size_t>(bytesRead) + 1);
        }
        if (bytesRead == 0) return L"";
        int wideCharCount = MultiByteToWideChar(CP_UTF8, 0, readBuffer, -1, nullptr, 0);
        if (wideCharCount <= 0) wideCharCount = MultiByteToWideChar(CP_ACP, 0, readBuffer, -1, nullptr, 0);
        if (wideCharCount <= 0) return L"";
        std::wstring password(static_cast<size_t>(wideCharCount), L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, readBuffer, -1, password.data(), wideCharCount) <= 0)
            MultiByteToWideChar(CP_ACP, 0, readBuffer, -1, password.data(), wideCharCount);
        password.resize(static_cast<size_t>(wideCharCount - 1));
        return password;
    }

    std::wstring ReadPasswordPromptFromUi()
    {
        // Use system credential dialog for interactive maintenance actions.
        HMODULE credUiModule = LoadLibraryW(L"Credui.dll");
        if (!credUiModule)
            return L"";

        using PFN_CredUIPromptForCredentialsW = DWORD(WINAPI*)(
            PCREDUI_INFOW,
            PCWSTR,
            PCtxtHandle,
            DWORD,
            PWSTR,
            ULONG,
            PWSTR,
            ULONG,
            BOOL*,
            DWORD);

        auto credUIPromptForCredentialsW = reinterpret_cast<PFN_CredUIPromptForCredentialsW>(
            GetProcAddress(credUiModule, "CredUIPromptForCredentialsW"));
        if (!credUIPromptForCredentialsW)
        {
            FreeLibrary(credUiModule);
            return L"";
        }

        CREDUI_INFOW promptInfo{};
        promptInfo.cbSize = sizeof(promptInfo);
        promptInfo.hwndParent = GetForegroundWindow();
        promptInfo.pszCaptionText = L"ShutdownGuard 维护验证";
        promptInfo.pszMessageText = L"请输入维护密码以继续执行启用/禁用操作。";

        wchar_t userName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"Maintenance";
        wchar_t password[CREDUI_MAX_PASSWORD_LENGTH + 1] = {};
        BOOL save = FALSE;

        const DWORD flags =
            CREDUI_FLAGS_GENERIC_CREDENTIALS |
            CREDUI_FLAGS_ALWAYS_SHOW_UI |
            CREDUI_FLAGS_DO_NOT_PERSIST |
            CREDUI_FLAGS_KEEP_USERNAME;

        DWORD result = credUIPromptForCredentialsW(
            &promptInfo,
            L"ShutdownGuardMaintenance",
            nullptr,
            0,
            userName,
            static_cast<ULONG>(std::size(userName)),
            password,
            static_cast<ULONG>(std::size(password)),
            &save,
            flags
        );

        std::wstring out;
        if (result == NO_ERROR)
            out = password;

        SecureZeroMemory(password, sizeof(password));
        SecureZeroMemory(userName, sizeof(userName));
        FreeLibrary(credUiModule);
        return out;
    }

    std::wstring ReadPasswordPromptFromConsole()
    {
        // Best-effort no-echo prompt.
        if (!AttachConsole(ATTACH_PARENT_PROCESS) && GetLastError() != ERROR_ACCESS_DENIED)
            return L"";

        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hIn == nullptr || hIn == INVALID_HANDLE_VALUE) { FreeConsole(); return L""; }
        if (hOut == nullptr || hOut == INVALID_HANDLE_VALUE) { FreeConsole(); return L""; }

        DWORD oldMode = 0;
        GetConsoleMode(hIn, &oldMode);
        DWORD newMode = oldMode;
        newMode &= ~ENABLE_ECHO_INPUT;
        SetConsoleMode(hIn, newMode);

        const wchar_t* prompt = L"Input maintenance password: ";
        DWORD written = 0;
        WriteConsoleW(hOut, prompt, static_cast<DWORD>(wcslen(prompt)), &written, nullptr);

        wchar_t buf[256] = {};
        DWORD read = 0;
        ReadConsoleW(hIn, buf, static_cast<DWORD>(std::size(buf) - 1), &read, nullptr);

        // restore console mode
        SetConsoleMode(hIn, oldMode);

        // write newline (since echo was disabled)
        const wchar_t* nl = L"\r\n";
        WriteConsoleW(hOut, nl, 2, &written, nullptr);

        std::wstring pw = buf;
        SecureZeroMemory(buf, sizeof(buf));
        while (!pw.empty() && (pw.back() == L'\r' || pw.back() == L'\n'))
            pw.pop_back();
        FreeConsole();
        return pw;
    }

    std::wstring GetMaintenancePasswordFromArgsOrPrompt(const std::vector<std::wstring>& args)
    {
        std::wstring password;
        if (auto p = GetArgValue(args, L"--password"); p.has_value())
            password = *p;
        else if (auto p = GetArgValue(args, L"--password-file"); p.has_value())
            password = ReadPasswordFromFile(*p);
        else if (HasArg(args, L"--password-stdin"))
            password = ReadPasswordFromStdin();
        else
        {
            password = ReadPasswordPromptFromUi();
            if (password.empty())
                password = ReadPasswordPromptFromConsole();
        }
        return password;
    }

    bool EnsureAuthTokenInitializedFromMaintenancePassword(const std::wstring& maintenancePassword)
    {
        if (maintenancePassword.empty())
            return false;
        const std::wstring iniPath = guard::paths::ConfigPath();
        auto settings = guard::cfg::Load(iniPath);
        if (guard::cfg::HasAuthTokenConfigured(settings))
            return true;
        DWORD iterations = settings.authTokenIterations
            ? settings.authTokenIterations
            : (settings.pbkdf2Iterations ? settings.pbkdf2Iterations : 200'000);
        return guard::cfg::SetAuthToken(iniPath, maintenancePassword, iterations);
    }

    // Enforce: install/uninstall must supply correct password.
    bool ValidateOrInitializeMaintenancePasswordForInstall(const std::vector<std::wstring>& args)
    {
        EnsureDefaultConfig();

        const std::wstring iniPath = guard::paths::ConfigPath();
        auto settings = guard::cfg::Load(iniPath);

        std::wstring password = GetMaintenancePasswordFromArgsOrPrompt(args);

        if (password.empty())
            return false;

        if (!guard::cfg::HasPasswordConfigured(settings))
        {
            bool ok = guard::cfg::SetPassword(iniPath, password, settings.pbkdf2Iterations ? settings.pbkdf2Iterations : 200'000);
            if (!ok) return false;
            return EnsureAuthTokenInitializedFromMaintenancePassword(password);
        }

        return guard::cfg::VerifyPassword(settings, password);
    }

    bool ValidateMaintenancePasswordForAdminAction(const std::vector<std::wstring>& args, std::wstring& outPassword)
    {
        EnsureDefaultConfig();

        const std::wstring iniPath = guard::paths::ConfigPath();
        auto settings = guard::cfg::Load(iniPath);
        if (!guard::cfg::HasPasswordConfigured(settings))
            return false;

        std::wstring password = GetMaintenancePasswordFromArgsOrPrompt(args);

        if (password.empty())
            return false;

        if (!guard::cfg::VerifyPassword(settings, password))
            return false;
        outPassword = password;
        return true;
    }

    bool ConfigureServiceRecovery(SC_HANDLE serviceHandle)
    {
        // Restart on failure to reduce "handy stop" impact.
        SC_ACTION actions[3]{};
        actions[0].Type = SC_ACTION_RESTART;
        actions[0].Delay = 1000;   // 1s
        actions[1].Type = SC_ACTION_RESTART;
        actions[1].Delay = 5000;   // 5s
        actions[2].Type = SC_ACTION_RESTART;
        actions[2].Delay = 10'000; // 10s

        SERVICE_FAILURE_ACTIONSW sfa{};
        sfa.dwResetPeriod = 24 * 60 * 60; // 1 day
        sfa.cActions = static_cast<DWORD>(std::size(actions));
        sfa.lpsaActions = actions;

        if (!ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
            return false;

        // Apply to non-crash failures too (best-effort; not supported on all systems).
        SERVICE_FAILURE_ACTIONS_FLAG flag{};
        flag.fFailureActionsOnNonCrashFailures = TRUE;
        ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
        return true;
    }

    bool ConfigureDelayedAutoStart(SC_HANDLE serviceHandle)
    {
        SERVICE_DELAYED_AUTO_START_INFO info{};
        info.fDelayedAutostart = TRUE;
        return ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info) != FALSE;
    }

    bool InstallOrUpdateService(const std::wstring& serviceExePath)
    {
        std::wstring binPath = L"\"" + serviceExePath + L"\"";
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!serviceControlManagerHandle) return false;

        SC_HANDLE serviceHandle = CreateServiceW(
            serviceControlManagerHandle,
            kServiceName,
            kServiceName,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binPath.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr
        );

        if (!serviceHandle)
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_SERVICE_EXISTS || lastError == ERROR_DUP_NAME)
            {
                // Already installed: update binPath + (re)apply settings.
                SC_HANDLE existing = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
                if (existing)
                {
                    ChangeServiceConfigW(
                        existing,
                        SERVICE_NO_CHANGE,
                        SERVICE_AUTO_START,
                        SERVICE_NO_CHANGE,
                        binPath.c_str(),
                        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
                    );
                    bool success = ConfigureServiceRecovery(existing);
                    ConfigureDelayedAutoStart(existing);
                    CloseServiceHandle(existing);
                    CloseServiceHandle(serviceControlManagerHandle);
                    return success;
                }
            }
            CloseServiceHandle(serviceControlManagerHandle);
            return false;
        }

        ConfigureServiceRecovery(serviceHandle);
        ConfigureDelayedAutoStart(serviceHandle);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return true;
    }

    bool QueryServiceState(SC_HANDLE serviceHandle, DWORD& outState)
    {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytes = 0;
        if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes))
            return false;
        outState = ssp.dwCurrentState;
        return true;
    }

    bool QueryServiceStopped(SC_HANDLE serviceHandle, DWORD timeoutMs)
    {
        DWORD start = GetTickCount();
        for (;;)
        {
            DWORD state = SERVICE_STOPPED;
            if (!QueryServiceState(serviceHandle, state))
                return false;
            if (state == SERVICE_STOPPED)
                return true;
            if (GetTickCount() - start > timeoutMs)
                return false;
            Sleep(300);
        }
    }

    bool QueryServiceRunning(SC_HANDLE serviceHandle, DWORD timeoutMs)
    {
        DWORD start = GetTickCount();
        for (;;)
        {
            DWORD state = SERVICE_STOPPED;
            if (!QueryServiceState(serviceHandle, state))
                return false;
            if (state == SERVICE_RUNNING)
                return true;
            // Start failed or service crashed back to stopped.
            if (state == SERVICE_STOPPED)
                return false;
            if (GetTickCount() - start > timeoutMs)
                return false;
            Sleep(300);
        }
    }

    bool StopServiceBestEffort(DWORD timeoutMs)
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;
        SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!svc) { CloseServiceHandle(scm); return false; }

        DWORD state = SERVICE_STOPPED;
        if (QueryServiceState(svc, state) && state == SERVICE_STOPPED)
        {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return true;
        }

        SERVICE_STATUS status{};
        if (!ControlService(svc, SERVICE_CONTROL_STOP, &status))
        {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE)
            {
                // If a race already stopped it, still treat as success.
                DWORD latestState = SERVICE_STOPPED;
                if (!(QueryServiceState(svc, latestState) && latestState == SERVICE_STOPPED))
                {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return false;
                }
            }
        }

        bool ok = QueryServiceStopped(svc, timeoutMs);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok;
    }

    bool StartServiceBestEffort(DWORD timeoutMs = 30'000)
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;
        SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
        if (!svc) { CloseServiceHandle(scm); return false; }

        DWORD state = SERVICE_STOPPED;
        if (QueryServiceState(svc, state) && state == SERVICE_RUNNING)
        {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return true;
        }

        BOOL ok = StartServiceW(svc, 0, nullptr);
        if (!ok)
        {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING)
            {
                // If SCM reports a transient state, wait and verify real final state.
                DWORD latestState = SERVICE_STOPPED;
                if (!(QueryServiceState(svc, latestState) && latestState == SERVICE_START_PENDING))
                {
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return false;
                }
            }
        }

        bool running = QueryServiceRunning(svc, timeoutMs);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return running;
    }

    bool SetServiceStartTypeBestEffort(DWORD startType)
    {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;
        SC_HANDLE svc = OpenServiceW(scm, kServiceName, SERVICE_CHANGE_CONFIG);
        if (!svc) { CloseServiceHandle(scm); return false; }
        BOOL ok = ChangeServiceConfigW(
            svc,
            SERVICE_NO_CHANGE,
            startType,
            SERVICE_NO_CHANGE,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
        );
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok != FALSE;
    }

    std::wstring GetInstalledDirBestEffort()
    {
        const std::wstring cfgPath = guard::paths::ConfigPath();
        std::wstring installDir = guard::cfg::ReadIniString(cfgPath, L"Install", L"InstallDir", L"");
        if (!installDir.empty())
            return installDir;
        return ExeDir();
    }

    int RunConsole()
    {
        EnsureDefaultConfig();

        guard::service::GuardPipeServer server;
        server.Start();
        Log().Write(L"[console] started (Ctrl+C to stop)");
        static std::atomic<bool> running{ true };
        SetConsoleCtrlHandler([](DWORD type) -> BOOL
        {
            if (type == CTRL_C_EVENT || type == CTRL_CLOSE_EVENT)
            {
                Log().Write(L"[console] stop requested");
                if (g_pipeServer) g_pipeServer->Stop();
                running = false;
                return TRUE;
            }
            return FALSE;
        }, TRUE);

        g_pipeServer = &server;
        while (running.load())
            Sleep(200);
        g_pipeServer = nullptr;
        return 0;
    }
}

int wmain(int argc, wchar_t** argv)
{
    guard::paths::EnsureLayout();

    std::vector<std::wstring> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);

    if (!args.empty() && args[0] == L"--install")
    {
        if (!IsElevated())
            return 1;
        // Must provide password on install. If config already has a password, the provided one must match.
        if (!ValidateOrInitializeMaintenancePasswordForInstall(args))
            return 2;

        std::wstring installDir = DefaultInstallDir();
        if (auto p = GetArgValue(args, L"--install-dir"); p.has_value() && !p->empty())
            installDir = *p;

        std::wstring serviceExe;
        if (!InstallFilesToDir(installDir, serviceExe))
            return 3;

        // Autostart at logon (reversible; removed on uninstall).
        SetRunKey(L"ShutdownGuardUI", L"\"" + JoinPath(installDir, L"ShutdownGuardUI.exe") + L"\"");
        SetRunKey(L"ShutdownGuardInjector", L"\"" + JoinPath(installDir, L"ShutdownGuardInjector.exe") + L"\"");

        // On every install/reinstall, force secure runtime defaults.
        const std::wstring cfgPath = guard::paths::ConfigPath();
        guard::cfg::WriteIniString(cfgPath, L"Behavior", L"DenyIfServiceDown", L"1");
        guard::cfg::WriteIniString(cfgPath, L"Behavior", L"UninstallAllowAll", L"0");
        guard::cfg::WriteIniString(cfgPath, L"General", L"Mode", L"block");

        return InstallOrUpdateService(serviceExe) ? 0 : 1;
    }
    if (!args.empty() && args[0] == L"--enable-service")
    {
        if (!IsElevated())
            return 1;
        std::wstring maintenancePassword;
        if (!ValidateMaintenancePasswordForAdminAction(args, maintenancePassword))
            return 2;

        const std::wstring cfgPath = guard::paths::ConfigPath();
        guard::cfg::WriteIniString(cfgPath, L"General", L"Mode", L"block");
        guard::cfg::WriteIniString(cfgPath, L"Behavior", L"DenyIfServiceDown", L"1");
        guard::cfg::WriteIniString(cfgPath, L"Behavior", L"UninstallAllowAll", L"0");
        (void)EnsureAuthTokenInitializedFromMaintenancePassword(maintenancePassword);

        const std::wstring installDir = GetInstalledDirBestEffort();
        if (installDir.empty() || !ApplyInstallDirAclLocked(installDir))
        {
            Log().Write(L"[enable-service] failed to apply locked ACL: " + installDir);
            return 3;
        }

        SetGuardHelperStartupEntriesBestEffort(true, installDir);

        if (!SetServiceStartTypeBestEffort(SERVICE_AUTO_START))
        {
            Log().Write(L"[enable-service] failed to set startup type auto");
            return 3;
        }
        if (!StartServiceBestEffort(30'000))
        {
            Log().Write(L"[enable-service] failed to start service");
            return 3;
        }
        return 0;
    }
    if (!args.empty() && args[0] == L"--disable-service")
    {
        if (!IsElevated())
            return 1;
        std::wstring maintenancePassword;
        if (!ValidateMaintenancePasswordForAdminAction(args, maintenancePassword))
            return 2;

        // Disable policy first so existing hooked processes won't fail-closed once service stops.
        const std::wstring cfgPath = guard::paths::ConfigPath();
        guard::cfg::WriteIniString(cfgPath, L"General", L"Mode", L"observe");
        guard::cfg::WriteIniString(cfgPath, L"Behavior", L"DenyIfServiceDown", L"0");
        guard::cfg::WriteIniString(cfgPath, L"Behavior", L"UninstallAllowAll", L"0");

        const std::wstring installDir = GetInstalledDirBestEffort();
        if (installDir.empty() || !ApplyInstallDirAclUnlocked(installDir))
        {
            Log().Write(L"[disable-service] failed to apply unlocked ACL: " + installDir);
            return 3;
        }

        const bool stopped = StopServiceBestEffort(30'000);
        if (!stopped)
            Log().Write(L"[disable-service] failed to stop service");

        const bool disabled = SetServiceStartTypeBestEffort(SERVICE_DISABLED);
        if (!disabled)
            Log().Write(L"[disable-service] failed to set startup type disabled");

        SetGuardHelperStartupEntriesBestEffort(false, installDir);
        TerminateGuardHelperProcessesBestEffort();

        return (stopped && disabled) ? 0 : 3;
    }
    if (!args.empty() && args[0] == L"--console")
        return RunConsole();

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(table);
    return 0;
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

