#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <objbase.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include <iostream>
#include <fstream>
#include <algorithm>

#include "common/IniConfig.hpp"
#include "common/WinPaths.hpp"
#include "common/SimpleLogger.hpp"
#include "hook/HookUninstall.hpp"

namespace
{
    bool QueryServiceStopped(SC_HANDLE serviceHandle, DWORD timeoutMs);

    constexpr wchar_t kServiceName[] = L"ShutdownGuard";
    constexpr DWORD kCtrlPrepareUninstallStopWatcher = 129;  // 停止注入器，进入卸载准备
    constexpr wchar_t kAutostartUiTaskName[] = L"ShutdownGuard\\UI";
    constexpr wchar_t kAutostartInjectorTaskName[] = L"ShutdownGuard\\Injector";

    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\uninstall.log");
        return logger;
    }

    std::vector<std::wstring> Args(int argc, wchar_t** argv)
    {
        std::vector<std::wstring> out;
        if (!argv || argc <= 0) return out;
        for (int i = 1; i < argc; ++i)
            out.push_back(argv[i] ? argv[i] : L"");
        return out;
    }

    bool HasArg(const std::vector<std::wstring>& args, const std::wstring& key)
    {
        for (const auto& a : args)
            if (a == key) return true;
        return false;
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

    std::wstring ReadPasswordFromStdin()
    {
        AttachConsole(ATTACH_PARENT_PROCESS);
        HANDLE standardInputHandle = GetStdHandle(STD_INPUT_HANDLE);
        if (standardInputHandle != nullptr && standardInputHandle != INVALID_HANDLE_VALUE)
        {
            Sleep(120);
            char readBuffer[512] = {};
            DWORD bytesRead = 0;
            if (ReadFile(standardInputHandle, readBuffer, sizeof(readBuffer) - 1, &bytesRead, nullptr) && bytesRead > 0)
            {
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
                if (bytesRead == 0) { FreeConsole(); return L""; }

                auto tryDecode = [&readBuffer, &bytesRead](UINT cp) -> std::wstring {
                    int wideCharCount = MultiByteToWideChar(cp, 0, readBuffer, -1, nullptr, 0);
                    if (wideCharCount <= 0) return L"";
                    std::wstring password(static_cast<size_t>(wideCharCount), L'\0');
                    if (MultiByteToWideChar(cp, 0, readBuffer, -1, password.data(), wideCharCount) <= 0) return L"";
                    password.resize(static_cast<size_t>(wideCharCount - 1));
                    return password;
                };
                std::wstring password = tryDecode(CP_UTF8);
                if (password.empty()) password = tryDecode(CP_ACP);
                if (password.empty()) password = tryDecode(CP_OEMCP);
                if (!password.empty()) { FreeConsole(); return password; }
            }
        }
        FreeConsole();
        std::wstring password;
        std::getline(std::wcin, password);
        while (!password.empty() && (password.back() == L'\r' || password.back() == L'\n'))
            password.pop_back();
        return password;
    }

    std::wstring ReadPasswordFromFile(const std::wstring& path)
    {
        char readBuffer[512] = {};
        DWORD bytesRead = 0;
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            if (attempt > 0) Sleep(200);
            HANDLE fileHandle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE) return L"";
            BOOL success = ReadFile(fileHandle, readBuffer, sizeof(readBuffer) - 1, &bytesRead, nullptr);
            CloseHandle(fileHandle);
            if (success && bytesRead > 0) break;
        }
        if (bytesRead == 0) return L"";
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

    std::wstring UnquoteWrapped(std::wstring s)
    {
        if (s.size() >= 2 && s.front() == L'"' && s.back() == L'"')
            return s.substr(1, s.size() - 2);
        return s;
    }

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

    std::wstring ToolsDirDefault();

    guard::cfg::Settings LoadPasswordSettingsFallback(const std::wstring& toolsDir)
    {
        const std::wstring iniPath = guard::paths::ConfigPath();
        auto settings = guard::cfg::Load(iniPath);
        if (guard::cfg::HasPasswordConfigured(settings))
            return settings;

        const std::wstring bak = toolsDir + L"\\auth_backup.ini";
        return guard::cfg::Load(bak);
    }

    // Returns: 0 = OK, 1 = password empty, 3 = no config or VerifyPassword failed
    int ValidatePassword(const std::vector<std::wstring>& args)
    {
        std::wstring password;
        if (auto p = GetArgValue(args, L"--password"); p.has_value())
        {
            std::wcerr << L"warning: --password is visible to other processes; prefer --password-stdin\n";
            password = UnquoteWrapped(*p);
        }
        else if (auto p = GetArgValue(args, L"--password-file"); p.has_value())
            password = ReadPasswordFromFile(UnquoteWrapped(*p));
        else if (HasArg(args, L"--password-stdin"))
            password = ReadPasswordFromStdin();

        if (password.empty())
            return 1;

        // If guard.ini is deleted, fall back to toolsDir\\auth_backup.ini.
        // 若 guard.ini 被误删，改用 toolsDir\\auth_backup.ini 验证（仍需同一把密码）。
        std::wstring toolsDir = ToolsDirDefault();
        const std::wstring configPath = guard::paths::ConfigPath();
        DWORD fileAttributes = GetFileAttributesW(configPath.c_str());
        if (fileAttributes != INVALID_FILE_ATTRIBUTES)
        {
            std::wstring configuredToolsDir = guard::cfg::ReadIniString(configPath, L"Install", L"ToolsDir", L"");
            if (!configuredToolsDir.empty()) toolsDir = configuredToolsDir;
        }

        auto settings = LoadPasswordSettingsFallback(toolsDir);
        if (!guard::cfg::HasPasswordConfigured(settings))
            return 3;
        return guard::cfg::VerifyPassword(settings, password) ? 0 : 3;
    }

    bool RunSchtasks(const std::wstring& args)
    {
        std::wstring cmd = L"cmd.exe /c schtasks " + args;
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        BOOL success = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (!success) return false;
        WaitForSingleObject(pi.hProcess, 30'000);
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return code == 0;
    }

    bool RunPowercfg(const std::wstring& args)
    {
        std::wstring cmd = L"cmd.exe /c powercfg " + args;
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        BOOL success = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (!success) return false;
        WaitForSingleObject(pi.hProcess, 15'000);
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return code == 0;
    }

    void RestoreSleepPolicyBestEffort()
    {
        const std::wstring configFilePath = guard::paths::ConfigPath();
        std::wstring modified = guard::cfg::ReadIniString(configFilePath, L"Power", L"PolicyModified", L"0");
        if (modified != L"1") return;

        std::wstring standbyStr = guard::cfg::ReadIniString(configFilePath, L"Power", L"OriginalStandbyAC", L"");
        std::wstring hibernateStr = guard::cfg::ReadIniString(configFilePath, L"Power", L"OriginalHibernateAC", L"");
        std::wstring showSleepStr = guard::cfg::ReadIniString(configFilePath, L"Power", L"OriginalShowSleep", L"1");

        int standbyMin = standbyStr.empty() ? 30 : (std::stoi(standbyStr) / 60);
        int hibernateMin = hibernateStr.empty() ? 60 : (std::stoi(hibernateStr) / 60);

        RunPowercfg(L"/hibernate on");
        RunPowercfg(L"/change standby-timeout-ac " + std::to_wstring(standbyMin));
        RunPowercfg(L"/change hibernate-timeout-ac " + std::to_wstring(hibernateMin));

        HKEY registryKey = nullptr;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings", 0, nullptr, 0, KEY_WRITE, nullptr, &registryKey, nullptr) == ERROR_SUCCESS)
        {
            DWORD showSleepValue = (showSleepStr == L"0") ? 0 : 1;
            RegSetValueExW(registryKey, L"ShowSleepOption", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&showSleepValue), sizeof(showSleepValue));
            RegCloseKey(registryKey);
        }

        Log().Write(L"[uninstall] sleep/hibernate policy restored (standby=" + std::to_wstring(standbyMin) + L"min hibernate=" + std::to_wstring(hibernateMin) + L"min)");
    }

    std::wstring TimePlusMinutesHHMM(int minutesToAdd)
    {
        SYSTEMTIME localTime{};
        GetLocalTime(&localTime);

        FILETIME ft{};
        if (!SystemTimeToFileTime(&localTime, &ft))
            return L"00:00";

        ULARGE_INTEGER ui{};
        ui.LowPart = ft.dwLowDateTime;
        ui.HighPart = ft.dwHighDateTime;

        const ULONGLONG add = static_cast<ULONGLONG>(minutesToAdd) * 60ULL * 10'000'000ULL;
        ui.QuadPart += add;

        ft.dwLowDateTime = ui.LowPart;
        ft.dwHighDateTime = ui.HighPart;

        SYSTEMTIME resultTime{};
        if (!FileTimeToSystemTime(&ft, &resultTime))
            return L"00:00";

        wchar_t formatBuffer[16] = {};
        swprintf_s(formatBuffer, static_cast<size_t>(std::size(formatBuffer)), L"%02u:%02u", resultTime.wHour, resultTime.wMinute);
        return formatBuffer;
    }

    std::wstring SelfPath()
    {
        wchar_t pathBuffer[MAX_PATH] = {};
        DWORD pathLength = GetModuleFileNameW(nullptr, pathBuffer, MAX_PATH);
        return (pathLength > 0) ? std::wstring(pathBuffer, pathLength) : L"";
    }

    std::wstring ToolsDirDefault()
    {
        return guard::paths::ProgramDataDir() + L"\\ShutdownGuardTools";
    }

    bool ApplyToolsDirAclBestEffort(const std::wstring& dir)
    {
        PSID adminsSid = nullptr;
        PSID systemSid = nullptr;
        PSID auSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;

        if (!AllocateAndInitializeSid(&ntAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                0, 0, 0, 0, 0, 0, &adminsSid))
            return false;

        if (!AllocateAndInitializeSid(&ntAuth, 1,
                SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0, &systemSid))
        {
            FreeSid(adminsSid);
            return false;
        }

        if (!AllocateAndInitializeSid(&ntAuth, 1,
                SECURITY_AUTHENTICATED_USER_RID,
                0, 0, 0, 0, 0, 0, 0, &auSid))
        {
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        EXPLICIT_ACCESSW explicitAccessEntries[3] = {};
        explicitAccessEntries[0].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[0].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        explicitAccessEntries[0].Trustee.ptstrName = (LPWSTR)systemSid;

        explicitAccessEntries[1].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[1].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[1].Trustee.ptstrName = (LPWSTR)adminsSid;

        explicitAccessEntries[2].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[2].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | READ_CONTROL | SYNCHRONIZE;
        explicitAccessEntries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[2].Trustee.ptstrName = (LPWSTR)auSid;

        PACL newDacl = nullptr;
        DWORD aclResult = SetEntriesInAclW(3, explicitAccessEntries, nullptr, &newDacl);
        if (aclResult != ERROR_SUCCESS || !newDacl)
        {
            FreeSid(auSid);
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        DWORD securityDescriptorResult = SetNamedSecurityInfoW(
            (LPWSTR)dir.c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr,
            newDacl,
            nullptr
        );

        LocalFree(newDacl);
        FreeSid(auSid);
        FreeSid(systemSid);
        FreeSid(adminsSid);
        return securityDescriptorResult == ERROR_SUCCESS;
    }

    bool WriteTokenFile(const std::wstring& path, const std::wstring& token)
    {
        std::wofstream ofs(path.c_str(), std::ios::binary | std::ios::trunc);
        if (!ofs.is_open()) return false;
        ofs << token;
        return true;
    }

    std::wstring ReadWholeFile(const std::wstring& path)
    {
        std::wifstream ifs(path.c_str(), std::ios::binary);
        if (!ifs.is_open()) return L"";
        return std::wstring((std::istreambuf_iterator<wchar_t>(ifs)), std::istreambuf_iterator<wchar_t>());
    }

    std::wstring NewGuidString()
    {
        GUID g{};
        if (CoCreateGuid(&g) != S_OK) return L"";
        wchar_t formatBuffer[64] = {};
        swprintf_s(formatBuffer, std::size(formatBuffer),
            L"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
            g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        return formatBuffer;
    }

    void DeleteLogonTasksBestEffort()
    {
        RunSchtasks(L"/Delete /TN \"" + std::wstring(kAutostartUiTaskName) + L"\" /F");
        RunSchtasks(L"/Delete /TN \"" + std::wstring(kAutostartInjectorTaskName) + L"\" /F");
    }

    // 安装时若经由 ShutdownGuard.exe --install 会写入 Run 键；独立卸载也须删除，与安装对齐。
    void DeleteRunKeysBestEffort()
    {
        HKEY registryKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &registryKey) != ERROR_SUCCESS)
            return;
        RegDeleteValueW(registryKey, L"ShutdownGuardUI");
        RegDeleteValueW(registryKey, L"ShutdownGuardInjector");
        RegCloseKey(registryKey);
        Log().Write(L"[uninstall] Run key entries removed");
    }

    // Stop the service and wait for process exit so we can delete the install dir.
    void StopServiceAndWaitBestEffort(DWORD waitMs = 30'000)
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!serviceControlManagerHandle) return;
        SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!serviceHandle) { CloseServiceHandle(serviceControlManagerHandle); return; }
        SERVICE_STATUS serviceStatus{};
        ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);
        QueryServiceStopped(serviceHandle, waitMs);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        Log().Write(L"[uninstall] service stopped, proceeding to delete install dir");
    }

    void TerminateGuardProcessesBestEffort()
    {
        const wchar_t* names[] = { L"ShutdownGuardUI.exe", L"ShutdownGuardInjector.exe" };
        HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (processSnapshotHandle == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (!Process32FirstW(processSnapshotHandle, &processEntry)) { CloseHandle(processSnapshotHandle); return; }
        do
        {
            for (const wchar_t* name : names)
            {
                if (_wcsicmp(processEntry.szExeFile, name) != 0) continue;
                HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
                if (processHandle) { TerminateProcess(processHandle, 0); CloseHandle(processHandle); Log().Write(L"[uninstall] terminated " + std::wstring(name)); }
                break;
            }
        } while (Process32NextW(processSnapshotHandle, &processEntry));
        CloseHandle(processSnapshotHandle);
    }

    // Enable SE_DEBUG_NAME so we can OpenProcess(PROCESS_TERMINATE) on e.g. WmiPrvSE.exe.
    void EnableDebugPrivilegeBestEffort()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) || !token)
            return;
        TOKEN_PRIVILEGES tp{};
        if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
            { CloseHandle(token); return; }
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
    }

    // Terminate any process that has ShutdownGuardHook.dll loaded (so we can delete the install dir).
    void TerminateProcessesUsingHookDllBestEffort(const std::wstring& installDir)
    {
        if (installDir.empty()) return;
        EnableDebugPrivilegeBestEffort();
        const DWORD selfProcessId = GetCurrentProcessId();
        std::wstring normalizedInstallDirectory = installDir;
        if (!normalizedInstallDirectory.empty() && normalizedInstallDirectory.back() != L'\\')
            normalizedInstallDirectory += L'\\';
        HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (processSnapshotHandle == INVALID_HANDLE_VALUE) return;
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (!Process32FirstW(processSnapshotHandle, &processEntry)) { CloseHandle(processSnapshotHandle); return; }
        do
        {
            if (processEntry.th32ProcessID == selfProcessId) continue;
            auto enumModules = [&](DWORD flags) -> bool {
                HANDLE moduleSnapshotHandle = CreateToolhelp32Snapshot(flags, processEntry.th32ProcessID);
                if (moduleSnapshotHandle == INVALID_HANDLE_VALUE) return false;
                MODULEENTRY32W moduleEntry{};
                moduleEntry.dwSize = sizeof(moduleEntry);
                bool found = false;
                if (Module32FirstW(moduleSnapshotHandle, &moduleEntry))
                {
                    do
                    {
                        if (_wcsicmp(moduleEntry.szModule, L"ShutdownGuardHook.dll") != 0) continue;
                        bool pathMatch = false;
                        if (moduleEntry.szExePath[0] && !normalizedInstallDirectory.empty())
                        {
                            size_t pathLen = std::wcslen(moduleEntry.szExePath);
                            if (pathLen >= normalizedInstallDirectory.size())
                                pathMatch = (_wcsnicmp(moduleEntry.szExePath, normalizedInstallDirectory.c_str(), normalizedInstallDirectory.size()) == 0);
                        }
                        if (pathMatch)
                        {
                            HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processEntry.th32ProcessID);
                            if (processHandle)
                            {
                                TerminateProcess(processHandle, 0);
                                CloseHandle(processHandle);
                                found = true;
                                Log().Write(L"[uninstall] terminated pid " + std::to_wstring(processEntry.th32ProcessID) + L" " + std::wstring(processEntry.szExeFile) + L" (had Hook DLL)");
                            }
                            else
                                Log().Write(L"[uninstall] OpenProcess(TERMINATE) failed for pid " + std::to_wstring(processEntry.th32ProcessID) + L" err=" + std::to_wstring(GetLastError()));
                            break;
                        }
                    } while (Module32NextW(moduleSnapshotHandle, &moduleEntry));
                }
                CloseHandle(moduleSnapshotHandle);
                return found;
            };
            if (enumModules(TH32CS_SNAPMODULE)) continue;
            enumModules(TH32CS_SNAPMODULE32);
        } while (Process32NextW(processSnapshotHandle, &processEntry));
        CloseHandle(processSnapshotHandle);
    }

    bool UninstallServiceBestEffort()
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!serviceControlManagerHandle) return false;

        SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!serviceHandle)
        {
            CloseServiceHandle(serviceControlManagerHandle);
            return false;
        }

        SERVICE_STATUS serviceStatus{};
        ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);
        bool success = (DeleteService(serviceHandle) != FALSE);

        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return success;
    }

    bool QueryServiceStopped(SC_HANDLE serviceHandle, DWORD timeoutMs)
    {
        DWORD start = GetTickCount();
        for (;;)
        {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes))
                return false;
            if (ssp.dwCurrentState == SERVICE_STOPPED)
                return true;
            if (GetTickCount() - start > timeoutMs)
                return false;
            Sleep(300);
        }
    }

    // 发送控制码 129：服务停止注入器线程，不再对新进程注入。配合 UninstallAllowAll=1 形成「停止模式」。
    void SendPrepareUninstallStopWatcherControlBestEffort()
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!serviceControlManagerHandle)
        {
            Log().Write(L"[uninstall] PrepareUninstall(129) skipped: OpenSCManager failed err=" + std::to_wstring(GetLastError()));
            return;
        }
        SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_USER_DEFINED_CONTROL | SERVICE_QUERY_STATUS);
        if (!serviceHandle)
        {
            Log().Write(L"[uninstall] PrepareUninstall(129) skipped: OpenService failed err=" + std::to_wstring(GetLastError()));
            CloseServiceHandle(serviceControlManagerHandle);
            return;
        }
        SERVICE_STATUS serviceStatus{};
        const bool sent = (ControlService(serviceHandle, kCtrlPrepareUninstallStopWatcher, &serviceStatus) != FALSE);
        if (sent)
        {
            Log().Write(L"[uninstall] sent PrepareUninstall(129) to service");
        }
        else
        {
            Log().Write(L"[uninstall] failed to send PrepareUninstall(129) err=" + std::to_wstring(GetLastError()));
        }
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
    }

    void RestoreAclToInheritedBestEffort(const std::wstring& path)
    {
        // Remove explicit DACL protection; allow inheritance to apply.
        // Best-effort: if it fails, uninstall continues.
        SetNamedSecurityInfoW(
            (LPWSTR)path.c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr
        );
    }

    bool RestoreSecurityFromSddlFileBestEffort(const std::wstring& path, const std::wstring& sddlFile)
    {
        if (path.empty() || sddlFile.empty())
            return false;

        std::wstring sddl = ReadWholeFile(sddlFile);
        if (sddl.empty())
            return false;

        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr) || !sd)
            return false;

        PSID owner = nullptr;
        PSID group = nullptr;
        PACL dacl = nullptr;
        BOOL ownerDefaulted = FALSE, groupDefaulted = FALSE, daclPresent = FALSE, daclDefaulted = FALSE;
        GetSecurityDescriptorOwner(sd, &owner, &ownerDefaulted);
        GetSecurityDescriptorGroup(sd, &group, &groupDefaulted);
        GetSecurityDescriptorDacl(sd, &daclPresent, &dacl, &daclDefaulted);

        DWORD setSecurityResult = SetNamedSecurityInfoW(
            (LPWSTR)path.c_str(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            owner,
            group,
            daclPresent ? dacl : nullptr,
            nullptr
        );

        LocalFree(sd);
        return setSecurityResult == ERROR_SUCCESS;
    }

    void RemoveTreeBestEffort(const std::wstring& path)
    {
        // rmdir /s /q handles readonly/hidden better than manual walk (best-effort)
        std::wstring cmd = L"cmd.exe /c rmdir /s /q \"" + path + L"\"";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            WaitForSingleObject(pi.hProcess, 60'000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    bool ScheduleDeleteAtRebootBestEffort(const std::wstring& path, bool verbose = true)
    {
        if (path.empty()) return false;
        DWORD fileAttributes = GetFileAttributesW(path.c_str());
        if (fileAttributes != INVALID_FILE_ATTRIBUTES && (fileAttributes & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesW(path.c_str(), fileAttributes & ~FILE_ATTRIBUTE_READONLY);

        if (MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
        {
            if (verbose)
                Log().Write(L"[uninstall] scheduled delete at reboot: " + path);
            return true;
        }
        if (verbose)
            Log().Write(L"[uninstall] ScheduleDeleteAtReboot failed path=" + path + L" err=" + std::to_wstring(GetLastError()));
        return false;
    }

    bool IsDotOrDotDot(const wchar_t* name)
    {
        return name
            && name[0] == L'.'
            && (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0'));
    }

    void CollectPathsForRebootDelete(const std::wstring& dirPath, std::vector<std::wstring>& outFilePaths, std::vector<std::wstring>& outDirPaths)
    {
        std::wstring searchPattern = dirPath;
        if (!searchPattern.empty() && searchPattern.back() != L'\\' && searchPattern.back() != L'/')
            searchPattern += L'\\';
        searchPattern += L"*";

        WIN32_FIND_DATAW findData{};
        HANDLE findHandle = FindFirstFileW(searchPattern.c_str(), &findData);
        if (findHandle == INVALID_HANDLE_VALUE)
            return;

        do
        {
            if (IsDotOrDotDot(findData.cFileName))
                continue;

            std::wstring childPath = dirPath;
            if (!childPath.empty() && childPath.back() != L'\\' && childPath.back() != L'/')
                childPath += L'\\';
            childPath += findData.cFileName;

            const bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            const bool isReparsePoint = (findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;

            if (isDirectory && !isReparsePoint)
            {
                CollectPathsForRebootDelete(childPath, outFilePaths, outDirPaths);
                outDirPaths.push_back(childPath);
            }
            else
            {
                outFilePaths.push_back(childPath);
            }
        } while (FindNextFileW(findHandle, &findData));

        FindClose(findHandle);
    }

    // 逐檔 + 逐層目录登记重启删除，降低“目录非空导致仅登记根目录删除失败”的概率。
    void ScheduleDeleteTreeAtRebootBestEffort(const std::wstring& rootPath)
    {
        if (rootPath.empty())
            return;

        std::vector<std::wstring> filePaths;
        std::vector<std::wstring> directoryPaths;
        CollectPathsForRebootDelete(rootPath, filePaths, directoryPaths);

        // Safety: ensure deepest directories are removed first.
        std::sort(directoryPaths.begin(), directoryPaths.end(),
            [](const std::wstring& left, const std::wstring& right) {
                return left.size() > right.size();
            });

        std::size_t fileScheduledCount = 0;
        std::size_t fileFailedCount = 0;
        std::size_t directoryScheduledCount = 0;
        std::size_t directoryFailedCount = 0;

        for (const auto& path : filePaths)
        {
            if (ScheduleDeleteAtRebootBestEffort(path, false))
                ++fileScheduledCount;
            else
                ++fileFailedCount;
        }

        for (const auto& path : directoryPaths)
        {
            if (ScheduleDeleteAtRebootBestEffort(path, false))
                ++directoryScheduledCount;
            else
                ++directoryFailedCount;
        }

        const bool rootScheduled = ScheduleDeleteAtRebootBestEffort(rootPath, false);
        if (!rootScheduled)
            ++directoryFailedCount;

        Log().Write(
            L"[uninstall] scheduled reboot delete tree root=" + rootPath
            + L" files(ok/fail)=" + std::to_wstring(fileScheduledCount) + L"/" + std::to_wstring(fileFailedCount)
            + L" dirs(ok/fail)=" + std::to_wstring(directoryScheduledCount + (rootScheduled ? 1 : 0))
            + L"/" + std::to_wstring(directoryFailedCount)
        );
    }

    // Best-effort: delete the running uninstaller and its tools dir after exit.
    void ScheduleSelfDeleteBestEffort(const std::wstring& toolsDir)
    {
        const std::wstring self = SelfPath();
        if (self.empty() || toolsDir.empty()) return;

        // timeout is available on modern Windows; suppress output.
        std::wstring cmd =
            L"cmd.exe /c timeout /t 3 /nobreak >nul & del /f /q \"" + self +
            L"\" >nul 2>&1 & rmdir /s /q \"" + toolsDir + L"\" >nul 2>&1";

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            Log().Write(L"[uninstall] scheduled immediate self/tools cleanup command");
        }
        else
        {
            Log().Write(L"[uninstall] failed to schedule immediate self/tools cleanup err=" + std::to_wstring(GetLastError()));
        }

        // Fallback: ensure tools dir is also registered for reboot-time recursive cleanup.
        ScheduleDeleteTreeAtRebootBestEffort(toolsDir);
    }

    bool WaitForFileGone(const std::wstring& path, DWORD timeoutMs)
    {
        DWORD start = GetTickCount();
        for (;;)
        {
            DWORD attr = GetFileAttributesW(path.c_str());
            if (attr == INVALID_FILE_ATTRIBUTES)
                return true;
            if (GetTickCount() - start > timeoutMs)
                return false;
            Sleep(300);
        }
    }

    bool WaitForFileExists(const std::wstring& path, DWORD timeoutMs)
    {
        DWORD start = GetTickCount();
        for (;;)
        {
            DWORD attr = GetFileAttributesW(path.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES)
                return true;
            if (GetTickCount() - start > timeoutMs)
                return false;
            Sleep(300);
        }
    }

    bool RunSystemUninstallCleanupHelperViaTempTask(const std::wstring& toolsDir, const std::wstring& tokenFile,
        const std::wstring& installDir, const std::wstring& rootDir, const std::wstring& sddlFile)
    {
        const std::wstring uninstallExePath = SelfPath();
        if (uninstallExePath.empty()) return false;

        const std::wstring tempSystemHelperTaskName = L"ShutdownGuard\\UninstallHelperTmp";
        const std::wstring helperDoneMarkerPath = toolsDir + L"\\uninstall_helper.done";

        // ensure old marker gone
        DeleteFileW(helperDoneMarkerPath.c_str());

        std::wstring helperTaskCommand =
            L"\\\"" + uninstallExePath + L"\\\" --system-helper"
            L" --token-file \\\"" + tokenFile + L"\\\""
            L" --done-file \\\"" + helperDoneMarkerPath + L"\\\""
            L" --install-dir \\\"" + installDir + L"\\\""
            L" --root-dir \\\"" + rootDir + L"\\\""
            L" --sddl-file \\\"" + sddlFile + L"\\\"";

        // Avoid /SD locale issues: rely on default date and set /ST to a near-future time.
        const std::wstring taskStartTime = TimePlusMinutesHHMM(1);
        std::wstring createTempHelperTaskArgs =
            L"/Create /TN \"" + tempSystemHelperTaskName + L"\" /SC ONCE /ST " + taskStartTime +
            L" /RU SYSTEM /RL HIGHEST /TR \"" + helperTaskCommand + L"\" /F";
        if (!RunSchtasks(createTempHelperTaskArgs))
            return false;

        bool helperTaskStarted = RunSchtasks(L"/Run /TN \"" + tempSystemHelperTaskName + L"\"");
        if (!helperTaskStarted)
        {
            RunSchtasks(L"/Delete /TN \"" + tempSystemHelperTaskName + L"\" /F");
            return false;
        }

        // wait for helper to finish (done marker)
        bool helperCompleted = WaitForFileExists(helperDoneMarkerPath, 120'000);

        // cleanup task + marker (best-effort)
        RunSchtasks(L"/Delete /TN \"" + tempSystemHelperTaskName + L"\" /F");
        DeleteFileW(helperDoneMarkerPath.c_str());
        return helperCompleted;
    }
}

int wmain(int argc, wchar_t** argv)
{
    auto args = Args(argc, argv);
    const bool emergencyReset = HasArg(args, L"--emergency-reset") || HasArg(args, L"--emergency-reset-backdoor");

    if (HasArg(args, L"--help") || HasArg(args, L"-h"))
    {
        const wchar_t* help = L"ShutdownGuardUninstall [options]\n"
            L"  --password-file \"path\" read password from file (recommended for batch)\n"
            L"  --password-stdin     read password from stdin\n"
            L"  --password \"pw\"      password on command line (less secure)\n"
            L"  --help, -h           show this and exit\n";
        if (AttachConsole(ATTACH_PARENT_PROCESS))
        {
            HANDLE standardOutputHandle = GetStdHandle(STD_OUTPUT_HANDLE);
            if (standardOutputHandle != nullptr && standardOutputHandle != INVALID_HANDLE_VALUE)
            {
                DWORD bytesWritten = 0;
                WriteConsoleW(standardOutputHandle, help, static_cast<DWORD>(wcslen(help)), &bytesWritten, nullptr);
                FreeConsole();
            }
            else
                FreeConsole();
        }
        MessageBoxW(nullptr, help, L"ShutdownGuardUninstall --help", MB_OK);
        return 0;
    }

    guard::paths::EnsureLayout();

    // SYSTEM helper mode: restore ACLs and delete directories.
    if (HasArg(args, L"--system-helper"))
    {
        std::wstring tokenFile = GetArgValue(args, L"--token-file").value_or(L"");
        std::wstring helperDoneMarkerPath = GetArgValue(args, L"--done-file").value_or(L"");
        std::wstring installDir = GetArgValue(args, L"--install-dir").value_or(L"");
        std::wstring rootDir = GetArgValue(args, L"--root-dir").value_or(L"");
        std::wstring sddlFile = GetArgValue(args, L"--sddl-file").value_or(L"");

        // token check (best-effort)
        if (tokenFile.empty() || ReadWholeFile(tokenFile).empty())
            return 3;

        // consume token
        DeleteFileW(tokenFile.c_str());

        if (!installDir.empty())
        {
            RestoreSecurityFromSddlFileBestEffort(installDir, sddlFile);
            RemoveTreeBestEffort(installDir);
        }
        if (!rootDir.empty())
        {
            RestoreAclToInheritedBestEffort(rootDir);
            RemoveTreeBestEffort(rootDir);
        }

        if (!helperDoneMarkerPath.empty())
        {
            std::wofstream ofs(helperDoneMarkerPath.c_str(), std::ios::binary | std::ios::trunc);
            if (ofs.is_open()) ofs << L"ok";
        }
        return 0;
    }

    if (!IsElevated())
    {
        const wchar_t* msg = L"admin required (run elevated)\n";
        if (AttachConsole(ATTACH_PARENT_PROCESS))
        {
            HANDLE standardErrorHandle = GetStdHandle(STD_ERROR_HANDLE);
            if (standardErrorHandle != nullptr && standardErrorHandle != INVALID_HANDLE_VALUE)
            {
                DWORD bytesWritten = 0;
                WriteConsoleW(standardErrorHandle, msg, static_cast<DWORD>(wcslen(msg)), &bytesWritten, nullptr);
                FreeConsole();
                return 1;
            }
            FreeConsole();
        }
        MessageBoxW(nullptr, msg, L"ShutdownGuardUninstall", MB_OK | MB_ICONWARNING);
        return 1;
    }

    if (!emergencyReset)
    {
        int pwResult = ValidatePassword(args);
        if (pwResult != 0)
        {
            const wchar_t* msg = (pwResult == 1) ? L"Password empty: could not read from stdin or file.\n"
                : L"Password verification failed (wrong password).\n";
            if (AttachConsole(ATTACH_PARENT_PROCESS))
            {
                HANDLE standardErrorHandle = GetStdHandle(STD_ERROR_HANDLE);
                if (standardErrorHandle != nullptr && standardErrorHandle != INVALID_HANDLE_VALUE)
                {
                    DWORD bytesWritten = 0;
                    WriteConsoleW(standardErrorHandle, msg, static_cast<DWORD>(wcslen(msg)), &bytesWritten, nullptr);
                    FreeConsole();
                    return 2;
                }
                FreeConsole();
            }
            MessageBoxW(nullptr, msg, L"ShutdownGuardUninstall", MB_OK | MB_ICONWARNING);
            return 2;
        }
    }
    else
    {
        Log().Write(L"[uninstall] emergency reset mode enabled (password bypass)");
    }

    // read install dir before deleting config
    const std::wstring configFilePath = guard::paths::ConfigPath();
    std::wstring installDir = guard::cfg::ReadIniString(configFilePath, L"Install", L"InstallDir", L"");
    std::wstring toolsDir = guard::cfg::ReadIniString(configFilePath, L"Install", L"ToolsDir", L"");
    std::wstring installAclBackup = guard::cfg::ReadIniString(configFilePath, L"Install", L"InstallDirAclBackup", L"");
    if (toolsDir.empty()) toolsDir = ToolsDirDefault();
    if (installDir.empty() && emergencyReset) installDir = L"C:\\Program Files\\ShutdownGuard";
    if (installAclBackup.empty() && emergencyReset) installAclBackup = guard::paths::RootDir() + L"\\install_dir_acl.sddl";
    int exitCode = 0;

    RestoreSleepPolicyBestEffort();

    // 卸载顺序：停止模式 → 解除注入 → 停服务 → 删档卸载
    // 1) 停止模式：DenyIfServiceDown=0（避免 hook 死锁）+ UninstallAllowAll=1（一律放行）+ 发送 129 停止注入器
    // 卸載期間若某 Hook 請求恰好在寫入 INI 的瞬間送出，該次請求可能仍用舊策略；實務上機率低，下方 Sleep(2500) 有助收斂。
    guard::cfg::WriteIniString(configFilePath, L"Behavior", L"DenyIfServiceDown", L"0");
    guard::cfg::WriteIniString(configFilePath, L"Behavior", L"UninstallAllowAll", L"1");
    Log().Write(L"[uninstall] set DenyIfServiceDown=0, UninstallAllowAll=1 (stop mode)");
    SendPrepareUninstallStopWatcherControlBestEffort();
    Sleep(2500);

        // 2) 解除注入：先 UninstallHooks（远程 FreeLibrary → DllMain DETACH → RemoveHooks），再对残留进程终止
        guard::hook::UninstallHooksFromAllProcessesBestEffort(installDir);
        Sleep(1500);
        TerminateProcessesUsingHookDllBestEffort(installDir);
        Sleep(1200);
        TerminateProcessesUsingHookDllBestEffort(installDir);
        Sleep(800);

    // 3) 結束 UI/Injector，再停止服務
    TerminateGuardProcessesBestEffort();
    StopServiceAndWaitBestEffort(30'000);

    // Lock down tools dir so token files can't be spoofed by low-priv users (best-effort).
    guard::paths::EnsureDir(toolsDir);
    (void)ApplyToolsDirAclBestEffort(toolsDir);
    DeleteLogonTasksBestEffort();
    DeleteRunKeysBestEffort();

    // try to restore ACLs then remove files
    if (!installDir.empty())
    {
        bool restored = RestoreSecurityFromSddlFileBestEffort(installDir, installAclBackup);
        if (!restored)
            RestoreAclToInheritedBestEffort(installDir);

        RemoveTreeBestEffort(installDir);

        // If still not deleted (likely due to ACL), ask SYSTEM helper to do it.
        DWORD attr = GetFileAttributesW(installDir.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
        {
            const std::wstring token = NewGuidString();
            const std::wstring tokenFile = toolsDir + L"\\uninstall.token";
            guard::paths::EnsureDir(toolsDir);
            WriteTokenFile(tokenFile, token);
            // Prefer Task Scheduler helper; if it fails, rely on reboot-delete fallback below.
            bool systemCleanupHelperTaskOk = RunSystemUninstallCleanupHelperViaTempTask(toolsDir, tokenFile, installDir, guard::paths::RootDir(), installAclBackup);
            if (!systemCleanupHelperTaskOk)
            {
                Log().Write(L"[uninstall] SYSTEM cleanup helper task failed; will rely on reboot-delete fallback if needed");
            }
            // verify
            if (!WaitForFileGone(installDir, 60'000))
            {
                ScheduleDeleteTreeAtRebootBestEffort(installDir);
                std::wcerr << L"install dir still exists; scheduled recursive delete at reboot\n";
                exitCode = 6;
            }
        }
    }

    // Now remove the service (it may have stopped itself in helper mode).
    UninstallServiceBestEffort();

    // Remove ProgramData state (config + logs)
    const std::wstring root = guard::paths::RootDir();
    RestoreAclToInheritedBestEffort(root);
    RemoveTreeBestEffort(root);
    if (!WaitForFileGone(root, 30'000))
    {
        ScheduleDeleteTreeAtRebootBestEffort(root);
        std::wcerr << L"root dir still exists; scheduled recursive delete at reboot\n";
        exitCode = 6;
    }

    // Tools are outside root; delete after exit to avoid locking ourselves.
    if (!toolsDir.empty())
        ScheduleSelfDeleteBestEffort(toolsDir);

    Log().Write(L"[uninstall] completed");
    return exitCode;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    const wchar_t* cmd = GetCommandLineW();
    if (cmd && (wcsstr(cmd, L"--help") || wcsstr(cmd, L" -h")))
    {
        const wchar_t* help = L"ShutdownGuardUninstall [options]\n"
            L"  --password-file \"path\" read password from file (recommended for batch)\n"
            L"  --password-stdin     read password from stdin\n"
            L"  --password \"pw\"      password on command line (less secure)\n"
            L"  --help, -h           show this and exit\n";
        MessageBoxW(nullptr, help, L"ShutdownGuardUninstall --help", MB_OK);
        return 0;
    }
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmd ? cmd : L"", &argc);
    if (!argv || argc <= 0)
    {
        if (argv) LocalFree(argv);
        return wmain(0, nullptr);
    }
    int ret = wmain(argc, argv);
    LocalFree(argv);
    return ret;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR, int nCmdShow)
{
    return wWinMain(hInst, hPrev, nullptr, nCmdShow);
}

