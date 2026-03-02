#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <commctrl.h>
#include <wincred.h>

#include <cstring>
#include <string>
#include <vector>
#include <optional>
#include <iostream>
#include <fstream>

#include "common/IniConfig.hpp"
#include "common/WinPaths.hpp"
#include "common/SimpleLogger.hpp"

namespace
{
    constexpr wchar_t kServiceName[] = L"ShutdownGuard";
    constexpr wchar_t kAutostartUiTaskName[] = L"ShutdownGuard\\UI";
    constexpr wchar_t kAutostartInjectorTaskName[] = L"ShutdownGuard\\Injector";
    constexpr wchar_t kUninstallExeName[] = L"ShutdownGuardUninstall.exe";

    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\install.log");
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
                // Trim trailing CR/LF and leading/trailing spaces
                while (bytesRead > 0 && (readBuffer[bytesRead - 1] == '\r' || readBuffer[bytesRead - 1] == '\n' || readBuffer[bytesRead - 1] == ' ' || readBuffer[bytesRead - 1] == '\t'))
                    readBuffer[--bytesRead] = '\0';
                size_t start = 0;
                while (start < static_cast<size_t>(bytesRead) && (readBuffer[start] == ' ' || readBuffer[start] == '\t'))
                    ++start;
                if (start > 0) { memmove(readBuffer, readBuffer + start, bytesRead - start + 1); bytesRead -= static_cast<DWORD>(start); }
                // Skip UTF-8 BOM if present
                if (bytesRead >= 3 && static_cast<unsigned char>(readBuffer[0]) == 0xEF && static_cast<unsigned char>(readBuffer[1]) == 0xBB && static_cast<unsigned char>(readBuffer[2]) == 0xBF)
                {
                    bytesRead -= 3;
                    memmove(readBuffer, readBuffer + 3, static_cast<size_t>(bytesRead) + 1);
                }
                if (bytesRead == 0) return L"";

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

    void EnsureDefaultConfig()
    {
        guard::paths::EnsureLayout();
        const std::wstring configFilePath = guard::paths::ConfigPath();
        DWORD fileAttributes = GetFileAttributesW(configFilePath.c_str());
        if (fileAttributes != INVALID_FILE_ATTRIBUTES) return;

        guard::cfg::WriteIniString(configFilePath, L"General", L"Mode", L"block");
        guard::cfg::WriteIniString(configFilePath, L"Behavior", L"HookTimeoutMs", L"30000");
        guard::cfg::WriteIniString(configFilePath, L"Behavior", L"DenyIfServiceDown", L"1");
        guard::cfg::WriteIniString(configFilePath, L"Behavior", L"UninstallAllowAll", L"0");
        guard::cfg::WriteIniString(configFilePath, L"Auth", L"TokenSeconds", L"300");
        guard::cfg::WriteIniString(configFilePath, L"Auth", L"Iterations", L"200000");

        // installer defaults
        guard::cfg::WriteIniString(configFilePath, L"Install", L"InstallDir", L"");
        guard::cfg::WriteIniString(configFilePath, L"Watchdog", L"Enabled", L"1");
        guard::cfg::WriteIniString(configFilePath, L"Watchdog", L"IntervalMs", L"5000");
        guard::cfg::WriteIniString(configFilePath, L"Watchdog", L"InjectorEveryMs", L"5000");
    }

    std::wstring ExePath()
    {
        wchar_t pathBuffer[MAX_PATH] = {};
        DWORD pathLength = GetModuleFileNameW(nullptr, pathBuffer, MAX_PATH);
        return (pathLength > 0) ? std::wstring(pathBuffer, pathLength) : L"";
    }

    std::wstring ExeDir()
    {
        std::wstring p = ExePath();
        size_t pos = p.find_last_of(L"\\/");
        return (pos == std::wstring::npos) ? L"." : p.substr(0, pos);
    }

    std::wstring JoinPath(const std::wstring& dir, const std::wstring& name)
    {
        if (dir.empty()) return name;
        if (dir.back() == L'\\' || dir.back() == L'/') return dir + name;
        return dir + L"\\" + name;
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

    bool StopServiceBestEffort(DWORD timeoutMs)
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!serviceControlManagerHandle) return false;

        SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!serviceHandle)
        {
            CloseServiceHandle(serviceControlManagerHandle);
            return false;
        }

        SERVICE_STATUS serviceStatus{};
        ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);

        DWORD start = GetTickCount();
        for (;;)
        {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes))
                break;
            if (ssp.dwCurrentState == SERVICE_STOPPED)
                break;
            if (GetTickCount() - start > timeoutMs)
                break;
            Sleep(300);
        }

        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return true;
    }

    bool EnsureDir(const std::wstring& dir)
    {
        if (dir.empty()) return false;
        if (CreateDirectoryW(dir.c_str(), nullptr))
            return true;
        DWORD lastError = GetLastError();
        return lastError == ERROR_ALREADY_EXISTS;
    }

    bool CopyOne(const std::wstring& src, const std::wstring& dst)
    {
        if (!CopyFileW(src.c_str(), dst.c_str(), FALSE))
            return false;
        return true;
    }

    bool FileExistsRegular(const std::wstring& path)
    {
        DWORD fileAttributes = GetFileAttributesW(path.c_str());
        return fileAttributes != INVALID_FILE_ATTRIBUTES && (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    std::wstring ToolsDir()
    {
        return guard::paths::ProgramDataDir() + L"\\ShutdownGuardTools";
    }

    bool ApplyToolsDirAclBestEffort(const std::wstring& dir)
    {
        // ToolsDir is outside the locked installDir. We tighten it to prevent token spoofing.
        // ToolsDir 在安装目录之外（避免自锁）；这里收紧权限避免 token 伪造。
        PSID adminsSid = nullptr;
        PSID systemSid = nullptr;
        PSID auSid = nullptr;
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

        // NT AUTHORITY\Authenticated Users
        if (!AllocateAndInitializeSid(&ntAuth, 1,
                SECURITY_AUTHENTICATED_USER_RID,
                0, 0, 0, 0, 0, 0, 0, &auSid))
        {
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        EXPLICIT_ACCESSW explicitAccessEntries[3] = {};

        // SYSTEM full control
        explicitAccessEntries[0].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[0].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        explicitAccessEntries[0].Trustee.ptstrName = (LPWSTR)systemSid;

        // Administrators full control
        explicitAccessEntries[1].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[1].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[1].Trustee.ptstrName = (LPWSTR)adminsSid;

        // Authenticated Users read/execute only (no write)
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

    void BackupAuthToToolsBestEffort(const std::wstring& toolsDir)
    {
        // Backup PBKDF2 parameters to toolsDir so uninstall can still validate password
        // even if guard.ini is accidentally deleted.
        // 将 PBKDF2 参数备份到 toolsDir：即使 guard.ini 被误删，仍可验证卸载密码。
        const std::wstring configFilePath = guard::paths::ConfigPath();
        const std::wstring salt = guard::cfg::ReadIniString(configFilePath, L"Auth", L"SaltHex", L"");
        const std::wstring hash = guard::cfg::ReadIniString(configFilePath, L"Auth", L"HashHex", L"");
        const std::wstring iter = guard::cfg::ReadIniString(configFilePath, L"Auth", L"Iterations", L"");
        if (salt.empty() || hash.empty()) return;

        const std::wstring bak = toolsDir + L"\\auth_backup.ini";
        guard::cfg::WriteIniString(bak, L"Auth", L"SaltHex", salt);
        guard::cfg::WriteIniString(bak, L"Auth", L"HashHex", hash);
        if (!iter.empty())
            guard::cfg::WriteIniString(bak, L"Auth", L"Iterations", iter);
        SetFileAttributesW(bak.c_str(), FILE_ATTRIBUTE_HIDDEN);
    }

    bool BackupSecuritySddlToFile(const std::wstring& path, const std::wstring& backupFile)
    {
        PSECURITY_DESCRIPTOR sd = nullptr;
        DWORD getResult = GetNamedSecurityInfoW(
            (LPWSTR)path.c_str(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr,
            &sd
        );
        if (getResult != ERROR_SUCCESS || !sd)
            return false;

        LPWSTR sddl = nullptr;
        DWORD sddlLength = 0;
        BOOL success = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &sddl,
            &sddlLength
        );

        if (!success || !sddl)
        {
            LocalFree(sd);
            return false;
        }

        std::wofstream ofs(backupFile.c_str(), std::ios::binary | std::ios::trunc);
        if (!ofs.is_open())
        {
            LocalFree(sddl);
            LocalFree(sd);
            return false;
        }
        ofs << sddl;
        ofs.close();

        LocalFree(sddl);
        LocalFree(sd);
        return true;
    }

    bool ApplyAntiAccidentalDeleteAcl(const std::wstring& dir)
    {
        // NOTE / 注意：
        // This function contains your manual ACL intent: deny Administrators delete/WRITE_DAC/WRITE_OWNER for installDir.
        // 本函数包含你手写的核心 ACL 意图：对 installDir 拒绝 Administrators 的删除/改权限/夺所有权。
        // Do not "simplify" it unless you explicitly request changes.
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

        // 准备4个ACE：顺序很重要（DENY放前面，ALLOW放后面）
        EXPLICIT_ACCESSW explicitAccessEntries[4] = {};

        // 1. 拒绝Users写入/删除（跟你原来一样）
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

        // DO NOT REMOVE THIS CODE 人工代码！！！
        // 2. 拒绝Administrators删除/改权限/夺所有权（核心改动）
        explicitAccessEntries[1].grfAccessMode = DENY_ACCESS;
        explicitAccessEntries[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[1].grfAccessPermissions =
            DELETE |
            FILE_DELETE_CHILD |
            WRITE_DAC |           // 禁止修改权限
            WRITE_OWNER;          // 禁止夺取所有权
        explicitAccessEntries[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[1].Trustee.ptstrName = (LPWSTR)adminsSid;

        // DO NOT REMOVE THIS CODE 人工代码！！！
        // 3. 允许Administrators读+执行（这样还能进目录看文件）
        explicitAccessEntries[2].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[2].grfAccessPermissions =
            FILE_GENERIC_READ |
            FILE_GENERIC_EXECUTE |
            SYNCHRONIZE |
            READ_CONTROL;         // 允许看权限（但改不了）
        explicitAccessEntries[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        explicitAccessEntries[2].Trustee.ptstrName = (LPWSTR)adminsSid;

        // 4. 允许SYSTEM完全控制
        explicitAccessEntries[3].grfAccessMode = GRANT_ACCESS;
        explicitAccessEntries[3].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        explicitAccessEntries[3].grfAccessPermissions = GENERIC_ALL;
        explicitAccessEntries[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        explicitAccessEntries[3].Trustee.TrusteeType = TRUSTEE_IS_USER;
        explicitAccessEntries[3].Trustee.ptstrName = (LPWSTR)systemSid;

        // 获取现有的DACL（为了合并）
        PACL oldDacl = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        DWORD getResult = GetNamedSecurityInfoW(
            (LPWSTR)dir.c_str(), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &oldDacl, nullptr, &sd
        );
        if (getResult != ERROR_SUCCESS)
        {
            FreeSid(usersSid);
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        // 合并新ACE到新ACL
        PACL newDacl = nullptr;
        DWORD aclResult = SetEntriesInAclW(static_cast<ULONG>(std::size(explicitAccessEntries)), explicitAccessEntries, oldDacl, &newDacl);
        if (aclResult != ERROR_SUCCESS)
        {
            LocalFree(sd);
            FreeSid(usersSid);
            FreeSid(systemSid);
            FreeSid(adminsSid);
            return false;
        }

        // 设置新的DACL（同时把所有者设为SYSTEM）
        // SUB_CONTAINERS_AND_OBJECTS_INHERIT 是 ACE 继承用，不是 SECURITY_INFORMATION 合法值，传入会导致 SetNamedSecurityInfoW 失败
        DWORD setResult = SetNamedSecurityInfoW(
            (LPWSTR)dir.c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            systemSid,    // 新所有者设为SYSTEM
            nullptr,
            newDacl,
            nullptr
        );

        LocalFree(newDacl);
        LocalFree(sd);
        FreeSid(usersSid);
        FreeSid(systemSid);
        FreeSid(adminsSid);

        return setResult == ERROR_SUCCESS;
    }

    bool ConfigureServiceRecovery(SC_HANDLE serviceHandle)
    {
        SC_ACTION actions[3]{};
        actions[0].Type = SC_ACTION_RESTART;
        actions[0].Delay = 1000;
        actions[1].Type = SC_ACTION_RESTART;
        actions[1].Delay = 5000;
        actions[2].Type = SC_ACTION_RESTART;
        actions[2].Delay = 10'000;

        SERVICE_FAILURE_ACTIONSW sfa{};
        sfa.dwResetPeriod = 24 * 60 * 60;
        sfa.cActions = static_cast<DWORD>(std::size(actions));
        sfa.lpsaActions = actions;
        if (!ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
            return false;

        SERVICE_FAILURE_ACTIONS_FLAG flag{};
        flag.fFailureActionsOnNonCrashFailures = TRUE;
        ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag);
        return true;
    }

    void ConfigureDelayedAutoStartBestEffort(SC_HANDLE serviceHandle)
    {
        SERVICE_DELAYED_AUTO_START_INFO info{};
        info.fDelayedAutostart = TRUE;
        ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info);
    }

    bool InstallOrUpdateService(const std::wstring& serviceExePath)
    {
        const std::wstring binPath = L"\"" + serviceExePath + L"\"";
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
                SC_HANDLE existing = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
                if (!existing)
                {
                    CloseServiceHandle(serviceControlManagerHandle);
                    return false;
                }
                // Update binPath/start settings on reinstall/update.
                ChangeServiceConfigW(existing,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    binPath.c_str(),
                    nullptr, nullptr, nullptr, nullptr, nullptr,
                    kServiceName);
                ConfigureServiceRecovery(existing);
                ConfigureDelayedAutoStartBestEffort(existing);
                CloseServiceHandle(existing);
                CloseServiceHandle(serviceControlManagerHandle);
                return true;
            }

            CloseServiceHandle(serviceControlManagerHandle);
            return false;
        }

        ConfigureServiceRecovery(serviceHandle);
        ConfigureDelayedAutoStartBestEffort(serviceHandle);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return true;
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

    bool RunProcessAndWait(const std::wstring& exePath, const std::wstring& args, DWORD waitTimeoutMs, DWORD& outExitCode)
    {
        outExitCode = static_cast<DWORD>(-1);
        if (exePath.empty()) return false;

        std::wstring commandLine = L"\"" + exePath + L"\"";
        if (!args.empty())
            commandLine += L" " + args;

        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        BOOL ok = CreateProcessW(
            exePath.c_str(),
            mutableCommandLine.data(),
            nullptr, nullptr,
            FALSE,
            0,
            nullptr, nullptr,
            &startupInfo,
            &processInfo
        );
        if (!ok)
            return false;

        DWORD waitResult = WaitForSingleObject(processInfo.hProcess, waitTimeoutMs);
        if (waitResult == WAIT_OBJECT_0)
            GetExitCodeProcess(processInfo.hProcess, &outExitCode);
        else
        {
            outExitCode = static_cast<DWORD>(-1);
            if (waitResult == WAIT_TIMEOUT)
                SetLastError(ERROR_TIMEOUT);
            else
                SetLastError(ERROR_GEN_FAILURE);
        }

        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return waitResult == WAIT_OBJECT_0;
    }

    bool ShouldSetupAuthorizationPasswordNow()
    {
        auto fallbackPrompt = []() -> bool {
            int choice = MessageBoxW(
                nullptr,
                L"是否现在设置授权密码？\r\n\r\n"
                L"是：立即设置授权密码（关机/重启放行时使用）\r\n"
                L"否：先跳过（之后可手动执行 ShutdownGuardUI.exe --set-auth-password）",
                L"ShutdownGuardInstall",
                MB_YESNO | MB_ICONQUESTION | MB_TOPMOST
            );
            return choice == IDYES;
        };

        HMODULE comctlModule = LoadLibraryW(L"comctl32.dll");
        if (!comctlModule)
            return fallbackPrompt();

        using PFN_TaskDialogIndirect = HRESULT(WINAPI*)(
            const TASKDIALOGCONFIG*,
            int*,
            int*,
            BOOL*
        );
        auto taskDialogIndirect = reinterpret_cast<PFN_TaskDialogIndirect>(
            GetProcAddress(comctlModule, "TaskDialogIndirect")
        );
        if (!taskDialogIndirect)
        {
            FreeLibrary(comctlModule);
            return fallbackPrompt();
        }

        constexpr int kButtonSetup = 1001;
        constexpr int kButtonSkip = 1002;
        TASKDIALOG_BUTTON buttons[] = {
            { kButtonSetup, L"设置" },
            { kButtonSkip,  L"跳过" },
        };

        TASKDIALOGCONFIG config{};
        config.cbSize = sizeof(config);
        config.hwndParent = nullptr;
        config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
        config.dwCommonButtons = 0;
        config.pszWindowTitle = L"ShutdownGuardInstall";
        config.pszMainInstruction = L"是否现在设置授权密码？";
        config.pszContent =
            L"设置：立即设置授权密码（关机/重启放行时使用）\n"
            L"跳过：先略过，之后可手动执行 ShutdownGuardUI.exe --set-auth-password";
        config.cButtons = static_cast<UINT>(std::size(buttons));
        config.pButtons = buttons;
        config.nDefaultButton = kButtonSetup;

        int pressedButton = 0;
        HRESULT hr = taskDialogIndirect(&config, &pressedButton, nullptr, nullptr);
        FreeLibrary(comctlModule);
        if (SUCCEEDED(hr))
            return pressedButton == kButtonSetup;
        return fallbackPrompt();
    }

    void SecureWipeString(std::wstring& text)
    {
        if (!text.empty())
            SecureZeroMemory(text.data(), text.size() * sizeof(wchar_t));
        text.clear();
    }

    enum class CredUiPromptResult
    {
        Ok,
        Cancelled,
        Unavailable,
        Failed,
    };

    CredUiPromptResult PromptPasswordViaCredUi(const wchar_t* caption, const wchar_t* message, std::wstring& outPassword)
    {
        outPassword.clear();

        HMODULE credUiModule = LoadLibraryW(L"Credui.dll");
        if (!credUiModule)
            return CredUiPromptResult::Unavailable;

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

        auto credUiPromptForCredentialsW = reinterpret_cast<PFN_CredUIPromptForCredentialsW>(
            GetProcAddress(credUiModule, "CredUIPromptForCredentialsW")
        );
        if (!credUiPromptForCredentialsW)
        {
            FreeLibrary(credUiModule);
            return CredUiPromptResult::Unavailable;
        }

        CREDUI_INFOW promptInfo{};
        promptInfo.cbSize = sizeof(promptInfo);
        promptInfo.hwndParent = GetForegroundWindow();
        promptInfo.pszCaptionText = caption;
        promptInfo.pszMessageText = message;

        wchar_t userName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"Authorization";
        wchar_t password[CREDUI_MAX_PASSWORD_LENGTH + 1] = {};
        BOOL save = FALSE;

        const DWORD flags =
            CREDUI_FLAGS_GENERIC_CREDENTIALS |
            CREDUI_FLAGS_ALWAYS_SHOW_UI |
            CREDUI_FLAGS_DO_NOT_PERSIST |
            CREDUI_FLAGS_KEEP_USERNAME;

        DWORD result = credUiPromptForCredentialsW(
            &promptInfo,
            L"ShutdownGuardAuthorization",
            nullptr,
            0,
            userName,
            static_cast<ULONG>(std::size(userName)),
            password,
            static_cast<ULONG>(std::size(password)),
            &save,
            flags
        );

        CredUiPromptResult promptResult = CredUiPromptResult::Failed;
        if (result == NO_ERROR)
        {
            outPassword.assign(password);
            promptResult = CredUiPromptResult::Ok;
        }
        else if (result == ERROR_CANCELLED)
        {
            promptResult = CredUiPromptResult::Cancelled;
        }

        SecureZeroMemory(password, sizeof(password));
        SecureZeroMemory(userName, sizeof(userName));
        FreeLibrary(credUiModule);
        return promptResult;
    }

    enum class InlineAuthSetupResult
    {
        Success,
        Cancelled,
        Unavailable,
        Failed,
    };

    InlineAuthSetupResult TrySetupAuthorizationPasswordInline(const std::wstring& configPath)
    {
        constexpr int kMaxAttempts = 3;
        for (int attempt = 0; attempt < kMaxAttempts; ++attempt)
        {
            std::wstring newPassword;
            CredUiPromptResult newPrompt = PromptPasswordViaCredUi(
                L"ShutdownGuardInstall - 设置授权密码",
                L"请输入新的授权密码（用于放行关机/重启）。",
                newPassword
            );

            if (newPrompt == CredUiPromptResult::Unavailable)
                return InlineAuthSetupResult::Unavailable;
            if (newPrompt == CredUiPromptResult::Cancelled)
                return InlineAuthSetupResult::Cancelled;
            if (newPrompt != CredUiPromptResult::Ok)
                return InlineAuthSetupResult::Failed;

            if (newPassword.empty())
            {
                MessageBoxW(nullptr, L"授权密码不能为空，请重试。", L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
                continue;
            }

            std::wstring confirmPassword;
            CredUiPromptResult confirmPrompt = PromptPasswordViaCredUi(
                L"ShutdownGuardInstall - 确认授权密码",
                L"请再次输入相同的授权密码。",
                confirmPassword
            );

            if (confirmPrompt == CredUiPromptResult::Unavailable)
            {
                SecureWipeString(newPassword);
                return InlineAuthSetupResult::Unavailable;
            }
            if (confirmPrompt == CredUiPromptResult::Cancelled)
            {
                SecureWipeString(newPassword);
                return InlineAuthSetupResult::Cancelled;
            }
            if (confirmPrompt != CredUiPromptResult::Ok)
            {
                SecureWipeString(newPassword);
                return InlineAuthSetupResult::Failed;
            }

            if (newPassword != confirmPassword)
            {
                SecureWipeString(newPassword);
                SecureWipeString(confirmPassword);
                MessageBoxW(nullptr, L"两次输入不一致，请重试。", L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
                continue;
            }

            const bool saveOk = guard::cfg::SetAuthToken(configPath, newPassword);
            SecureWipeString(newPassword);
            SecureWipeString(confirmPassword);

            if (!saveOk)
                return InlineAuthSetupResult::Failed;

            MessageBoxW(nullptr,
                L"授权密码已设置完成。\r\n放行关机/重启时将使用此密码。",
                L"ShutdownGuardInstall",
                MB_OK | MB_ICONINFORMATION);
            Log().Write(L"[install] auth password set (inline)");
            return InlineAuthSetupResult::Success;
        }

        return InlineAuthSetupResult::Failed;
    }

    void PromptAuthorizationPasswordSetupBestEffort(const std::wstring& installedUiPath, const std::vector<std::wstring>& args)
    {
        if (HasArg(args, L"--skip-auth-setup"))
            return;

        if (!ShouldSetupAuthorizationPasswordNow())
        {
            Log().Write(L"[install] auth password setup skipped by user");
            return;
        }

        // Preferred path: set authorization password directly in installer process.
        // This avoids child-process UI crashes at install tail.
        const std::wstring configPath = guard::paths::ConfigPath();
        InlineAuthSetupResult inlineResult = TrySetupAuthorizationPasswordInline(configPath);
        if (inlineResult == InlineAuthSetupResult::Success)
            return;
        if (inlineResult == InlineAuthSetupResult::Cancelled)
        {
            Log().Write(L"[install] auth password setup cancelled by user");
            return;
        }
        if (inlineResult == InlineAuthSetupResult::Failed)
        {
            Log().Write(L"[install] inline auth password setup failed");
            MessageBoxW(nullptr,
                L"授权密码设置失败。\r\n维护密码仍可用于放行。\r\n你可稍后手动执行：ShutdownGuardUI.exe --set-auth-password",
                L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
            return;
        }

        // Fallback only when inline prompt API is unavailable on this machine.
        DWORD fileAttributes = GetFileAttributesW(installedUiPath.c_str());
        if (fileAttributes == INVALID_FILE_ATTRIBUTES || (fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            Log().Write(L"[install] inline auth prompt unavailable and UI executable missing");
            MessageBoxW(nullptr,
                L"当前系统不支持内置授权密码弹窗，且找不到 ShutdownGuardUI.exe。\r\n"
                L"维护密码仍可用于放行；请确认 UI 程序后再单独设置授权密码。",
                L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
            return;
        }

        DWORD exitCode = static_cast<DWORD>(-1);
        if (!RunProcessAndWait(installedUiPath, L"--set-auth-password", 5 * 60 * 1000, exitCode))
        {
            Log().Write(L"[install] failed to launch auth setup UI err=" + std::to_wstring(GetLastError()));
            MessageBoxW(nullptr,
                L"无法启动授权密码设置界面。\r\n"
                L"你可稍后手动执行：ShutdownGuardUI.exe --set-auth-password",
                L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
            return;
        }

        Log().Write(L"[install] auth setup UI exited code=" + std::to_wstring(exitCode));
        if (exitCode != 0)
        {
            std::wstring msg = L"授权密码设置界面已退出（代码 " + std::to_wstring(exitCode) + L"）。\r\n"
                L"维护密码仍可用于安装/卸载。\r\n"
                L"如需单独授权密码，请稍后手动执行：ShutdownGuardUI.exe --set-auth-password";
            MessageBoxW(nullptr, msg.c_str(), L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
        }
    }

    int RunEmergencyResetViaUninstaller()
    {
        const std::wstring configPath = guard::paths::ConfigPath();
        std::wstring toolsDir = guard::cfg::ReadIniString(configPath, L"Install", L"ToolsDir", L"");
        if (toolsDir.empty())
            toolsDir = ToolsDir();

        const std::wstring installedUninstall = JoinPath(toolsDir, kUninstallExeName);
        const std::wstring localUninstall = JoinPath(ExeDir(), kUninstallExeName);

        std::wstring uninstallExe;
        if (FileExistsRegular(installedUninstall))
            uninstallExe = installedUninstall;
        else if (FileExistsRegular(localUninstall))
            uninstallExe = localUninstall;

        if (uninstallExe.empty())
        {
            MessageBoxW(nullptr,
                L"应急恢复失败：找不到 ShutdownGuardUninstall.exe。\r\n"
                L"请将安装包中的卸载程序放到同目录后再试。",
                L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
            return 8;
        }

        DWORD exitCode = static_cast<DWORD>(-1);
        if (!RunProcessAndWait(uninstallExe, L"--emergency-reset", 10 * 60 * 1000, exitCode))
        {
            DWORD errorCode = GetLastError();
            std::wstring msg = L"启动应急恢复失败，错误码: " + std::to_wstring(errorCode) + L"\r\n"
                L"你可手动运行：\r\n" + uninstallExe + L" --emergency-reset";
            MessageBoxW(nullptr, msg.c_str(), L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
            return 8;
        }

        if (exitCode != 0)
        {
            std::wstring msg = L"应急恢复执行失败，退出代码: " + std::to_wstring(exitCode);
            MessageBoxW(nullptr, msg.c_str(), L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
            return static_cast<int>(exitCode);
        }

        MessageBoxW(nullptr,
            L"应急恢复执行完成，系统已恢复到未安装状态。",
            L"ShutdownGuardInstall", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    // GUIDs for power scheme query via PowerReadACValueIndex (loaded dynamically).
    static const GUID kSleepSubgroup = { 0x238C9FA8, 0x0AAD, 0x41ED, {0x83, 0xF4, 0x97, 0xBE, 0x24, 0x2C, 0x8F, 0x20} };
    static const GUID kStandbyTimeout = { 0x29F6C1DB, 0x86DA, 0x48C5, {0x9F, 0xDB, 0xF2, 0xB6, 0x7B, 0x1F, 0x44, 0xDA} };
    static const GUID kHibernateTimeout = { 0x9D7815A6, 0x7EE4, 0x497E, {0x88, 0x88, 0x51, 0x5A, 0x05, 0xF0, 0x23, 0x64} };

    DWORD ReadACPowerTimeout(const GUID& subgroup, const GUID& setting)
    {
        HMODULE libraryHandle = LoadLibraryW(L"PowrProf.dll");
        if (!libraryHandle) return MAXDWORD;

        using PFN_GetScheme = DWORD(WINAPI*)(HKEY, GUID**);
        using PFN_ReadAC = DWORD(WINAPI*)(HKEY, const GUID*, const GUID*, const GUID*, DWORD*);
        auto pGetScheme = reinterpret_cast<PFN_GetScheme>(GetProcAddress(libraryHandle, "PowerGetActiveScheme"));
        auto pReadAC = reinterpret_cast<PFN_ReadAC>(GetProcAddress(libraryHandle, "PowerReadACValueIndex"));
        if (!pGetScheme || !pReadAC) { FreeLibrary(libraryHandle); return MAXDWORD; }

        GUID* scheme = nullptr;
        if (pGetScheme(nullptr, &scheme) != ERROR_SUCCESS || !scheme) { FreeLibrary(libraryHandle); return MAXDWORD; }

        DWORD value = MAXDWORD;
        pReadAC(nullptr, scheme, &subgroup, &setting, &value);
        LocalFree(scheme);
        FreeLibrary(libraryHandle);
        return value;
    }

    void SaveAndDisableSleepPolicy()
    {
        const std::wstring configFilePath = guard::paths::ConfigPath();

        DWORD standby = ReadACPowerTimeout(kSleepSubgroup, kStandbyTimeout);
        DWORD hibernate = ReadACPowerTimeout(kSleepSubgroup, kHibernateTimeout);

        if (standby != MAXDWORD)
            guard::cfg::WriteIniString(configFilePath, L"Power", L"OriginalStandbyAC", std::to_wstring(standby));
        if (hibernate != MAXDWORD)
            guard::cfg::WriteIniString(configFilePath, L"Power", L"OriginalHibernateAC", std::to_wstring(hibernate));

        // Read current ShowSleepOption registry value before overwriting.
        HKEY registryKey = nullptr;
        DWORD oldShowSleep = 1;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings", 0, KEY_READ, &registryKey) == ERROR_SUCCESS)
        {
            DWORD size = sizeof(oldShowSleep);
            RegQueryValueExW(registryKey, L"ShowSleepOption", nullptr, nullptr, reinterpret_cast<LPBYTE>(&oldShowSleep), &size);
            RegCloseKey(registryKey);
        }
        guard::cfg::WriteIniString(configFilePath, L"Power", L"OriginalShowSleep", std::to_wstring(oldShowSleep));
        guard::cfg::WriteIniString(configFilePath, L"Power", L"PolicyModified", L"1");

        RunPowercfg(L"/change standby-timeout-ac 0");
        RunPowercfg(L"/change standby-timeout-dc 0");
        RunPowercfg(L"/change hibernate-timeout-ac 0");
        RunPowercfg(L"/change hibernate-timeout-dc 0");
        RunPowercfg(L"/hibernate off");

        // Hide sleep button from Start Menu power flyout.
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlyoutMenuSettings", 0, nullptr, 0, KEY_WRITE, nullptr, &registryKey, nullptr) == ERROR_SUCCESS)
        {
            DWORD powerValue = 0;
            RegSetValueExW(registryKey, L"ShowSleepOption", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&powerValue), sizeof(powerValue));
            RegCloseKey(registryKey);
        }

        Log().Write(L"[install] sleep/hibernate policy disabled (standby=" + std::to_wstring(standby) + L" hibernate=" + std::to_wstring(hibernate) + L")");
    }

    bool CreateAutostartLogonTasks(const std::wstring& installDir)
    {
        const std::wstring ui = JoinPath(installDir, L"ShutdownGuardUI.exe");
        const std::wstring inj = JoinPath(installDir, L"ShutdownGuardInjector.exe");

        // Create foldered tasks. (Best-effort: if folder creation fails, task creation may still work)
        // /IT helps UI show on the interactive desktop when the user is logged on.
        bool autostartUiTaskCreated = RunSchtasks(L"/Create /TN \"" + std::wstring(kAutostartUiTaskName) + L"\" /SC ONLOGON /RL HIGHEST /IT /TR \"\\\"" + ui + L"\\\"\" /F");
        bool autostartInjectorTaskCreated = RunSchtasks(L"/Create /TN \"" + std::wstring(kAutostartInjectorTaskName) + L"\" /SC ONLOGON /RL HIGHEST /TR \"\\\"" + inj + L"\\\"\" /F");
        return autostartUiTaskCreated && autostartInjectorTaskCreated;
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

    // Returns: 0 = OK, 1 = password empty, 2 = SetPassword failed, 3 = VerifyPassword failed
    int ValidateOrInitializePassword(const std::vector<std::wstring>& args, std::wstring& outPassword)
    {
        outPassword.clear();
        EnsureDefaultConfig();
        const std::wstring configFilePath = guard::paths::ConfigPath();
        auto settings = guard::cfg::Load(configFilePath);

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
        outPassword = password;

        if (!guard::cfg::HasPasswordConfigured(settings))
        {
            if (!guard::cfg::SetPassword(configFilePath, password, settings.pbkdf2Iterations ? settings.pbkdf2Iterations : 200'000))
                return 2;
            return 0;
        }
        return guard::cfg::VerifyPassword(settings, password) ? 0 : 3;
    }

    bool EnsureAuthTokenInitializedFromMaintenancePassword(const std::wstring& maintenancePassword)
    {
        if (maintenancePassword.empty())
            return false;

        const std::wstring configFilePath = guard::paths::ConfigPath();
        auto settings = guard::cfg::Load(configFilePath);
        if (guard::cfg::HasAuthTokenConfigured(settings))
            return true;

        DWORD iterations = settings.authTokenIterations
            ? settings.authTokenIterations
            : (settings.pbkdf2Iterations ? settings.pbkdf2Iterations : 200'000);
        if (!guard::cfg::SetAuthToken(configFilePath, maintenancePassword, iterations))
            return false;

        Log().Write(L"[install] auth token initialized from maintenance password");
        return true;
    }
}

int wmain(int argc, wchar_t** argv)
{
    auto args = Args(argc, argv);

    if (HasArg(args, L"--help") || HasArg(args, L"-h"))
    {
        const wchar_t* help = L"ShutdownGuardInstall [options]\n"
            L"  --password-file \"path\" read password from file (recommended for batch)\n"
            L"  --password-stdin     read password from stdin (redirect)\n"
            L"  --password \"pw\"      password on command line (less secure)\n"
            L"  --dir \"path\"         install dir (default: C:\\Program Files\\ShutdownGuard)\n"
            L"  --start-service      start service after install\n"
            L"  --skip-auth-setup   do not show auth-password setup prompt\n"
            L"  --no-acl             skip ACL hardening (test only)\n"
            L"  --no-schtasks        skip logon tasks\n"
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
        MessageBoxW(nullptr, help, L"ShutdownGuardInstall --help", MB_OK);
        return 0;
    }

    guard::paths::EnsureLayout();
    EnsureDefaultConfig();

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
        MessageBoxW(nullptr, msg, L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
        return 1;
    }

    if (HasArg(args, L"--emergency-reset"))
        return RunEmergencyResetViaUninstaller();

    // required: password
    std::wstring maintenancePassword;
    int pwResult = ValidateOrInitializePassword(args, maintenancePassword);
    if (pwResult != 0)
    {
        const wchar_t* msg = (pwResult == 1) ? L"Password empty: could not read from stdin or file.\n"
            : (pwResult == 2) ? L"Failed to set password (first-time): config write error.\n"
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
        MessageBoxW(nullptr, msg, L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
        return 2;
    }

    // Installation order (same style as uninstall):
    // 1) Create tools dir (outside install dir to avoid self-lock) and optional ACL.
    // 2) Create install dir; backup its ACL so uninstall can restore.
    // 3) If reinstalling, stop service so files are not locked.
    // 4) Copy service exe, UI, Injector, Hook DLL into install dir; copy uninstaller to tools dir.
    // 5) Apply anti-accidental-delete ACL on install dir (best-effort).
    // 6) Persist InstallDir / ToolsDir / UninstallExe in config; backup auth to tools dir.
    // 7) Save and disable sleep policy (for guard behavior).
    // 8) Install or update the service (SCM); create logon tasks (UI + Injector).
    // 9) Optionally start service (--start-service).
    std::wstring installDir = L"C:\\Program Files\\ShutdownGuard";
    if (auto p = GetArgValue(args, L"--dir"); p.has_value())
        installDir = *p;

    // (1) Tools directory is OUTSIDE the install directory to avoid self-lock.
    const std::wstring toolsDir = ToolsDir();
    if (!EnsureDir(toolsDir))
    {
        MessageBoxW(nullptr, L"failed to create tools dir", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 3;
    }
    if (!HasArg(args, L"--no-acl"))
        (void)ApplyToolsDirAclBestEffort(toolsDir);

    // (2) Create install dir; backup its ACL so uninstall can restore.
    if (!EnsureDir(installDir))
    {
        MessageBoxW(nullptr, L"failed to create dir", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 3;
    }

    // Backup original ACL so uninstall can restore "as if never installed".
    const std::wstring aclBackup = guard::paths::RootDir() + L"\\install_dir_acl.sddl";
    if (BackupSecuritySddlToFile(installDir, aclBackup))
    {
        guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Install", L"InstallDirAclBackup", aclBackup);
    }
    else
    {
        Log().Write(L"[install] Warning: failed to backup install dir ACL");
    }

    const std::wstring from = ExeDir();
    const std::wstring srcSvc = JoinPath(from, L"ShutdownGuard.exe");
    const std::wstring srcUi = JoinPath(from, L"ShutdownGuardUI.exe");
    const std::wstring srcInj = JoinPath(from, L"ShutdownGuardInjector.exe");
    const std::wstring srcHook = JoinPath(from, L"ShutdownGuardHook.dll");
    const std::wstring srcUninstall = JoinPath(from, L"ShutdownGuardUninstall.exe");

    const std::wstring dstSvc = JoinPath(installDir, L"ShutdownGuard.exe");
    const std::wstring dstUi = JoinPath(installDir, L"ShutdownGuardUI.exe");
    const std::wstring dstInj = JoinPath(installDir, L"ShutdownGuardInjector.exe");
    const std::wstring dstHook = JoinPath(installDir, L"ShutdownGuardHook.dll");
    const std::wstring dstUninstall = JoinPath(toolsDir, L"ShutdownGuardUninstall.exe");

    // (3) If reinstalling over an existing running service, stop it to avoid file locks.
    StopServiceBestEffort(15'000);

    // (4) Copy service exe, UI, Injector, Hook DLL; uninstaller to tools dir.
    if (!CopyOne(srcSvc, dstSvc) || !CopyOne(srcUi, dstUi) || !CopyOne(srcInj, dstInj) || !CopyOne(srcHook, dstHook))
    {
        MessageBoxW(nullptr, L"copy failed (missing exe/dll in current dir?)", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 4;
    }

    // Put uninstaller OUTSIDE the install dir.
    // Not fatal if you ship uninstall separately, but recommended.
    if (!CopyOne(srcUninstall, dstUninstall))
    {
        MessageBoxW(nullptr, L"copy uninstall failed", L"ShutdownGuardInstall", MB_OK | MB_ICONWARNING);
        if (!HasArg(args, L"--no-acl"))
            return 4;
    }

    // (5) Apply anti-accidental-delete ACL on install dir (best-effort).
    if (!HasArg(args, L"--no-acl"))
    {
        if (!ApplyAntiAccidentalDeleteAcl(installDir))
            Log().Write(L"[install] Warning: ACL hardening failed (install dir); continuing");
    }

    // (6) Persist InstallDir / ToolsDir / UninstallExe; backup auth to tools dir.
    if (!guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Install", L"InstallDir", installDir))
    {
        MessageBoxW(nullptr, L"failed to write config (InstallDir)", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 7;
    }
    if (!guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Install", L"ToolsDir", toolsDir))
    {
        MessageBoxW(nullptr, L"failed to write config (ToolsDir)", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 7;
    }
    if (!guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Install", L"UninstallExe", dstUninstall))
    {
        MessageBoxW(nullptr, L"failed to write config (UninstallExe)", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 7;
    }

    // Reset runtime behavior to secure baseline on every install/reinstall.
    // 防止卸载残留状态（如 UninstallAllowAll=1）在重装后继续放行关机/重启。
    if (!guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Behavior", L"DenyIfServiceDown", L"1")
        || !guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Behavior", L"UninstallAllowAll", L"0"))
    {
        MessageBoxW(nullptr, L"failed to write config (Behavior)", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 7;
    }

    // Ensure authorization password is really wired into runtime logic.
    // If user doesn't set a dedicated auth password, fallback to maintenance password by default.
    if (!EnsureAuthTokenInitializedFromMaintenancePassword(maintenancePassword))
    {
        MessageBoxW(nullptr, L"failed to initialize auth token from maintenance password", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 7;
    }

    // Password config backup to tools dir, so uninstall can still validate even if guard.ini is deleted.
    BackupAuthToToolsBestEffort(toolsDir);

    // (7) Save and disable sleep policy (for guard behavior).
    SaveAndDisableSleepPolicy();

    // (8) Install or update the service; create logon tasks (UI + Injector).
    if (!InstallOrUpdateService(dstSvc))
    {
        MessageBoxW(nullptr, L"service install failed", L"ShutdownGuardInstall", MB_OK | MB_ICONERROR);
        return 5;
    }

    if (!HasArg(args, L"--no-schtasks"))
    {
        if (!CreateAutostartLogonTasks(installDir))
        {
            std::wcerr << L"schtasks failed\n";
            // not fatal; watchdog in service still starts UI + injector
        }
    }

    // (9) Optionally start service (--start-service).
    if (HasArg(args, L"--start-service"))
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (serviceControlManagerHandle)
        {
            SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_START);
            if (serviceHandle)
            {
                StartServiceW(serviceHandle, 0, nullptr);
                CloseServiceHandle(serviceHandle);
            }
            CloseServiceHandle(serviceControlManagerHandle);
        }
    }

    // Optional UX step: let user decide whether to set authorization password right now.
    PromptAuthorizationPasswordSetupBestEffort(dstUi, args);

    Log().Write(L"[install] installed to " + installDir);
    return 0;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int)
{
    const wchar_t* cmd = GetCommandLineW();
    if (cmd && (wcsstr(cmd, L"--help") || wcsstr(cmd, L" -h")))
    {
        const wchar_t* help = L"ShutdownGuardInstall [options]\n"
            L"  --password-file \"path\" read password from file (recommended for batch)\n"
            L"  --password-stdin     read password from stdin (redirect)\n"
            L"  --password \"pw\"      password on command line (less secure)\n"
            L"  --dir \"path\"         install dir (default: C:\\Program Files\\ShutdownGuard)\n"
            L"  --start-service      start service after install\n"
            L"  --skip-auth-setup   do not show auth-password setup prompt\n"
            L"  --no-acl             skip ACL hardening (test only)\n"
            L"  --no-schtasks        skip logon tasks\n"
            L"  --help, -h           show this and exit\n";
        MessageBoxW(nullptr, help, L"ShutdownGuardInstall --help", MB_OK);
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

