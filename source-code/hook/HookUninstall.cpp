#include "hook/HookUninstall.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <cstring>

namespace guard::hook
{
    namespace
    {
        void EnableDebugPrivilegeBestEffort()
        {
            HANDLE token = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) || !token)
                return;
            TOKEN_PRIVILEGES tp{};
            if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
            {
                CloseHandle(token);
                return;
            }
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            CloseHandle(token);
        }

        // 当前进程架构：用于与目标进程比较，避免 WoW64 下用错 RVA 导致目标进程崩溃。
        static USHORT GetSelfMachine()
        {
#if defined(_WIN64)
            return IMAGE_FILE_MACHINE_AMD64;
#else
            return IMAGE_FILE_MACHINE_I386;
#endif
        }

        // 目标进程与当前进程是否同架构。仅同架构时才能用本进程的 FreeLibrary RVA 做 RemoteFreeLibrary。
        bool IsTargetSameBitness(DWORD processId)
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
            if (!hProcess) return false;

            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

            using FnIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
            auto pIsWow64Process2 = reinterpret_cast<FnIsWow64Process2>(
                GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
            if (pIsWow64Process2 && pIsWow64Process2(hProcess, &processMachine, &nativeMachine))
            {
                CloseHandle(hProcess);
                USHORT target = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) ? processMachine : nativeMachine;
                USHORT self = GetSelfMachine();
                if (target == IMAGE_FILE_MACHINE_UNKNOWN || self == IMAGE_FILE_MACHINE_UNKNOWN)
                    return true; // 检测失败时保守放行，由 RemoteFreeLibrary 自行承担风险
                return target == self;
            }

            BOOL isWow64 = FALSE;
            if (!IsWow64Process(hProcess, &isWow64))
            {
                CloseHandle(hProcess);
                return true; // 无法检测时保守放行
            }
            SYSTEM_INFO si{};
            GetNativeSystemInfo(&si);
            switch (si.wProcessorArchitecture)
            {
            case PROCESSOR_ARCHITECTURE_AMD64: nativeMachine = IMAGE_FILE_MACHINE_AMD64; break;
            case PROCESSOR_ARCHITECTURE_INTEL:  nativeMachine = IMAGE_FILE_MACHINE_I386; break;
            default: break;
            }
            processMachine = isWow64 ? IMAGE_FILE_MACHINE_I386 : nativeMachine;
            CloseHandle(hProcess);
            USHORT target = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) ? processMachine : nativeMachine;
            USHORT self = GetSelfMachine();
            if (target == IMAGE_FILE_MACHINE_UNKNOWN || self == IMAGE_FILE_MACHINE_UNKNOWN)
                return true;
            return target == self;
        }

        // 取得本进程内 FreeLibrary 相对于 kernel32 基址的 RVA（目标进程内 kernel32+RVA 即为该进程的 FreeLibrary）。
        // 仅对与当前进程同架构的目标进程有效；WoW64 下异架构须跳过 RemoteFreeLibrary。
        bool GetFreeLibraryRelativeVirtualAddress(ULONG_PTR& outRelativeVirtualAddress)
        {
            HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
            if (!hKernel32) return false;
            FARPROC pFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");
            if (!pFreeLibrary) return false;
            outRelativeVirtualAddress = reinterpret_cast<ULONG_PTR>(pFreeLibrary) - reinterpret_cast<ULONG_PTR>(hKernel32);
            return true;
        }

        // 对指定进程做 CreateRemoteThread(FreeLibrary, ourDllBase)，等待线程结束。返回是否成功卸载。
        // 调用方须保证目标进程与当前进程同架构（否则 RVA 错误会导致目标崩溃）。
        bool RemoteFreeLibrary(DWORD processId, ULONG_PTR freeLibraryRelativeVirtualAddress, const std::wstring& normalizedInstallDirectory)
        {
            HANDLE processHandle = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                FALSE, processId);
            if (!processHandle) return false;

            HMODULE ourHookModuleHandle = nullptr;
            HMODULE kernel32ModuleHandle = nullptr;
            auto enumerateModulesInProcess = [&](DWORD snapshotFlags) -> bool {
                HANDLE moduleSnapshotHandle = CreateToolhelp32Snapshot(snapshotFlags, processId);
                if (moduleSnapshotHandle == INVALID_HANDLE_VALUE) return false;
                MODULEENTRY32W moduleEntry{};
                moduleEntry.dwSize = sizeof(moduleEntry);
                bool foundOurHookDll = false;
                bool foundKernel32 = false;
                if (Module32FirstW(moduleSnapshotHandle, &moduleEntry))
                {
                    do
                    {
                        if (_wcsicmp(moduleEntry.szModule, L"ShutdownGuardHook.dll") == 0)
                        {
                            if (moduleEntry.szExePath[0] && normalizedInstallDirectory.size() > 0 &&
                                _wcsnicmp(moduleEntry.szExePath, normalizedInstallDirectory.c_str(), normalizedInstallDirectory.size()) == 0)
                            {
                                ourHookModuleHandle = moduleEntry.hModule;
                                foundOurHookDll = true;
                            }
                        }
                        else if (_wcsicmp(moduleEntry.szModule, L"kernel32.dll") == 0)
                        {
                            kernel32ModuleHandle = moduleEntry.hModule;
                            foundKernel32 = true;
                        }
                    } while (Module32NextW(moduleSnapshotHandle, &moduleEntry));
                }
                CloseHandle(moduleSnapshotHandle);
                return foundOurHookDll && foundKernel32;
            };
            if (!enumerateModulesInProcess(TH32CS_SNAPMODULE) && !enumerateModulesInProcess(TH32CS_SNAPMODULE32))
            {
                CloseHandle(processHandle);
                return false;
            }

            ULONG_PTR targetProcessFreeLibraryAddress = reinterpret_cast<ULONG_PTR>(kernel32ModuleHandle) + freeLibraryRelativeVirtualAddress;
            HANDLE remoteThreadHandle = CreateRemoteThread(
                processHandle, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(targetProcessFreeLibraryAddress),
                ourHookModuleHandle, 0, nullptr);
            if (!remoteThreadHandle)
            {
                CloseHandle(processHandle);
                return false;
            }
            WaitForSingleObject(remoteThreadHandle, 8000);
            CloseHandle(remoteThreadHandle);
            CloseHandle(processHandle);
            return true;
        }
    }

    void UninstallHooksFromAllProcessesBestEffort(const std::wstring& installDir)
    {
        if (installDir.empty()) return;
        EnableDebugPrivilegeBestEffort();

        std::wstring normalizedInstallDirectory = installDir;
        if (normalizedInstallDirectory.back() != L'\\')
            normalizedInstallDirectory += L'\\';

        ULONG_PTR freeLibraryRelativeVirtualAddress = 0;
        if (!GetFreeLibraryRelativeVirtualAddress(freeLibraryRelativeVirtualAddress)) return;

        const DWORD selfProcessId = GetCurrentProcessId();
        HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (processSnapshotHandle == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (!Process32FirstW(processSnapshotHandle, &processEntry)) { CloseHandle(processSnapshotHandle); return; }

        do
        {
            if (processEntry.th32ProcessID == selfProcessId) continue;
            auto processHasOurHookDll = [&](DWORD snapshotFlags) -> bool {
                HANDLE moduleSnapshotHandle = CreateToolhelp32Snapshot(snapshotFlags, processEntry.th32ProcessID);
                if (moduleSnapshotHandle == INVALID_HANDLE_VALUE) return false;
                MODULEENTRY32W moduleEntry{};
                moduleEntry.dwSize = sizeof(moduleEntry);
                bool found = false;
                if (Module32FirstW(moduleSnapshotHandle, &moduleEntry))
                {
                    do
                    {
                        if (_wcsicmp(moduleEntry.szModule, L"ShutdownGuardHook.dll") != 0) continue;
                        if (!moduleEntry.szExePath[0] || normalizedInstallDirectory.empty()) continue;
                        if (_wcsnicmp(moduleEntry.szExePath, normalizedInstallDirectory.c_str(), normalizedInstallDirectory.size()) == 0)
                            found = true;
                    } while (Module32NextW(moduleSnapshotHandle, &moduleEntry));
                }
                CloseHandle(moduleSnapshotHandle);
                return found;
            };
            if (processHasOurHookDll(TH32CS_SNAPMODULE) || processHasOurHookDll(TH32CS_SNAPMODULE32))
            {
                // WoW64: 仅对与卸载程序同架构的进程做 RemoteFreeLibrary，避免 64 位 RVA 注入 32 位进程导致崩溃。
                if (IsTargetSameBitness(processEntry.th32ProcessID))
                    RemoteFreeLibrary(processEntry.th32ProcessID, freeLibraryRelativeVirtualAddress, normalizedInstallDirectory);
            }
        } while (Process32NextW(processSnapshotHandle, &processEntry));

        CloseHandle(processSnapshotHandle);
    }
}
