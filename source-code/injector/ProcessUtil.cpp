#include "ProcessUtil.hpp"

#include <tlhelp32.h>
#include <string>

namespace guard::inject
{
    namespace
    {
        struct ProcessMachineInfo
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            bool success = false;
        };

        ProcessMachineInfo QueryMachineInfo(HANDLE processHandle)
        {
            ProcessMachineInfo machineInfo{};

            // Prefer IsWow64Process2 when available (Win10+).
            using FnIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
            auto isWow64Process2Function = reinterpret_cast<FnIsWow64Process2>(
                GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
            if (isWow64Process2Function)
            {
                USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
                if (isWow64Process2Function(processHandle, &processMachine, &nativeMachine))
                {
                    machineInfo.processMachine = processMachine;
                    machineInfo.nativeMachine = nativeMachine;
                    machineInfo.success = true;
                    return machineInfo;
                }
            }

            // Fallback: IsWow64Process + GetNativeSystemInfo.
            BOOL isWow64Process = FALSE;
            if (!IsWow64Process(processHandle, &isWow64Process))
                return machineInfo;

            SYSTEM_INFO si{};
            GetNativeSystemInfo(&si);
            switch (si.wProcessorArchitecture)
            {
            case PROCESSOR_ARCHITECTURE_AMD64: machineInfo.nativeMachine = IMAGE_FILE_MACHINE_AMD64; break;
            case PROCESSOR_ARCHITECTURE_ARM64: machineInfo.nativeMachine = IMAGE_FILE_MACHINE_ARM64; break;
            case PROCESSOR_ARCHITECTURE_INTEL: machineInfo.nativeMachine = IMAGE_FILE_MACHINE_I386; break;
            default: machineInfo.nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN; break;
            }

            machineInfo.processMachine = isWow64Process ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_UNKNOWN;
            machineInfo.success = true;
            return machineInfo;
        }

        USHORT EffectiveMachine(const ProcessMachineInfo& machineInfo)
        {
            return (machineInfo.processMachine != IMAGE_FILE_MACHINE_UNKNOWN) ? machineInfo.processMachine : machineInfo.nativeMachine;
        }

        // Only inject when injector and target process bitness match.
        // 仅在注入器与目标进程位数一致时注入，避免远端执行错位数的 LoadLibraryW 造成崩溃。
        bool IsInjectionBitnessCompatible(HANDLE targetProcessHandle)
        {
            ProcessMachineInfo machineInfo = QueryMachineInfo(targetProcessHandle);
            if (!machineInfo.success) return true; // best effort: don't block injection on detection failure

            const USHORT target = EffectiveMachine(machineInfo);
#if defined(_WIN64)
            const USHORT self = IMAGE_FILE_MACHINE_AMD64;
#else
            const USHORT self = IMAGE_FILE_MACHINE_I386;
#endif
            if (target == IMAGE_FILE_MACHINE_UNKNOWN || self == IMAGE_FILE_MACHINE_UNKNOWN)
                return true;
            return target == self;
        }
    }

    bool EnablePrivilege(const wchar_t* privName)
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return false;

        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, privName, &luid))
        {
            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        BOOL success = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        DWORD lastError = GetLastError();
        CloseHandle(token);
        return success && (lastError == ERROR_SUCCESS);
    }

    std::vector<DWORD> FindPidsByImageName(const std::wstring& imageName)
    {
        std::vector<DWORD> pids;
        HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (processSnapshotHandle == INVALID_HANDLE_VALUE) return pids;

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (Process32FirstW(processSnapshotHandle, &processEntry))
        {
            do
            {
                if (_wcsicmp(processEntry.szExeFile, imageName.c_str()) == 0)
                    pids.push_back(processEntry.th32ProcessID);
            } while (Process32NextW(processSnapshotHandle, &processEntry));
        }

        CloseHandle(processSnapshotHandle);
        return pids;
    }

    bool InjectLoadLibraryW(DWORD pid, const std::wstring& dllPath, DWORD& outWin32Error)
    {
        outWin32Error = ERROR_SUCCESS;
        if (pid == 0) { outWin32Error = ERROR_INVALID_PARAMETER; return false; }

        HANDLE targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
        if (!targetProcessHandle)
        {
            outWin32Error = GetLastError();
            return false;
        }

        if (!IsInjectionBitnessCompatible(targetProcessHandle))
        {
            outWin32Error = ERROR_NOT_SUPPORTED;
            CloseHandle(targetProcessHandle);
            return false;
        }

        SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
        void* remoteBuffer = VirtualAllocEx(targetProcessHandle, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteBuffer)
        {
            outWin32Error = GetLastError();
            CloseHandle(targetProcessHandle);
            return false;
        }

        if (!WriteProcessMemory(targetProcessHandle, remoteBuffer, dllPath.c_str(), bytes, nullptr))
        {
            outWin32Error = GetLastError();
            VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(targetProcessHandle);
            return false;
        }

        HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
        FARPROC pLoadLibraryW = hKernel ? GetProcAddress(hKernel, "LoadLibraryW") : nullptr;
        if (!pLoadLibraryW)
        {
            outWin32Error = ERROR_PROC_NOT_FOUND;
            VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(targetProcessHandle);
            return false;
        }

        HANDLE remoteThreadHandle = CreateRemoteThread(targetProcessHandle, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW),
            remoteBuffer, 0, nullptr);
        if (!remoteThreadHandle)
        {
            outWin32Error = GetLastError();
            VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(targetProcessHandle);
            return false;
        }

        DWORD wait = WaitForSingleObject(remoteThreadHandle, 10'000);
        if (wait != WAIT_OBJECT_0)
        {
            outWin32Error = (wait == WAIT_TIMEOUT) ? ERROR_TIMEOUT : GetLastError();
            // If the remote thread is still running, freeing the remote buffer can crash it.
            // Leave the allocation behind as a last-resort safety trade-off.
            CloseHandle(remoteThreadHandle);
            CloseHandle(targetProcessHandle);
            return false;
        }

        DWORD exitCode = 0;
        if (!GetExitCodeThread(remoteThreadHandle, &exitCode))
        {
            outWin32Error = GetLastError();
            CloseHandle(remoteThreadHandle);
            VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(targetProcessHandle);
            return false;
        }

        CloseHandle(remoteThreadHandle);
        VirtualFreeEx(targetProcessHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(targetProcessHandle);

        if (exitCode == 0)
        {
            outWin32Error = ERROR_MOD_NOT_FOUND;
            return false;
        }

        return true;
    }
}

