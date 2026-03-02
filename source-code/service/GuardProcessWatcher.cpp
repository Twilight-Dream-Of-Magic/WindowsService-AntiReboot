#include "service/GuardProcessWatcher.hpp"
#include "common/SimpleLogger.hpp"
#include "common/WinPaths.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <vector>
#include <set>
#include <atomic>
#include <cstring>

#ifdef _MSC_VER
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#endif

namespace guard::service
{
    std::atomic<bool> g_watcherStopRequested{ false };

    namespace
    {
        guard::SimpleLogger& WatcherLog()
        {
            static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\process_watcher.log");
            return logger;
        }

        const wchar_t* const kTargetImages[] = {
            L"explorer.exe", L"cmd.exe", L"powershell.exe", L"pwsh.exe",
            L"shutdown.exe", L"schtasks.exe", L"wmiprvse.exe", L"runtimebroker.exe", L"rundll32.exe"
        };

        std::wstring ToLower(std::wstring s)
        {
            for (auto& c : s)
                if (c >= L'A' && c <= L'Z') c += (L'a' - L'A');
            return s;
        }

        bool IsTargetImage(const std::wstring& processName)
        {
            std::wstring lower = ToLower(processName);
            for (const wchar_t* t : kTargetImages)
                if (lower == t) return true;
            return false;
        }

        void LaunchInjectorForPid(const wchar_t* injectorExePath, DWORD processId)
        {
            if (!injectorExePath || processId == 0) return;
            std::wstring line = L"\"" + std::wstring(injectorExePath) + L"\" --pid " + std::to_wstring(processId);
            std::vector<wchar_t> cmdLine(line.begin(), line.end());
            cmdLine.push_back(L'\0');
            STARTUPINFOW si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            if (CreateProcessW(
                    injectorExePath,
                    cmdLine.data(),
                    nullptr, nullptr, FALSE,
                    CREATE_NO_WINDOW,
                    nullptr, nullptr, &si, &pi))
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                WatcherLog().Write(L"[watcher] injected new pid=" + std::to_wstring(processId));
            }
            else
                WatcherLog().Write(L"[watcher] failed launch injector for pid=" + std::to_wstring(processId) + L" err=" + std::to_wstring(GetLastError()));
        }

#ifdef _MSC_VER
        void WatcherLoop(const std::wstring& injectorPath)
        {
            HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
            {
                WatcherLog().Write(L"[watcher] CoInitializeEx failed hr=" + std::to_wstring(static_cast<unsigned>(hr)));
                return;
            }

            IWbemLocator* loc = nullptr;
            hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&loc));
            if (FAILED(hr) || !loc)
            {
                WatcherLog().Write(L"[watcher] CoCreateInstance WbemLocator failed");
                CoUninitialize();
                return;
            }

            BSTR nameSpace = SysAllocString(L"ROOT\\CIMV2");
            IWbemServices* svc = nullptr;
            hr = loc->ConnectServer(
                nameSpace,
                nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
            SysFreeString(nameSpace);
            loc->Release();
            loc = nullptr;
            if (FAILED(hr) || !svc)
            {
                WatcherLog().Write(L"[watcher] ConnectServer failed");
                CoUninitialize();
                return;
            }

            hr = CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            if (FAILED(hr))
            {
                svc->Release();
                CoUninitialize();
                return;
            }

            BSTR wql = SysAllocString(L"WQL");
            BSTR query = SysAllocString(L"SELECT * FROM Win32_ProcessStartTrace");
            IEnumWbemClassObject* penum = nullptr;
            hr = svc->ExecNotificationQuery(
                wql, query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &penum);
            SysFreeString(wql);
            SysFreeString(query);
            svc->Release();
            svc = nullptr;
            if (FAILED(hr) || !penum)
            {
                WatcherLog().Write(L"[watcher] ExecNotificationQuery failed hr=" + std::to_wstring(static_cast<unsigned>(hr)));
                CoUninitialize();
                return;
            }

            WatcherLog().Write(L"[watcher] WMI subscription active");
            const wchar_t* path = injectorPath.c_str();

            for (;;)
            {
                if (guard::service::g_watcherStopRequested.load()) { WatcherLog().Write(L"[watcher] stop requested, exiting"); break; }
                IWbemClassObject* obj = nullptr;
                ULONG returned = 0;
                hr = penum->Next(2000, 1, &obj, &returned);
                if (hr != WBEM_S_NO_ERROR || returned == 0 || !obj)
                    continue;

                VARIANT vName, vPid;
                VariantInit(&vName);
                VariantInit(&vPid);
                obj->Get(L"ProcessName", 0, &vName, nullptr, nullptr);
                obj->Get(L"ProcessID", 0, &vPid, nullptr, nullptr);

                DWORD processId = 0;
                if (vPid.vt == VT_I4) processId = static_cast<DWORD>(vPid.lVal);
                else if (vPid.vt == VT_UI4) processId = static_cast<DWORD>(vPid.ulVal);
                if (vName.vt == VT_BSTR && vName.bstrVal && processId != 0)
                {
                    std::wstring name(vName.bstrVal);
                    if (IsTargetImage(name))
                        LaunchInjectorForPid(path, processId);
                }
                VariantClear(&vName);
                VariantClear(&vPid);
                obj->Release();
            }
        }
#else
        // MinGW/Clang: no wbemuuid.lib; use polling via CreateToolhelp32Snapshot.
        void WatcherLoop(const std::wstring& injectorPath)
        {
            // 輪詢間隔宜短，否則像 powershell -Command "Restart-Computer -Force" 會在未被注入前就執行完。
            // 兩次輪詢之間啟動並立即執行關機的進程，有可能在注入前就結束，此為輪詢模式的固有限制。
            WatcherLog().Write(L"[watcher] polling mode (no WMI)");
            const wchar_t* path = injectorPath.c_str();
            std::set<DWORD> injectedPids;
            const DWORD kPollMs = 400;

            for (;;)
            {
                if (guard::service::g_watcherStopRequested.load()) { WatcherLog().Write(L"[watcher] stop requested, exiting"); break; }
                HANDLE processSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (processSnapshotHandle == INVALID_HANDLE_VALUE)
                {
                    Sleep(kPollMs);
                    continue;
                }
                PROCESSENTRY32W processEntry{};
                processEntry.dwSize = sizeof(processEntry);
                if (Process32FirstW(processSnapshotHandle, &processEntry))
                {
                    do
                    {
                        if (processEntry.th32ProcessID == 0) continue;
                        if (injectedPids.count(processEntry.th32ProcessID)) continue;
                        if (!IsTargetImage(processEntry.szExeFile)) continue;
                        injectedPids.insert(processEntry.th32ProcessID);
                        LaunchInjectorForPid(path, processEntry.th32ProcessID);
                    } while (Process32NextW(processSnapshotHandle, &processEntry));
                }
                CloseHandle(processSnapshotHandle);
                Sleep(kPollMs);
            }
        }
#endif
    }

    void RunProcessWatcherThread(const wchar_t* injectorExePath)
    {
        if (!injectorExePath) return;
        std::wstring path(injectorExePath);
        std::thread t([path]() { WatcherLoop(path); });
        t.detach();
    }

    void RequestWatcherStop()
    {
        g_watcherStopRequested.store(true);
    }

    void ResetWatcherStopRequest()
    {
        g_watcherStopRequested.store(false);
    }

    bool IsWatcherStopRequested()
    {
        return g_watcherStopRequested.load();
    }
}
