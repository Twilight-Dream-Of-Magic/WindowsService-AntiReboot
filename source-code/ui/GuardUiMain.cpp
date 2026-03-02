#include <windows.h>
#include <sddl.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <optional>
#include <thread>

#include "shared/GuardProtocol.hpp"
#include "common/IniConfig.hpp"
#include "common/SimpleLogger.hpp"
#include "common/WinPaths.hpp"
#include "ui/PasswordPromptWindow.hpp"

namespace
{
    constexpr wchar_t kServiceName[] = L"ShutdownGuard";

    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\ui.log");
        return logger;
    }

    void EnsureDefaultConfig()
    {
        guard::paths::EnsureLayout();
        const std::wstring configPath = guard::paths::ConfigPath();
        DWORD fileAttributes = GetFileAttributesW(configPath.c_str());
        if (fileAttributes != INVALID_FILE_ATTRIBUTES) return;

        guard::cfg::WriteIniString(configPath, L"General", L"Mode", L"block");
        guard::cfg::WriteIniString(configPath, L"Behavior", L"HookTimeoutMs", L"30000");
        guard::cfg::WriteIniString(configPath, L"Behavior", L"DenyIfServiceDown", L"1");
        guard::cfg::WriteIniString(configPath, L"Behavior", L"UninstallAllowAll", L"0");
        guard::cfg::WriteIniString(configPath, L"Auth", L"TokenSeconds", L"300");
        guard::cfg::WriteIniString(configPath, L"Auth", L"Iterations", L"200000");
    }

    std::wstring CurrentExeDir()
    {
        wchar_t pathBuffer[MAX_PATH] = {};
        DWORD written = GetModuleFileNameW(nullptr, pathBuffer, MAX_PATH);
        std::wstring exePath = (written > 0) ? std::wstring(pathBuffer, written) : L"";
        size_t lastSlash = exePath.find_last_of(L"\\/");
        return (lastSlash == std::wstring::npos) ? L"." : exePath.substr(0, lastSlash);
    }

    std::wstring JoinPath(const std::wstring& dir, const std::wstring& name)
    {
        if (dir.empty()) return name;
        if (dir.back() == L'\\' || dir.back() == L'/') return dir + name;
        return dir + L"\\" + name;
    }

    std::optional<std::wstring> LocateSiblingServiceExe()
    {
        const std::wstring candidatePath = JoinPath(CurrentExeDir(), L"ShutdownGuard.exe");
        DWORD fileAttributes = GetFileAttributesW(candidatePath.c_str());
        if (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            return candidatePath;
        return std::nullopt;
    }

    bool IsServiceInstalled()
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!serviceControlManagerHandle) return false;
        SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_QUERY_STATUS);
        if (!serviceHandle)
        {
            CloseServiceHandle(serviceControlManagerHandle);
            return false;
        }
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return true;
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

    void RelaunchSelfAsAdminBestEffort(const wchar_t* arg0)
    {
        wchar_t exe[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::wstring params = arg0 ? std::wstring(arg0) : L"";
        ShellExecuteW(nullptr, L"runas", exe, params.c_str(), nullptr, SW_SHOW);
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
            Sleep(250);
        }
    }

    bool TryStartServiceBestEffort()
    {
        SC_HANDLE serviceControlManagerHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!serviceControlManagerHandle) return false;
        SC_HANDLE serviceHandle = OpenServiceW(serviceControlManagerHandle, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS);
        if (!serviceHandle)
        {
            CloseServiceHandle(serviceControlManagerHandle);
            return false;
        }

        auto queryState = [&](DWORD& outState) -> bool {
            SERVICE_STATUS_PROCESS serviceStatusProcess{};
            DWORD bytes = 0;
            if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<LPBYTE>(&serviceStatusProcess), sizeof(serviceStatusProcess), &bytes))
                return false;
            outState = serviceStatusProcess.dwCurrentState;
            return true;
        };

        DWORD currentState = SERVICE_STOPPED;
        if (queryState(currentState) && currentState == SERVICE_RUNNING)
        {
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(serviceControlManagerHandle);
            return true;
        }

        if (!StartServiceW(serviceHandle, 0, nullptr))
        {
            DWORD lastError = GetLastError();
            if (lastError != ERROR_SERVICE_ALREADY_RUNNING)
            {
                CloseServiceHandle(serviceHandle);
                CloseServiceHandle(serviceControlManagerHandle);
                return false;
            }
        }

        const DWORD startTick = GetTickCount();
        for (;;)
        {
            if (!queryState(currentState))
                break;
            if (currentState == SERVICE_RUNNING)
            {
                CloseServiceHandle(serviceHandle);
                CloseServiceHandle(serviceControlManagerHandle);
                return true;
            }
            if (currentState == SERVICE_STOPPED)
                break;
            if ((GetTickCount() - startTick) > 20'000)
                break;
            Sleep(250);
        }

        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return false;
    }

    bool InstallServiceWithBinPath(const std::wstring& serviceExePath)
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

    bool UninstallService()
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
        (void)QueryServiceStopped(serviceHandle, 30'000);
        bool success = (DeleteService(serviceHandle) != FALSE);
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(serviceControlManagerHandle);
        return success;
    }

    SECURITY_ATTRIBUTES MakePipeSecurity()
    {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;

        // SYSTEM + Administrators full, Authenticated Users read/write (UI side)
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
                SDDL_REVISION_1,
                &securityDescriptor,
                nullptr))
        {
            sa.lpSecurityDescriptor = securityDescriptor;
        }
        return sa;
    }

    void FreePipeSecurity(SECURITY_ATTRIBUTES& sa)
    {
        if (sa.lpSecurityDescriptor)
            LocalFree(sa.lpSecurityDescriptor);
        sa.lpSecurityDescriptor = nullptr;
    }

    // 启动时显示的状态窗口，避免黑窗啥都没有
    constexpr wchar_t kStatusWindowClass[] = L"ShutdownGuardUI_Status";

    LRESULT CALLBACK StatusWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
        case WM_PAINT:
            {
                PAINTSTRUCT ps{};
                HDC hdc = BeginPaint(hwnd, &ps);
                RECT clientRect;
                GetClientRect(hwnd, &clientRect);
                InflateRect(&clientRect, -16, -10);
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, RGB(0xe0, 0xe0, 0xe0));
                std::wstring line1 = L"ShutdownGuard UI 已运行";
                std::wstring line2 = L"拦截到关机/重启时会弹出授权窗口。关闭本窗口即退出。";
                DrawTextW(hdc, line1.c_str(), static_cast<int>(line1.size()), &clientRect, DT_LEFT | DT_TOP | DT_SINGLELINE);
                clientRect.top += 24;
                DrawTextW(hdc, line2.c_str(), static_cast<int>(line2.size()), &clientRect, DT_LEFT | DT_TOP | DT_WORDBREAK);
                EndPaint(hwnd, &ps);
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    int RunPipeServer();

    int RunWithStatusWindow()
    {
        std::thread pipeThread([]() { RunPipeServer(); });
        pipeThread.detach();

        HINSTANCE hInst = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = StatusWndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(RGB(0x2d, 0x2d, 0x30));
        wc.lpszClassName = kStatusWindowClass;
        if (!RegisterClassExW(&wc))
            return RunPipeServer();

        const int w = 380, h = 100;
        HWND hwnd = CreateWindowExW(
            0,
            kStatusWindowClass,
            L"ShutdownGuard",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            CW_USEDEFAULT, CW_USEDEFAULT, w, h,
            nullptr, nullptr, hInst, nullptr
        );
        if (!hwnd)
            return 0;

        ShowWindow(hwnd, SW_SHOW);

        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        return static_cast<int>(msg.wParam);
    }

    int RunPipeServer()
    {
        using namespace guard::proto;

        guard::paths::EnsureLayout();
        Log().Write(L"[ui] pipe server start");

        SECURITY_ATTRIBUTES sa = MakePipeSecurity();

        constexpr LONG kMaxConcurrent = 8;
        // Concurrency limit: avoid unlimited worker threads under pipe spam.
        // 并发限制：避免在管道被大量连线时无限制建立线程。
        HANDLE connectionSemaphore = CreateSemaphoreW(nullptr, kMaxConcurrent, kMaxConcurrent, nullptr);

        auto IoReadExactWithTimeout = [](HANDLE pipeHandle, void* buffer, DWORD length, DWORD timeoutMs) -> bool {
            OVERLAPPED overlapped{};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!overlapped.hEvent) return false;
            DWORD bytesRead = 0;
            BOOL success = ReadFile(pipeHandle, buffer, length, &bytesRead, &overlapped);
            if (!success)
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_IO_PENDING)
                {
                    CloseHandle(overlapped.hEvent);
                    SetLastError(lastError);
                    return false;
                }
                DWORD wait = WaitForSingleObject(overlapped.hEvent, timeoutMs);
                if (wait != WAIT_OBJECT_0)
                {
                    CancelIoEx(pipeHandle, &overlapped);
                    CloseHandle(overlapped.hEvent);
                    SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_CANCELLED);
                    return false;
                }
                if (!GetOverlappedResult(pipeHandle, &overlapped, &bytesRead, FALSE))
                {
                    DWORD lastError2 = GetLastError();
                    CloseHandle(overlapped.hEvent);
                    SetLastError(lastError2);
                    return false;
                }
            }
            CloseHandle(overlapped.hEvent);
            return bytesRead == length;
        };

        auto IoWriteExactWithTimeout = [](HANDLE pipeHandle, const void* buffer, DWORD length, DWORD timeoutMs) -> bool {
            OVERLAPPED overlapped{};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!overlapped.hEvent) return false;
            DWORD bytesWritten = 0;
            BOOL success = WriteFile(pipeHandle, buffer, length, &bytesWritten, &overlapped);
            if (!success)
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_IO_PENDING)
                {
                    CloseHandle(overlapped.hEvent);
                    SetLastError(lastError);
                    return false;
                }
                DWORD wait = WaitForSingleObject(overlapped.hEvent, timeoutMs);
                if (wait != WAIT_OBJECT_0)
                {
                    CancelIoEx(pipeHandle, &overlapped);
                    CloseHandle(overlapped.hEvent);
                    SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_CANCELLED);
                    return false;
                }
                if (!GetOverlappedResult(pipeHandle, &overlapped, &bytesWritten, FALSE))
                {
                    DWORD err2 = GetLastError();
                    CloseHandle(overlapped.hEvent);
                    SetLastError(err2);
                    return false;
                }
            }
            CloseHandle(overlapped.hEvent);
            return bytesWritten == length;
        };

        auto handleClient = [&](HANDLE pipeHandle) {
            UiAuthRequest authRequest{};
            DWORD readTimeout = 5'000;
            if (!IoReadExactWithTimeout(pipeHandle, &authRequest, sizeof(authRequest), readTimeout))
            {
                DisconnectNamedPipe(pipeHandle);
                CloseHandle(pipeHandle);
                return;
            }

            UiAuthResponse authResponse{};
            Init(authResponse);
            authResponse.requestId = authRequest.requestId;

            if (authRequest.protocolVersion != kProtocolVersion)
            {
                authResponse.approved = 0;
            }
            else
            {
                std::wstring msg = L"检测到关机/重启行为。\r\n"
                                   L"请先输入授权密码；若连续错误，将转为维护密码验证。\r\n"
                                   L"未授权操作将被拦截并记录。";
                if (authRequest.reason[0])
                {
                    std::wstring reason = authRequest.reason;
                    const bool authPasswordWrong =
                        (reason.find(L"password incorrect") != std::wstring::npos)
                        || (reason.find(L"授权密码错误") != std::wstring::npos);
                    const bool maintenancePasswordWrong =
                        (reason.find(L"维护密码错误") != std::wstring::npos);
                    if (authPasswordWrong || maintenancePasswordWrong)
                    {
                        const wchar_t* warningText = maintenancePasswordWrong
                            ? L"维护密码错误，请重试。"
                            : L"授权密码错误，请重试。";
                        MessageBoxW(nullptr, warningText, L"ShutdownGuard", MB_OK | MB_ICONWARNING | MB_TOPMOST);
                    }
                    msg += L"\r\n\r\n原因: " + reason;
                }

                auto promptResult = guard::ui::PasswordPromptWindow::Prompt(L"ShutdownGuard 授权", msg, authRequest.timeoutMs);
                authResponse.approved = promptResult.approved ? 1u : 0u;
                if (authResponse.approved)
                    wcsncpy_s(authResponse.password, promptResult.password.c_str(), _TRUNCATE);
            }

            DWORD writeTimeout = authRequest.timeoutMs ? authRequest.timeoutMs : guard::proto::kDefaultHookTimeoutMs;
            (void)IoWriteExactWithTimeout(pipeHandle, &authResponse, sizeof(authResponse), writeTimeout);
            FlushFileBuffers(pipeHandle);

            DisconnectNamedPipe(pipeHandle);
            CloseHandle(pipeHandle);
        };

        for (;;)
        {
            HANDLE pipeHandle = CreateNamedPipeW(
                kPipeServiceToUi,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                sizeof(UiAuthResponse),
                sizeof(UiAuthRequest),
                0,
                sa.lpSecurityDescriptor ? &sa : nullptr
            );
            if (pipeHandle == INVALID_HANDLE_VALUE)
            {
                Log().Write(L"[ui] CreateNamedPipe failed err=" + std::to_wstring(GetLastError()));
                Sleep(1000);
                continue;
            }

            OVERLAPPED overlapped{};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!overlapped.hEvent)
            {
                CloseHandle(pipeHandle);
                continue;
            }

            BOOL connected = ConnectNamedPipe(pipeHandle, &overlapped);
            if (!connected)
            {
                DWORD lastError = GetLastError();
                if (lastError == ERROR_PIPE_CONNECTED)
                    SetEvent(overlapped.hEvent);
                else if (lastError != ERROR_IO_PENDING)
                {
                    CloseHandle(overlapped.hEvent);
                    CloseHandle(pipeHandle);
                    continue;
                }
            }

            DWORD wait = WaitForSingleObject(overlapped.hEvent, INFINITE);
            if (wait != WAIT_OBJECT_0)
            {
                CancelIoEx(pipeHandle, &overlapped);
                CloseHandle(overlapped.hEvent);
                CloseHandle(pipeHandle);
                continue;
            }

            DWORD dummy = 0;
            if (!GetOverlappedResult(pipeHandle, &overlapped, &dummy, FALSE))
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_PIPE_CONNECTED)
                {
                    CloseHandle(overlapped.hEvent);
                    CloseHandle(pipeHandle);
                    continue;
                }
            }
            CloseHandle(overlapped.hEvent);

            connected = TRUE;
            if (!connected)
            {
                CloseHandle(pipeHandle);
                continue;
            }

            if (connectionSemaphore && WaitForSingleObject(connectionSemaphore, 0) != WAIT_OBJECT_0)
            {
                DisconnectNamedPipe(pipeHandle);
                CloseHandle(pipeHandle);
                continue;
            }

            std::thread([&, pipeHandle]() {
                handleClient(pipeHandle);
                if (connectionSemaphore) ReleaseSemaphore(connectionSemaphore, 1, nullptr);
            }).detach();
        }

        FreePipeSecurity(sa);
        if (connectionSemaphore) CloseHandle(connectionSemaphore);
        return 0;
    }

    // 安装/卸载用密码（维护密码）
    int ConfigureMaintenancePasswordFlow()
    {
        guard::paths::EnsureLayout();
        const std::wstring configFilePath = guard::paths::ConfigPath();

        auto initialPasswordPrompt = guard::ui::PasswordPromptWindow::Prompt(
            L"设置安装/卸载密码",
            L"请输入新的安装/卸载密码（维护密码）。",
            60'000);
        if (!initialPasswordPrompt.approved || initialPasswordPrompt.password.empty()) return 2;

        auto confirmPasswordPrompt = guard::ui::PasswordPromptWindow::Prompt(
            L"设置安装/卸载密码",
            L"请再次输入相同的密码。",
            60'000);
        if (!confirmPasswordPrompt.approved || confirmPasswordPrompt.password != initialPasswordPrompt.password) return 3;

        if (!guard::cfg::SetPassword(configFilePath, initialPasswordPrompt.password))
            return 4;

        Log().Write(L"[ui] maintenance password set");
        MessageBoxW(nullptr, L"安装/卸载密码已设置完成。", L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    // 授权密码（放行关机/重启时输入）。
    // 若已存在授权密码，需先验证：可输入“当前授权密码”或“维护密码”继续修改。
    int ConfigureAuthorizationPasswordFlow()
    {
        guard::paths::EnsureLayout();
        EnsureDefaultConfig();
        const std::wstring configFilePath = guard::paths::ConfigPath();
        auto configuration = guard::cfg::Load(configFilePath);

        if (guard::cfg::HasAuthTokenConfigured(configuration))
        {
            auto identityVerificationPrompt = guard::ui::PasswordPromptWindow::Prompt(
                L"修改授权密码",
                L"已存在授权密码。\r\n请输入当前授权密码；若忘记，可输入维护密码继续。",
                60'000);
            if (!identityVerificationPrompt.approved)
                return 1;
            const bool authorizationPasswordValid = guard::cfg::VerifyAuthToken(configuration, identityVerificationPrompt.password);
            const bool maintenancePasswordValid = guard::cfg::HasPasswordConfigured(configuration)
                && guard::cfg::VerifyPassword(configuration, identityVerificationPrompt.password);
            if (!authorizationPasswordValid && !maintenancePasswordValid)
            {
                MessageBoxW(nullptr, L"授权密码与维护密码均不匹配，已拒绝修改。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
                return 5;
            }
        }

        auto newAuthorizationPasswordPrompt = guard::ui::PasswordPromptWindow::Prompt(
            L"设置授权密码",
            L"请输入新的授权密码（放行关机/重启时使用）。",
            60'000);
        if (!newAuthorizationPasswordPrompt.approved || newAuthorizationPasswordPrompt.password.empty()) return 2;

        auto confirmAuthorizationPasswordPrompt = guard::ui::PasswordPromptWindow::Prompt(
            L"设置授权密码",
            L"请再次输入相同的授权密码。",
            60'000);
        if (!confirmAuthorizationPasswordPrompt.approved
            || confirmAuthorizationPasswordPrompt.password != newAuthorizationPasswordPrompt.password) return 3;

        if (!guard::cfg::SetAuthToken(configFilePath, newAuthorizationPasswordPrompt.password))
            return 4;

        Log().Write(L"[ui] auth token password set");
        MessageBoxW(nullptr, L"授权密码已设置完成。\r\n放行关机/重启时将使用此密码。", L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    bool VerifyMaintenancePasswordInteractive(const std::wstring& title, const std::wstring& message, unsigned timeoutMs)
    {
        EnsureDefaultConfig();
        const std::wstring configFilePath = guard::paths::ConfigPath();
        auto configuration = guard::cfg::Load(configFilePath);
        if (!guard::cfg::HasPasswordConfigured(configuration))
            return false;

        auto verificationPrompt = guard::ui::PasswordPromptWindow::Prompt(title, message, timeoutMs);
        if (!verificationPrompt.approved) return false;
        return guard::cfg::VerifyPassword(configuration, verificationPrompt.password);
    }

    int InstallFlow()
    {
        guard::paths::EnsureLayout();
        EnsureDefaultConfig();

        if (!IsElevated())
        {
            RelaunchSelfAsAdminBestEffort(L"--install");
            return 0;
        }

        if (IsServiceInstalled())
        {
            const bool serviceRunning = TryStartServiceBestEffort();
            int returnCode = MessageBoxW(nullptr,
                serviceRunning
                    ? L"服务已安装，且当前正在运行。\r\n\r\n是否要设置或修改授权密码？"
                    : L"服务已安装，但当前未运行（已尝试启动失败）。\r\n请检查系统服务状态后再测试拦截效果。\r\n\r\n是否仍要设置或修改授权密码？",
                L"ShutdownGuard", MB_YESNO | MB_ICONINFORMATION);
            if (returnCode == IDYES)
                return ConfigureAuthorizationPasswordFlow();
            return 0;
        }

        const std::wstring configFilePath = guard::paths::ConfigPath();
        auto configuration = guard::cfg::Load(configFilePath);

        // If password already exists (e.g., leftover config), require it; otherwise set a new one.
        if (guard::cfg::HasPasswordConfigured(configuration))
        {
            if (!VerifyMaintenancePasswordInteractive(L"安装验证", L"请输入已有的安装/卸载密码以继续安装。", 60'000))
            {
                MessageBoxW(nullptr, L"密码错误或已取消，已拒绝安装。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
                return 2;
            }
        }
        else
        {
            int returnCode = ConfigureMaintenancePasswordFlow();
            if (returnCode != 0) return returnCode;
        }

        // 安装时一定会弹出授权密码设置；要设就输入（两次），不设就留空确定。
        MessageBoxW(nullptr,
            L"接下来设置授权密码（放行关机/重启时使用）。\r\n\r\n若要设置，请在下一窗口输入并确认；若不设置，留空并确定即可。",
            L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
        {
            auto initialAuthorizationPasswordPrompt = guard::ui::PasswordPromptWindow::Prompt(
                L"设置授权密码",
                L"请输入授权密码（放行关机/重启时使用）。\r\n留空直接确定则跳过，届时将使用安装/卸载密码。",
                120'000);
            if (!initialAuthorizationPasswordPrompt.approved)
                { /* 用户取消，继续安装，不设授权密码 */ }
            else if (initialAuthorizationPasswordPrompt.password.empty())
            {
                MessageBoxW(nullptr, L"已跳过授权密码设置。\r\n放行关机/重启时将使用安装/卸载密码。", L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
            }
            else
            {
                auto confirmAuthorizationPasswordPrompt = guard::ui::PasswordPromptWindow::Prompt(
                    L"设置授权密码",
                    L"请再次输入相同的授权密码以确认。",
                    60'000);
                if (confirmAuthorizationPasswordPrompt.approved
                    && confirmAuthorizationPasswordPrompt.password == initialAuthorizationPasswordPrompt.password)
                {
                    if (guard::cfg::SetAuthToken(configFilePath, initialAuthorizationPasswordPrompt.password))
                        Log().Write(L"[ui] auth token set during install");
                    MessageBoxW(nullptr, L"授权密码已设置完成。\r\n放行关机/重启时将使用此密码。", L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
                }
                else if (confirmAuthorizationPasswordPrompt.approved)
                    MessageBoxW(nullptr, L"两次输入不一致，已跳过设置授权密码。\r\n放行时将使用安装/卸载密码。", L"ShutdownGuard", MB_OK | MB_ICONWARNING);
            }
        }

        auto serviceExe = LocateSiblingServiceExe();
        if (!serviceExe.has_value())
        {
            MessageBoxW(nullptr, L"找不到同目录下的 ShutdownGuard.exe。请把 ShutdownGuardUI.exe 与 ShutdownGuard.exe 放在同一文件夹再执行安装。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
            return 3;
        }

        // Reset potential uninstall leftovers on install/reinstall.
        if (!guard::cfg::WriteIniString(configFilePath, L"Behavior", L"DenyIfServiceDown", L"1")
            || !guard::cfg::WriteIniString(configFilePath, L"Behavior", L"UninstallAllowAll", L"0"))
        {
            MessageBoxW(nullptr, L"写入策略配置失败。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
            return 4;
        }

        if (!InstallServiceWithBinPath(*serviceExe))
        {
            MessageBoxW(nullptr, L"安装服务失败（请以系统管理员身份运行）。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
            return 4;
        }

        const bool serviceRunning = TryStartServiceBestEffort();
        MessageBoxW(nullptr,
            serviceRunning
                ? L"安装完成，服务已启动并生效。\r\n\r\n"
                  L"建议：将 ShutdownGuardUI.exe 设置为登录自启。\r\n"
                  L"提示：服务看门狗也会尝试在登录后启动 UI。"
                : L"安装完成，但服务尚未成功启动。\r\n\r\n"
                  L"请先在“服务”中确认 ShutdownGuard 已启动，再进行拦截测试。\r\n"
                  L"（也可执行：sc start ShutdownGuard）",
            L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
        return 0;
    }

    int UninstallFlow()
    {
        guard::paths::EnsureLayout();
        EnsureDefaultConfig();

        if (!IsElevated())
        {
            RelaunchSelfAsAdminBestEffort(L"--uninstall");
            return 0;
        }

        if (!IsServiceInstalled())
        {
            MessageBoxW(nullptr, L"服务未安装。", L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
            return 0;
        }

        if (!VerifyMaintenancePasswordInteractive(L"卸载验证", L"请输入安装/卸载密码以卸载保护服务。", 60'000))
        {
            MessageBoxW(nullptr, L"密码错误或已取消，已拒绝卸载。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
            return 2;
        }

        // Stop mode BEFORE stopping service to avoid deadlock with lingering hooks.
        guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Behavior", L"DenyIfServiceDown", L"0");
        guard::cfg::WriteIniString(guard::paths::ConfigPath(), L"Behavior", L"UninstallAllowAll", L"1");

        if (!UninstallService())
        {
            MessageBoxW(nullptr, L"卸载服务失败（请以系统管理员身份运行）。", L"ShutdownGuard", MB_OK | MB_ICONERROR);
            return 3;
        }

        MessageBoxW(nullptr, L"卸载完成。", L"ShutdownGuard", MB_OK | MB_ICONINFORMATION);
        return 0;
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::vector<std::wstring> arguments;
    for (int i = 1; i < argc; ++i) arguments.emplace_back(argv[i]);

    if (!arguments.empty() && arguments[0] == L"--install")
        return InstallFlow();
    if (!arguments.empty() && arguments[0] == L"--uninstall")
        return UninstallFlow();
    if (!arguments.empty() && arguments[0] == L"--set-password")
        return ConfigureMaintenancePasswordFlow();
    if (!arguments.empty() && arguments[0] == L"--set-auth-password")
        return ConfigureAuthorizationPasswordFlow();

    // Single-instance for the UI pipe server mode.
    // Use a Global mutex so only one pipe server exists across sessions.
    // 使用 Global mutex：避免多个登录工作阶段同时跑多个 UI pipe server 造成竞态/混乱。
    HANDLE singleInstanceMutex = CreateMutexW(nullptr, TRUE, L"Global\\ShutdownGuardUI_PipeServer");
    if (singleInstanceMutex && GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(singleInstanceMutex);
        return 0;
    }

    return RunWithStatusWindow();
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

