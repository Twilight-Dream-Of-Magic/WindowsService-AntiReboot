#include "GuardPipeServer.hpp"

#include <windows.h>
#include <sddl.h>
#include <shellapi.h>
#include <string>
#include <thread>
#include <vector>

#include "shared/GuardProtocol.hpp"
#include "common/IniConfig.hpp"
#include "common/SimpleLogger.hpp"
#include "common/StrUtil.hpp"
#include "common/WinPaths.hpp"
#include "service/GuardProcessWatcher.hpp"

using guard::SimpleLogger;

namespace
{
    SimpleLogger& Log()
    {
        static SimpleLogger logger(guard::paths::LogsDir() + L"\\service.log");
        return logger;
    }

    SECURITY_ATTRIBUTES MakePipeSecurity()
    {
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;

        // 管道安全描述符 / Pipe security descriptor
        // - SYSTEM + Administrators: full control
        // - Authenticated Users: read/write (hook/UI in user session can talk to service)
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
                SDDL_REVISION_1,
                &sd,
                nullptr))
        {
            sa.lpSecurityDescriptor = sd; // freed after CreateNamedPipe returns
        }
        return sa;
    }

    void FreePipeSecurity(SECURITY_ATTRIBUTES& sa)
    {
        if (sa.lpSecurityDescriptor)
            LocalFree(sa.lpSecurityDescriptor);
        sa.lpSecurityDescriptor = nullptr;
    }

    struct RuntimeState
    {
        CRITICAL_SECTION lock{};
        ULONGLONG maintenanceExpireTick = 0;
        ULONGLONG authLockExpireTick = 0;
        DWORD lastAuthRequestId = 0;

        RuntimeState() { InitializeCriticalSection(&lock); }
        ~RuntimeState() { DeleteCriticalSection(&lock); }

        bool IsMaintenanceActive()
        {
            EnterCriticalSection(&lock);
            ULONGLONG now = GetTickCount64();
            if (maintenanceExpireTick != 0 && now > maintenanceExpireTick)
                maintenanceExpireTick = 0;
            bool active = (maintenanceExpireTick != 0);
            LeaveCriticalSection(&lock);
            return active;
        }

        void EnableMaintenance(DWORD seconds)
        {
            EnterCriticalSection(&lock);
            maintenanceExpireTick = GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000ULL;
            LeaveCriticalSection(&lock);
        }

        bool TryGetAuthLockRemainingSeconds(DWORD& outRemainingSeconds)
        {
            EnterCriticalSection(&lock);
            ULONGLONG now = GetTickCount64();
            if (authLockExpireTick != 0 && now >= authLockExpireTick)
                authLockExpireTick = 0;

            bool active = (authLockExpireTick != 0);
            if (active)
            {
                ULONGLONG remainMs = authLockExpireTick - now;
                outRemainingSeconds = static_cast<DWORD>((remainMs + 999ULL) / 1000ULL);
            }
            else
            {
                outRemainingSeconds = 0;
            }
            LeaveCriticalSection(&lock);
            return active;
        }

        void ActivateAuthLock(DWORD seconds)
        {
            EnterCriticalSection(&lock);
            authLockExpireTick = GetTickCount64() + static_cast<ULONGLONG>(seconds) * 1000ULL;
            LeaveCriticalSection(&lock);
        }

        void ClearAuthLock()
        {
            EnterCriticalSection(&lock);
            authLockExpireTick = 0;
            LeaveCriticalSection(&lock);
        }

        DWORD NextAuthRequestId()
        {
            EnterCriticalSection(&lock);
            DWORD id = ++lastAuthRequestId;
            if (id == 0) id = ++lastAuthRequestId;
            LeaveCriticalSection(&lock);
            return id;
        }
    };

    RuntimeState& State()
    {
        static RuntimeState st;
        return st;
    }

    std::wstring FormatRetryInText(DWORD seconds)
    {
        DWORD minutes = seconds / 60;
        DWORD remainSeconds = seconds % 60;
        return std::to_wstring(minutes) + L"分" + std::to_wstring(remainSeconds) + L"秒";
    }

    std::wstring RequestSummary(const guard::proto::GuardRequest& req)
    {
        std::wstring s;
        s += L"type=" + std::to_wstring(static_cast<std::uint32_t>(req.requestType));
        s += L" api=" + std::to_wstring(static_cast<std::uint32_t>(req.apiId));
        s += L" pid=" + std::to_wstring(req.processId);
        s += L" tid=" + std::to_wstring(req.threadId);
        s += L" sess=" + std::to_wstring(req.sessionId);
        if (req.imageName[0]) s += L" img=" + std::wstring(req.imageName);
        if (req.commandLine[0]) s += L" cmd=\"" + std::wstring(req.commandLine) + L"\"";
        s += L" flags=0x" + std::to_wstring(req.desiredActionFlags);
        return s;
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
        for (std::size_t i = 0; i < guard::proto::kShutdownishFlagCount; ++i)
        {
            if (ContainsTokenIgnoreCase(args, guard::proto::kShutdownishFlags[i]))
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
        return (loweredCommand.find(L"restart-computer") != std::wstring::npos)
            || (loweredCommand.find(L"stop-computer") != std::wstring::npos);
    }

    bool IsShutdownish(const guard::proto::GuardRequest& req)
    {
        using namespace guard::proto;
        if (req.requestType == RequestType::ShutdownApiCall)
            return true;

        if (req.requestType == RequestType::ProcessCreateAttempt || req.requestType == RequestType::ShellExecuteAttempt)
        {
            const std::wstring imageName = req.imageName;
            const std::wstring commandLine = req.commandLine;

            // If image itself is shutdown.exe, check flags (allow /a abort).
            if (IsShutdownExecutable(imageName))
            {
                const auto args = ParseCommandLineArgs(commandLine);
                if (ContainsTokenIgnoreCase(args, L"/a")) return false;
                return args.empty() ? true : HasShutdownActionFlag(args);
            }

            if (IsPowerShellExecutable(imageName) && ContainsPowerShellShutdownVerb(commandLine))
                return true;

            const auto args = ParseCommandLineArgs(commandLine);
            if (!args.empty() && IsShutdownExecutable(args[0]))
            {
                if (ContainsTokenIgnoreCase(args, L"/a")) return false;
                return HasShutdownActionFlag(args);
            }

            if (!args.empty() && IsPowerShellExecutable(args[0]) && ContainsPowerShellShutdownVerb(commandLine))
                return true;

            if (!args.empty() && EqualsIgnoreCase(guard::str::FileNamePart(args[0]), L"cmd.exe"))
            {
                for (size_t i = 1; i < args.size(); ++i)
                {
                    if (IsShutdownExecutable(args[i]))
                    {
                        if (ContainsTokenIgnoreCase(args, L"/a")) return false;
                        return HasShutdownActionFlag(args);
                    }
                    if (IsPowerShellExecutable(args[i]) && ContainsPowerShellShutdownVerb(commandLine))
                        return true;
                }
            }
        }
        return false;
    }

    // Overlapped I/O helper (exact size + timeout)
    // 重叠 I/O：读/写固定长度，并且有超时，避免恶意/坏 client 造成永久阻塞。
    bool IoReadExactWithTimeout(HANDLE pipe, void* buffer, DWORD byteLength, DWORD timeoutMs)
    {
        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) return false;

        DWORD bytesRead = 0;
        BOOL success = ReadFile(pipe, buffer, byteLength, &bytesRead, &overlapped);
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
                CancelIoEx(pipe, &overlapped);
                CloseHandle(overlapped.hEvent);
                SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_CANCELLED);
                return false;
            }
            if (!GetOverlappedResult(pipe, &overlapped, &bytesRead, FALSE))
            {
                DWORD lastError2 = GetLastError();
                CloseHandle(overlapped.hEvent);
                SetLastError(lastError2);
                return false;
            }
        }

        CloseHandle(overlapped.hEvent);
        return bytesRead == byteLength;
    }

    bool IoWriteExactWithTimeout(HANDLE pipe, const void* buffer, DWORD byteLength, DWORD timeoutMs)
    {
        OVERLAPPED overlapped{};
        overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!overlapped.hEvent) return false;

        DWORD bytesWritten = 0;
        BOOL success = WriteFile(pipe, buffer, byteLength, &bytesWritten, &overlapped);
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
                CancelIoEx(pipe, &overlapped);
                CloseHandle(overlapped.hEvent);
                SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_CANCELLED);
                return false;
            }
            if (!GetOverlappedResult(pipe, &overlapped, &bytesWritten, FALSE))
            {
                DWORD lastError2 = GetLastError();
                CloseHandle(overlapped.hEvent);
                SetLastError(lastError2);
                return false;
            }
        }

        CloseHandle(overlapped.hEvent);
        return bytesWritten == byteLength;
    }
}

namespace guard::service
{
    GuardPipeServer::GuardPipeServer()
    {
        guard::paths::EnsureLayout();
    }

    GuardPipeServer::~GuardPipeServer()
    {
        Stop();
    }

    bool GuardPipeServer::Start()
    {
        if (running_.exchange(true)) return false;
        hookThread_ = std::thread(&GuardPipeServer::HookServerLoop, this);
        Log().Write(L"[service] GuardPipeServer started");
        return true;
    }

    void GuardPipeServer::Stop()
    {
        if (!running_.exchange(false)) return;
        if (hookThread_.joinable())
            hookThread_.join();
        Log().Write(L"[service] GuardPipeServer stopped");
    }

    bool GuardPipeServer::SendAuthRequestAndWait(const std::wstring& reason, DWORD sessionId, DWORD timeoutMs, std::wstring& outPassword)
    {
        using namespace guard::proto;

        // UI agent runs as pipe SERVER. Service connects only when needed.
        if (!WaitNamedPipeW(kPipeServiceToUi, timeoutMs))
        {
            Log().Write(L"[auth] UI pipe not available");
            return false;
        }

        HANDLE pipeConnectionHandle = CreateFileW(
            kPipeServiceToUi,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr
        );
        if (pipeConnectionHandle == INVALID_HANDLE_VALUE)
        {
            Log().Write(L"[auth] CreateFile UI pipe failed err=" + std::to_wstring(GetLastError()));
            return false;
        }

        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(pipeConnectionHandle, &mode, nullptr, nullptr);

        UiAuthRequest req{};
        Init(req);
        req.requestId = State().NextAuthRequestId();
        req.timeoutMs = timeoutMs;
        req.sessionId = sessionId;
        wcsncpy_s(req.reason, reason.c_str(), _TRUNCATE);

        DWORD ioTimeout = timeoutMs ? timeoutMs : guard::proto::kDefaultHookTimeoutMs;
        if (!IoWriteExactWithTimeout(pipeConnectionHandle, &req, sizeof(req), ioTimeout))
        {
            CloseHandle(pipeConnectionHandle);
            Log().Write(L"[auth] WriteFile UI pipe failed err=" + std::to_wstring(GetLastError()));
            return false;
        }

        UiAuthResponse authResponse{};
        if (!IoReadExactWithTimeout(pipeConnectionHandle, &authResponse, sizeof(authResponse), ioTimeout))
        {
            CloseHandle(pipeConnectionHandle);
            Log().Write(L"[auth] ReadFile UI pipe failed err=" + std::to_wstring(GetLastError()));
            return false;
        }
        CloseHandle(pipeConnectionHandle);

        if (authResponse.protocolVersion != kProtocolVersion || authResponse.requestId != req.requestId)
        {
            Log().Write(L"[auth] UI response mismatch");
            return false;
        }
        if (authResponse.approved == 0)
        {
            Log().Write(L"[auth] UI denied/timeout");
            return false;
        }

        outPassword = authResponse.password;
        return true;
    }

    void GuardPipeServer::HookServerLoop()
    {
        using namespace guard::proto;

        SECURITY_ATTRIBUTES sa = MakePipeSecurity();
        Log().Write(L"[pipe] HookToService server loop start");

        constexpr LONG kMaxConcurrent = 32;
        HANDLE concurrencyLimitSemaphore = CreateSemaphoreW(nullptr, kMaxConcurrent, kMaxConcurrent, nullptr);

        auto handleClient = [&](HANDLE namedPipeHandle) {
            GuardRequest request{};
            GuardResponse policyResponse{};
            Init(policyResponse);

            DWORD readTimeout = 5'000;
            bool requestReadOk = IoReadExactWithTimeout(namedPipeHandle, &request, sizeof(request), readTimeout);

            if (!requestReadOk)
            {
                policyResponse.decision = Decision::Deny;
                policyResponse.win32ErrorToReturn = (GetLastError() == ERROR_TIMEOUT) ? ERROR_TIMEOUT : ERROR_INVALID_DATA;
                wcscpy_s(policyResponse.message, L"invalid request");
            }
            else if (request.protocolVersion != kProtocolVersion)
            {
                policyResponse.decision = Decision::Deny;
                policyResponse.win32ErrorToReturn = ERROR_REVISION_MISMATCH;
                wcscpy_s(policyResponse.message, L"protocol mismatch");
            }
            else
            {
                const std::wstring iniPath = guard::paths::ConfigPath();
                auto settings = guard::cfg::Load(iniPath);
                const DWORD uninstallAllowAll = guard::cfg::ReadIniDword(iniPath, L"Behavior", L"UninstallAllowAll", 0);
                const bool uninstallPrepareRequested = guard::service::IsWatcherStopRequested();
                const bool observe = (settings.mode == guard::cfg::Mode::Observe);
                const bool maint = State().IsMaintenanceActive();
                const bool shutdownish = IsShutdownish(request);

                std::wstring logLine = L"[REQ] " + RequestSummary(request);

                // Fail-safe: if config says "uninstall allow-all" but service never received prepare-uninstall signal,
                // treat it as stale residue and recover secure defaults immediately.
                if (shutdownish && uninstallAllowAll != 0 && !uninstallPrepareRequested)
                {
                    (void)guard::cfg::WriteIniString(iniPath, L"Behavior", L"UninstallAllowAll", L"0");
                    (void)guard::cfg::WriteIniString(iniPath, L"Behavior", L"DenyIfServiceDown", L"1");
                    Log().Write(L"[pipe] stale uninstall mode detected without prepare signal; recovered defaults");
                }

                if (uninstallAllowAll != 0 && uninstallPrepareRequested && shutdownish)
                {
                    policyResponse.decision = Decision::Allow;
                    policyResponse.win32ErrorToReturn = ERROR_SUCCESS;
                    wcscpy_s(policyResponse.message, L"uninstall mode allow");
                    logLine += L" => ALLOW(uninstall-prepare)";
                }
                else if (observe)
                {
                    policyResponse.decision = Decision::Allow;
                    policyResponse.win32ErrorToReturn = ERROR_SUCCESS;
                    wcscpy_s(policyResponse.message, L"observe mode allow");
                    logLine += L" => ALLOW(observe)";
                }
                else if (!shutdownish)
                {
                    policyResponse.decision = Decision::Allow;
                    policyResponse.win32ErrorToReturn = ERROR_SUCCESS;
                    wcscpy_s(policyResponse.message, L"policy allow");
                    logLine += L" => ALLOW";
                }
                else if (maint)
                {
                    policyResponse.decision = Decision::Allow;
                    policyResponse.win32ErrorToReturn = ERROR_SUCCESS;
                    wcscpy_s(policyResponse.message, L"maintenance allow");
                    logLine += L" => ALLOW(maint)";
                }
                else if (!guard::cfg::HasAuthTokenConfigured(settings) && !guard::cfg::HasPasswordConfigured(settings))
                {
                    policyResponse.decision = Decision::Deny;
                    policyResponse.win32ErrorToReturn = ERROR_ACCESS_DENIED;
                    wcscpy_s(policyResponse.message, L"password not configured");
                    logLine += L" => DENY(no-password)";
                }
                else
                {
                    // Authorization flow (service-side, single source of truth):
                    // - phase A: authorization password up to 3 attempts,
                    // - phase B: maintenance password up to 3 attempts,
                    // - both failed: activate cooldown lock (no more UI prompt, deny all until expire).
                    const bool hasAuthPassword = guard::cfg::HasAuthTokenConfigured(settings);
                    const bool hasMaintenancePassword = guard::cfg::HasPasswordConfigured(settings);

                    DWORD lockRemainingSeconds = 0;
                    if (State().TryGetAuthLockRemainingSeconds(lockRemainingSeconds))
                    {
                        policyResponse.decision = Decision::Deny;
                        policyResponse.win32ErrorToReturn = ERROR_ACCESS_DENIED;
                        std::wstring lockMessage = L"系统自我保护中，请在 " + FormatRetryInText(lockRemainingSeconds) + L" 后重试";
                        wcsncpy_s(policyResponse.message, lockMessage.c_str(), _TRUNCATE);
                        logLine += L" => DENY(lockout " + std::to_wstring(lockRemainingSeconds) + L"s left)";
                    }
                    else
                    {
                        DWORD lockSeconds = guard::cfg::ReadIniDword(iniPath, L"Behavior", L"AuthLockSeconds", 300);
                        if (lockSeconds < 30) lockSeconds = 30;
                        if (lockSeconds > 24 * 60 * 60) lockSeconds = 24 * 60 * 60;

                        const int authAttemptsMax = hasAuthPassword ? guard::proto::kAuthPasswordMaxAttempts : 0;
                        const int maintenanceAttemptsMax = hasMaintenancePassword ? guard::proto::kMaintenancePasswordMaxAttempts : 0;
                        const int totalAttempts = authAttemptsMax + maintenanceAttemptsMax;

                        const DWORD totalAuthorizationBudgetMs = request.timeoutHintMs
                            ? request.timeoutHintMs
                            : (settings.hookTimeoutMs ? settings.hookTimeoutMs : guard::proto::kDefaultHookTimeoutMs);
                        const DWORD minimumAttemptBudget = static_cast<DWORD>(totalAttempts > 0 ? totalAttempts : 1);
                        const DWORD minAuthorizationBudgetMs =
                            guard::proto::kDefaultHookTimeoutMs * minimumAttemptBudget;
                        const DWORD effectiveAuthorizationBudgetMs =
                            (totalAuthorizationBudgetMs < minAuthorizationBudgetMs) ? minAuthorizationBudgetMs : totalAuthorizationBudgetMs;

                        bool authorizationGranted = false;
                        bool hadPasswordInput = false;
                        bool authorizationTimeoutOrCancelled = false;
                        int authWrongCount = 0;
                        int maintenanceWrongCount = 0;
                        const ULONGLONG authBeginTick = GetTickCount64();

                        auto computeAttemptTimeout = [&](int attemptsRemaining) -> DWORD {
                            if (attemptsRemaining <= 0)
                                return 0;
                            const ULONGLONG elapsedMs = GetTickCount64() - authBeginTick;
                            if (elapsedMs >= effectiveAuthorizationBudgetMs)
                                return 0;
                            DWORD remainingMs = effectiveAuthorizationBudgetMs - static_cast<DWORD>(elapsedMs);
                            DWORD timeoutPerAttempt = remainingMs / static_cast<DWORD>(attemptsRemaining);
                            if (timeoutPerAttempt == 0)
                                timeoutPerAttempt = remainingMs;
                            return timeoutPerAttempt;
                        };

                        if (authAttemptsMax > 0)
                        {
                            for (int attempt = 1; attempt <= authAttemptsMax; ++attempt)
                            {
                                const int attemptsRemaining =
                                    (authAttemptsMax - attempt + 1) + maintenanceAttemptsMax;
                                DWORD attemptTimeoutMs = computeAttemptTimeout(attemptsRemaining);
                                if (attemptTimeoutMs == 0)
                                {
                                    authorizationTimeoutOrCancelled = true;
                                    break;
                                }

                                std::wstring promptReason = (attempt == 1)
                                    ? L"检测到关机/重启行为，请输入授权密码。"
                                    : L"授权密码错误，请重试。";
                                std::wstring password;
                                bool passwordSubmitted = SendAuthRequestAndWait(promptReason, request.sessionId, attemptTimeoutMs, password);
                                if (!passwordSubmitted)
                                {
                                    authorizationTimeoutOrCancelled = true;
                                    break;
                                }

                                hadPasswordInput = true;
                                if (guard::cfg::VerifyAuthToken(settings, password))
                                {
                                    authorizationGranted = true;
                                    break;
                                }

                                authWrongCount++;
                            }
                        }

                        if (!authorizationGranted && maintenanceAttemptsMax > 0)
                        {
                            const bool enterMaintenancePhase =
                                (authAttemptsMax == 0) || (authWrongCount >= authAttemptsMax);
                            if (enterMaintenancePhase)
                            {
                                for (int attempt = 1; attempt <= maintenanceAttemptsMax; ++attempt)
                                {
                                    const int attemptsRemaining = maintenanceAttemptsMax - attempt + 1;
                                    DWORD attemptTimeoutMs = computeAttemptTimeout(attemptsRemaining);
                                    if (attemptTimeoutMs == 0)
                                    {
                                        authorizationTimeoutOrCancelled = true;
                                        break;
                                    }

                                    std::wstring promptReason;
                                    if (attempt == 1)
                                    {
                                        promptReason = (authAttemptsMax > 0)
                                            ? L"授权密码连续错误 " + std::to_wstring(authAttemptsMax) + L" 次，请输入维护密码。"
                                            : L"请输入维护密码以放行本次关机/重启。";
                                    }
                                    else
                                    {
                                        promptReason = L"维护密码错误，请重试。";
                                    }

                                    std::wstring password;
                                    bool passwordSubmitted = SendAuthRequestAndWait(promptReason, request.sessionId, attemptTimeoutMs, password);
                                    if (!passwordSubmitted)
                                    {
                                        authorizationTimeoutOrCancelled = true;
                                        break;
                                    }

                                    hadPasswordInput = true;
                                    if (guard::cfg::VerifyPassword(settings, password))
                                    {
                                        authorizationGranted = true;
                                        break;
                                    }

                                    maintenanceWrongCount++;
                                }
                            }
                        }

                        if (authorizationGranted)
                        {
                            State().ClearAuthLock();
                            State().EnableMaintenance(settings.tokenSeconds ? settings.tokenSeconds : 300);
                            policyResponse.decision = Decision::Allow;
                            policyResponse.win32ErrorToReturn = ERROR_SUCCESS;
                            wcscpy_s(policyResponse.message, L"authorized allow");
                            logLine += L" => ALLOW(auth)";
                        }
                        else
                        {
                            const bool authPhaseExhausted = (authAttemptsMax > 0 && authWrongCount >= authAttemptsMax);
                            const bool maintenancePhaseExhausted = (maintenanceAttemptsMax > 0 && maintenanceWrongCount >= maintenanceAttemptsMax);
                            const bool shouldActivateLock =
                                (authAttemptsMax > 0 && maintenanceAttemptsMax == 0 && authPhaseExhausted)
                                || (maintenanceAttemptsMax > 0 && (
                                    (authAttemptsMax == 0 && maintenancePhaseExhausted) ||
                                    (authAttemptsMax > 0 && authPhaseExhausted && maintenancePhaseExhausted)));

                            policyResponse.decision = Decision::Deny;
                            policyResponse.win32ErrorToReturn = ERROR_ACCESS_DENIED;

                            if (shouldActivateLock)
                            {
                                State().ActivateAuthLock(lockSeconds);
                                std::wstring lockMessage = L"系统自我保护中，请在 " + FormatRetryInText(lockSeconds) + L" 后重试";
                                wcsncpy_s(policyResponse.message, lockMessage.c_str(), _TRUNCATE);
                                logLine += L" => DENY(lockout " + std::to_wstring(lockSeconds) + L"s)";
                            }
                            else if (hadPasswordInput)
                            {
                                wcscpy_s(policyResponse.message, L"密码错误");
                                logLine += L" => DENY(password)";
                            }
                            else if (authorizationTimeoutOrCancelled)
                            {
                                wcscpy_s(policyResponse.message, L"授权超时或取消");
                                logLine += L" => DENY(timeout)";
                            }
                            else
                            {
                                wcscpy_s(policyResponse.message, L"authorization denied");
                                logLine += L" => DENY";
                            }
                        }
                    }
                }

                Log().Write(logLine);
            }

            DWORD writeTimeout = request.timeoutHintMs ? request.timeoutHintMs : guard::proto::kDefaultHookTimeoutMs;
            if (writeTimeout < guard::proto::kMinHookTimeoutMs) writeTimeout = guard::proto::kMinHookTimeoutMs;
            (void)IoWriteExactWithTimeout(namedPipeHandle, &policyResponse, sizeof(policyResponse), writeTimeout);
            FlushFileBuffers(namedPipeHandle);

            DisconnectNamedPipe(namedPipeHandle);
            CloseHandle(namedPipeHandle);
        };

        while (running_.load())
        {
            HANDLE namedPipeHandle = CreateNamedPipeW(
                kPipeHookToService,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                sizeof(GuardResponse),
                sizeof(GuardRequest),
                1000,
                sa.lpSecurityDescriptor ? &sa : nullptr
            );

            if (namedPipeHandle == INVALID_HANDLE_VALUE)
            {
                Log().Write(L"[pipe] CreateNamedPipe failed err=" + std::to_wstring(GetLastError()));
                Sleep(500);
                continue;
            }

            OVERLAPPED overlapped{};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!overlapped.hEvent)
            {
                CloseHandle(namedPipeHandle);
                continue;
            }

            BOOL connected = ConnectNamedPipe(namedPipeHandle, &overlapped);
            if (!connected)
            {
                DWORD lastError = GetLastError();
                if (lastError == ERROR_PIPE_CONNECTED)
                {
                    SetEvent(overlapped.hEvent);
                }
                else if (lastError != ERROR_IO_PENDING)
                {
                    CloseHandle(overlapped.hEvent);
                    CloseHandle(namedPipeHandle);
                    continue;
                }
            }

            while (running_.load())
            {
                DWORD wait = WaitForSingleObject(overlapped.hEvent, 200);
                if (wait == WAIT_OBJECT_0) break;
                if (wait != WAIT_TIMEOUT) break;
            }

            if (!running_.load())
            {
                CancelIoEx(namedPipeHandle, &overlapped);
                CloseHandle(overlapped.hEvent);
                CloseHandle(namedPipeHandle);
                continue;
            }

            DWORD dummy = 0;
            if (!GetOverlappedResult(namedPipeHandle, &overlapped, &dummy, FALSE))
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_PIPE_CONNECTED)
                {
                    CloseHandle(overlapped.hEvent);
                    CloseHandle(namedPipeHandle);
                    continue;
                }
            }
            CloseHandle(overlapped.hEvent);

            if (concurrencyLimitSemaphore && WaitForSingleObject(concurrencyLimitSemaphore, 0) != WAIT_OBJECT_0)
            {
                // 並發滿載：回傳明確的「忙碌」回應，讓 Hook 端可區分於「服務不可用」並可重試。
                GuardResponse busyResponse{};
                Init(busyResponse);
                busyResponse.decision = Decision::Deny;
                busyResponse.win32ErrorToReturn = ERROR_BUSY;
                wcscpy_s(busyResponse.message, L"server busy; retry");
                (void)IoWriteExactWithTimeout(namedPipeHandle, &busyResponse, sizeof(busyResponse), 5'000);
                FlushFileBuffers(namedPipeHandle);
                DisconnectNamedPipe(namedPipeHandle);
                CloseHandle(namedPipeHandle);
                continue;
            }

            std::thread([&, namedPipeHandle]() {
                handleClient(namedPipeHandle);
                if (concurrencyLimitSemaphore) ReleaseSemaphore(concurrencyLimitSemaphore, 1, nullptr);
            }).detach();
        }

        if (concurrencyLimitSemaphore) CloseHandle(concurrencyLimitSemaphore);
        FreePipeSecurity(sa);
        Log().Write(L"[pipe] HookToService server loop stop");
    }
}

