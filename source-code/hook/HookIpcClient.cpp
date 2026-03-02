#include "HookIpcClient.hpp"

#include <windows.h>
#include <string>

#include "common/IniConfig.hpp"
#include "common/WinPaths.hpp"
#include "common/SimpleLogger.hpp"

namespace
{
    // Last service message is used only for diagnostics/logging.
    // 服务端回复消息仅用于诊断/日志（每线程一份，避免 data race）。
    thread_local std::wstring g_lastServiceMessage;
    thread_local std::wstring g_lastConsoleMessage;
    thread_local ULONGLONG g_lastConsoleMessageTick = 0;

    guard::SimpleLogger& Log()
    {
        static guard::SimpleLogger logger(guard::paths::LogsDir() + L"\\hook_ipc.log");
        return logger;
    }

    bool ShouldDenyWhenServiceUnavailable()
    {
        const std::wstring configPath = guard::paths::ConfigPath();
        DWORD attr = GetFileAttributesW(configPath.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES)
            return true; // fail-closed when config is missing/corrupted
        return guard::cfg::ReadIniDword(configPath, L"Behavior", L"DenyIfServiceDown", 1) != 0;
    }

    void PrintDenyReasonToCommandLine(const std::wstring& reason)
    {
        if (reason.empty())
            return;

        const ULONGLONG nowTick = GetTickCount64();
        if (!g_lastConsoleMessage.empty() && g_lastConsoleMessage == reason
            && g_lastConsoleMessageTick != 0 && (nowTick - g_lastConsoleMessageTick) < 1500)
        {
            return;
        }
        g_lastConsoleMessage = reason;
        g_lastConsoleMessageTick = nowTick;

        HANDLE standardErrorHandle = GetStdHandle(STD_ERROR_HANDLE);
        if (standardErrorHandle == nullptr || standardErrorHandle == INVALID_HANDLE_VALUE)
            return;

        std::wstring outputLine = L"[ShutdownGuard] " + reason + L"\r\n";
        DWORD fileType = GetFileType(standardErrorHandle);
        if (fileType == FILE_TYPE_CHAR)
        {
            DWORD charsWritten = 0;
            (void)WriteConsoleW(standardErrorHandle, outputLine.c_str(), static_cast<DWORD>(outputLine.size()), &charsWritten, nullptr);
            return;
        }

        int utf8Bytes = WideCharToMultiByte(
            CP_UTF8, 0,
            outputLine.c_str(),
            static_cast<int>(outputLine.size()),
            nullptr, 0, nullptr, nullptr);
        if (utf8Bytes <= 0)
            return;
        std::string utf8;
        utf8.resize(static_cast<size_t>(utf8Bytes));
        if (WideCharToMultiByte(
                CP_UTF8, 0,
                outputLine.c_str(),
                static_cast<int>(outputLine.size()),
                utf8.data(), utf8Bytes, nullptr, nullptr) <= 0)
            return;
        DWORD bytesWritten = 0;
        (void)WriteFile(standardErrorHandle, utf8.data(), static_cast<DWORD>(utf8.size()), &bytesWritten, nullptr);
    }

    // Send one request to the service pipe and read back a fixed-size response.
    // 送出一次请求到服务管道，并读回固定大小回复（Overlapped + timeout 防卡死）。
    bool SendRequestToService(const guard::proto::GuardRequest& request, guard::proto::GuardResponse& outResponse)
    {
        using namespace guard::proto;

        DWORD baseTimeoutMs = request.timeoutHintMs ? request.timeoutHintMs : kDefaultHookTimeoutMs;
        if (baseTimeoutMs < kDefaultHookTimeoutMs)
            baseTimeoutMs = kDefaultHookTimeoutMs;

        // Service may perform multi-attempt interactive auth inside one arbitration request.
        // Extend client-side pipe wait budget so response timeout and server-side retry budget stay consistent.
        const ULONGLONG scaledTimeoutMs = static_cast<ULONGLONG>(baseTimeoutMs)
            * static_cast<ULONGLONG>(kAuthorizationMaxAttempts > 0 ? kAuthorizationMaxAttempts : 1);
        const DWORD requestTimeoutMs = (scaledTimeoutMs > static_cast<ULONGLONG>(0xFFFFFFFFULL))
            ? 0xFFFFFFFFUL
            : static_cast<DWORD>(scaledTimeoutMs);

        GuardRequest outboundRequest = request;
        outboundRequest.timeoutHintMs = requestTimeoutMs;
        if (!WaitNamedPipeW(kPipeHookToService, requestTimeoutMs))
            return false;

        HANDLE pipeConnectionHandle = CreateFileW(
            kPipeHookToService,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr
        );
        if (pipeConnectionHandle == INVALID_HANDLE_VALUE)
            return false;

        DWORD pipeMode = PIPE_READMODE_MESSAGE;
        (void)SetNamedPipeHandleState(pipeConnectionHandle, &pipeMode, nullptr, nullptr);

        auto IoWithTimeout = [&](auto&& startIo, DWORD expectedBytes) -> bool {
            OVERLAPPED overlapped{};
            overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!overlapped.hEvent) return false;
            DWORD transferred = 0;
            BOOL ok = startIo(&transferred, &overlapped);
            if (!ok)
            {
                DWORD err = GetLastError();
                if (err != ERROR_IO_PENDING)
                {
                    CloseHandle(overlapped.hEvent);
                    SetLastError(err);
                    return false;
                }
                DWORD wait = WaitForSingleObject(overlapped.hEvent, requestTimeoutMs);
                if (wait != WAIT_OBJECT_0)
                {
                    CancelIoEx(pipeConnectionHandle, &overlapped);
                    CloseHandle(overlapped.hEvent);
                    SetLastError(wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_CANCELLED);
                    return false;
                }
                if (!GetOverlappedResult(pipeConnectionHandle, &overlapped, &transferred, FALSE))
                {
                    DWORD err2 = GetLastError();
                    CloseHandle(overlapped.hEvent);
                    SetLastError(err2);
                    return false;
                }
            }
            CloseHandle(overlapped.hEvent);
            return (transferred == expectedBytes);
        };

        if (!IoWithTimeout([&](DWORD* out, OVERLAPPED* ov) { return WriteFile(pipeConnectionHandle, &outboundRequest, sizeof(outboundRequest), out, ov); }, sizeof(outboundRequest)))
        {
            CloseHandle(pipeConnectionHandle);
            return false;
        }

        if (!IoWithTimeout([&](DWORD* out, OVERLAPPED* ov) { return ReadFile(pipeConnectionHandle, &outResponse, sizeof(outResponse), out, ov); }, sizeof(outResponse)))
        {
            CloseHandle(pipeConnectionHandle);
            return false;
        }

        CloseHandle(pipeConnectionHandle);
        return true;
    }
}

namespace guard::hook
{
    bool DecideOrDeny(const guard::proto::GuardRequest& request)
    {
        using namespace guard::proto;
        guard::paths::EnsureLayout();

        GuardResponse serviceResponse{};
        Init(serviceResponse);
        if (!SendRequestToService(request, serviceResponse))
        {
            g_lastServiceMessage = L"service unavailable";
            if (ShouldDenyWhenServiceUnavailable())
            {
                SetLastError(ERROR_ACCESS_DENIED);
                return false;
            }
            return true;
        }

        g_lastServiceMessage = serviceResponse.message;
        if (serviceResponse.decision == Decision::Allow || serviceResponse.decision == Decision::ObserveOnly)
            return true;

        PrintDenyReasonToCommandLine(g_lastServiceMessage);
        SetLastError(serviceResponse.win32ErrorToReturn ? serviceResponse.win32ErrorToReturn : ERROR_ACCESS_DENIED);
        return false;
    }

    std::wstring LastServiceMessage()
    {
        return g_lastServiceMessage;
    }
}

