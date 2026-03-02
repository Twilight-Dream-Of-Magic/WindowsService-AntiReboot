#pragma once
#include <windows.h>
#include <cstdint>
#include <type_traits>

namespace guard::proto
{
    // Named pipes (local machine)
    inline constexpr wchar_t kPipeHookToService[] = LR"(\\.\pipe\ShutdownGuard\HookToService)";
    inline constexpr wchar_t kPipeServiceToUi[]   = LR"(\\.\pipe\ShutdownGuard\ServiceToUi)";

    inline constexpr std::uint32_t kProtocolVersion = 1;
    inline constexpr DWORD kDefaultHookTimeoutMs = 30'000;
    inline constexpr DWORD kMinHookTimeoutMs = 1'000;
    // Interactive auth policy:
    // - authorization password: 3 attempts
    // - maintenance password: 3 attempts (fallback/secondary)
    inline constexpr int kAuthPasswordMaxAttempts = 3;
    inline constexpr int kMaintenancePasswordMaxAttempts = 3;
    inline constexpr int kAuthorizationMaxAttempts = kAuthPasswordMaxAttempts + kMaintenancePasswordMaxAttempts;

    // Shutdown-ish command-line flags for shutdown.exe (CreateProcess/ShellExecute). Shared by hook and service.
    inline constexpr std::size_t kShutdownishFlagCount = 9;
    inline constexpr const wchar_t* kShutdownishFlags[kShutdownishFlagCount] = {
        L"/s", L"/r", L"/p", L"/g", L"/sg", L"/hybrid", L"/fw", L"/o", L"/h"
    };
    inline constexpr std::uint32_t kMaxText = 260;

    enum class RequestType : std::uint32_t
    {
        Unknown = 0,
        ShutdownApiCall = 1,
        ProcessCreateAttempt = 2,
        ShellExecuteAttempt = 3,
    };

    enum class ApiId : std::uint32_t
    {
        Unknown = 0,

        ExitWindowsEx,
        InitiateShutdownW,
        InitiateShutdownA,
        InitiateSystemShutdownExW,
        InitiateSystemShutdownExA,
        InitiateSystemShutdownW,
        InitiateSystemShutdownA,
        NtShutdownSystem,
        NtSetSystemPowerState,
        SetSuspendState,

        CreateProcessW,
        CreateProcessA,
        ShellExecuteExW,
        ShellExecuteExA,
    };

    enum class Decision : std::uint32_t
    {
        Deny = 0,
        Allow = 1,
        ObserveOnly = 2,
    };

#pragma pack(push, 1)
    struct GuardRequest final
    {
        std::uint32_t protocolVersion;
        RequestType requestType;
        ApiId apiId;

        DWORD processId;
        DWORD threadId;
        DWORD sessionId;

        DWORD desiredActionFlags;  // parameters summary (e.g. EWX_REBOOT)
        DWORD timeoutHintMs;       // max wait time for arbitration

        wchar_t processPath[kMaxText];
        wchar_t imageName[kMaxText];
        wchar_t commandLine[kMaxText];
        wchar_t userName[kMaxText];
    };

    struct GuardResponse final
    {
        std::uint32_t protocolVersion;
        Decision decision;
        DWORD win32ErrorToReturn;
        DWORD reserved;
        wchar_t message[kMaxText];
    };

    // Service -> UI: request interactive auth.
    struct UiAuthRequest final
    {
        std::uint32_t protocolVersion;
        DWORD requestId;
        DWORD timeoutMs;
        DWORD sessionId;
        wchar_t reason[kMaxText];
    };

    // UI -> Service: answer for auth request.
    struct UiAuthResponse final
    {
        std::uint32_t protocolVersion;
        DWORD requestId;
        std::uint32_t approved; // 0=deny, nonzero=allow (fixed width for ABI stability)
        DWORD reserved;
        wchar_t password[kMaxText]; // MVP: plaintext; validated only in service
    };
#pragma pack(pop)

    static_assert(std::is_trivially_copyable_v<GuardRequest>);
    static_assert(std::is_trivially_copyable_v<GuardResponse>);
    static_assert(std::is_trivially_copyable_v<UiAuthRequest>);
    static_assert(std::is_trivially_copyable_v<UiAuthResponse>);

    // ABI sanity checks (pack(1) + fixed-width fields): adjust only with protocol version bump.
    static_assert(sizeof(GuardRequest) == (4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + (kMaxText * sizeof(wchar_t)) * 4), "GuardRequest size unexpected");
    static_assert(sizeof(GuardResponse) == (4 + 4 + 4 + 4 + (kMaxText * sizeof(wchar_t))), "GuardResponse size unexpected");
    static_assert(sizeof(UiAuthRequest) == (4 + 4 + 4 + 4 + (kMaxText * sizeof(wchar_t))), "UiAuthRequest size unexpected");
    static_assert(sizeof(UiAuthResponse) == (4 + 4 + 4 + 4 + (kMaxText * sizeof(wchar_t))), "UiAuthResponse size unexpected");

    inline void Init(GuardRequest& r)
    {
        ZeroMemory(&r, sizeof(r));
        r.protocolVersion = kProtocolVersion;
        r.timeoutHintMs = kDefaultHookTimeoutMs;
    }

    inline void Init(GuardResponse& r)
    {
        ZeroMemory(&r, sizeof(r));
        r.protocolVersion = kProtocolVersion;
        r.decision = Decision::Deny;
        r.win32ErrorToReturn = ERROR_ACCESS_DENIED;
    }

    inline void Init(UiAuthRequest& r)
    {
        ZeroMemory(&r, sizeof(r));
        r.protocolVersion = kProtocolVersion;
        r.timeoutMs = kDefaultHookTimeoutMs;
    }

    inline void Init(UiAuthResponse& r)
    {
        ZeroMemory(&r, sizeof(r));
        r.protocolVersion = kProtocolVersion;
        r.approved = 0;
    }
}

