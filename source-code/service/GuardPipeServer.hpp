#pragma once
#include <windows.h>
#include <atomic>
#include <string>
#include <thread>

namespace guard::service
{
    class GuardPipeServer
    {
    public:
        GuardPipeServer();
        ~GuardPipeServer();

        GuardPipeServer(const GuardPipeServer&) = delete;
        GuardPipeServer& operator=(const GuardPipeServer&) = delete;

        bool Start();
        void Stop();

    private:
        std::atomic<bool> running_{ false };
        std::thread hookThread_;

        void HookServerLoop();

        bool SendAuthRequestAndWait(const std::wstring& reason, DWORD sessionId, DWORD timeoutMs, std::wstring& outPassword);
    };
}

