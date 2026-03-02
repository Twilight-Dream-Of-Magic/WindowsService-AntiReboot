#include <windows.h>
#include <atomic>

#include "hook/HookInstall.hpp"

namespace
{
    // One-time init guard for hook installation thread.
    // 初始化保护：避免重复建立安装 hook 的线程。
    std::atomic<bool> g_initialized{ false };

    DWORD WINAPI InitThread(LPVOID)
    {
        guard::hook::InstallHooks();
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        {
            bool expected = false;
            if (g_initialized.compare_exchange_strong(expected, true))
            {
                HANDLE threadHandle = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
                if (!threadHandle)
                    g_initialized.store(false);  // 创建失败则重置，便于后续重试或 DETACH 时不误调 RemoveHooks
                else
                    CloseHandle(threadHandle);
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        // reserved == NULL：DLL 被 FreeLibrary 卸载，可做收尾。
        // reserved != NULL：进程正在退出，MSDN 建议「什么都不做直接 return」；此时卸 hook 无意义且可能危险（loader lock、其他线程已停）。
        // 本项目卸载时是 TerminateProcess 结束进程，故实务上几乎总是 reserved != NULL，RemoveHooks 很少被调到；若有人显式 FreeLibrary 则会正常卸 hook。
        if (reserved == nullptr)
            guard::hook::RemoveHooks();
        break;
    default:
        break;
    }
    return TRUE;
}

