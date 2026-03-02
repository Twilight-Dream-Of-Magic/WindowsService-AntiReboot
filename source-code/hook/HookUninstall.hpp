#pragma once

#include <string>

namespace guard::hook
{
    // 与 HookInstall（InstallHooks）对应：从所有载有 ShutdownGuardHook.dll（路径在 installDir 下）的进程中，
    // 远程调用 FreeLibrary 卸载 DLL，使 DllMain(DLL_PROCESS_DETACH, reserved=nullptr) 执行、RemoveHooks() 被调用。
    // 不杀进程；卸不掉的留给后续 TerminateProcessesUsingHookDllBestEffort 终止。
    void UninstallHooksFromAllProcessesBestEffort(const std::wstring& installDir);
}
