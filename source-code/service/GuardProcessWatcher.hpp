#pragma once

namespace guard::service
{
    // Runs in a dedicated thread: subscribes to WMI Win32_ProcessStartTrace,
    // and immediately launches the injector with --pid for any new process
    // whose image name is in the hook target list (cmd.exe, powershell.exe, etc.).
    // Call from service main after SetStatus(SERVICE_RUNNING); pass injector exe path.

    void RunProcessWatcherThread(const wchar_t* injectorExePath);

    // 卸载前调用：让 Watcher 线程退出，不再对新进程注入。发送控制码 129 后服务会调此函数。
    void RequestWatcherStop();
    void ResetWatcherStopRequest();
    bool IsWatcherStopRequested();
}
