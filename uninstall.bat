@echo off
setlocal enabledelayedexpansion
REM Save as UTF-8 with CRLF when deploying to other machines.
chcp 65001 >nul 2>&1
title ShutdownGuard 一键卸载

:: ============================================
::  ShutdownGuard 一键卸载脚本
::  使用方式：请以管理员身份运行
:: ============================================

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [错误] 需要管理员权限。
    set "MSG=请右键此脚本，选择 以管理员身份运行"
    echo        !MSG!
    echo.
    pause
    exit /b 1
)

:: 卸载程序位置（安装时放在 ProgramData\ShutdownGuardTools 下）
set "UNINSTALL_EXE=%ProgramData%\ShutdownGuardTools\ShutdownGuardUninstall.exe"

if not exist "%UNINSTALL_EXE%" (
    echo.
    echo [错误] 找不到卸载程序：
    echo        %UNINSTALL_EXE%
    echo.
    echo 请联系维护人员执行应急恢复流程。
    pause
    exit /b 2
)

set "SCRIPT_DIR=%~dp0"

echo.
echo ==========================================
echo   ShutdownGuard 一键卸载
echo ==========================================
echo.
echo  卸载后，本机的关机/重启防护将被完全移除。
echo.

set /p "PW=  输入维护密码: "
if "%PW%"=="" (
    echo [错误] 密码不能为空。
    pause
    exit /b 3
)

echo.
echo [信息] 还原睡眠和休眠策略...
powercfg /hibernate on >nul 2>&1
powercfg /change standby-timeout-ac 30 >nul 2>&1
powercfg /change hibernate-timeout-ac 60 >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowSleepOption /t REG_DWORD /d 1 /f >nul 2>&1

echo.
echo [信息] 正在卸载，请稍候（可能需要 30-60 秒）...
echo.
set "PWFILE=%SCRIPT_DIR%ShutdownGuard_pw_%RANDOM%.tmp"
echo %PW%> "%PWFILE%"
"%UNINSTALL_EXE%" --password-file "%PWFILE%"
set "RESULT=%errorlevel%"
del /f /s /q "%PWFILE%"

:: 清除密码
set "PW="

if %RESULT% equ 1 (
    echo.
    echo [错误] 卸载程序要求管理员权限（请以管理员身份运行）。
    pause
    exit /b 1
)
if %RESULT% equ 2 (
    echo.
    echo [错误] 维护密码为空或验证失败。
    pause
    exit /b 2
)
if not %RESULT%==0 if not %RESULT%==6 (
    echo.
    echo [错误] 卸载程序返回未预期错误码：%RESULT%
    echo        请查看日志后重试，或联系维护人员。
    pause
    exit /b %RESULT%
)

echo.
echo ==========================================
echo   卸载完成
echo ==========================================
echo   已完成：
echo   - 服务已移除，注入器已停止
echo   - 关机/重启/睡眠/休眠 防护已全部解除
echo   - 睡眠和休眠策略已还原
if %RESULT% equ 6 (
    echo.
    echo   待完成：
    echo   - 部分目录已登记为「重启后删除」
    echo   - 请重启电脑以彻底清理残留目录
    echo.
    echo   当前不影响系统使用。
) else (
    echo   - 安装档案已清理，无残留
)
echo ==========================================
echo.
pause
exit /b %RESULT%
