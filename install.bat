@echo off
REM Save this file as UTF-8 with CRLF line endings when deploying to other machines.
chcp 65001 >nul 2>&1
title ShutdownGuard 一键安装

:: ============================================
::  ShutdownGuard 一键安装脚本
::  使用方式：右键 -> 以管理员身份运行
:: ============================================

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [错误] 需要管理员权限。
    echo        请右键此脚本，选择 "以管理员身份运行"。
    echo.
    pause
    exit /b 1
)

set "SCRIPT_DIR=%~dp0"

:: 检查必要档案
set "MISSING="
for %%f in (
    ShutdownGuardInstall.exe
    ShutdownGuard.exe
    ShutdownGuardUI.exe
    ShutdownGuardInjector.exe
    ShutdownGuardHook.dll
    ShutdownGuardUninstall.exe
) do (
    if not exist "%SCRIPT_DIR%%%f" (
        echo [缺少] %%f
        set "MISSING=1"
    )
)
if defined MISSING (
    echo.
    echo [错误] 请确保以上档案与此脚本放在同一目录。
    pause
    exit /b 2
)

echo.
echo ==========================================
echo   ShutdownGuard 一键安装
echo ==========================================
echo.
echo  安装后，本机的关机和重启操作都需要输入密码。
echo  请牢记此密码。
echo " 遗忘只能通过物理断电进安全模式恢复。"
echo.

:: 读取密码（两次确认）
set /p "PW=  设定维护密码: "
if "%PW%"=="" (
    echo [错误] 密码不能为空。
    pause
    exit /b 3
)
set /p "PW2=  再次确认密码: "
if not "%PW%"=="%PW2%" (
    echo.
    echo [错误] 两次输入不一致，安装中止。
    set "PW=" & set "PW2="
    pause
    exit /b 3
)

echo.
echo [1/5] 正在安装档案、注册服务...
set "INSTALL_EXE=%SCRIPT_DIR%ShutdownGuardInstall.exe"
set "PWFILE=%SCRIPT_DIR%ShutdownGuard_pw_%RANDOM%.tmp"
echo %PW%> "%PWFILE%"
"%INSTALL_EXE%" --password-file "%PWFILE%" --start-service
set "INSTALL_ERR=%errorlevel%"
del /f /q "%PWFILE%" 2>nul
if %INSTALL_ERR% neq 0 (
    echo [错误] 安装失败，错误代码：%INSTALL_ERR%
    echo        若为 -1073741819，请确认：64位系统、杀毒未拦截、或直接运行 ShutdownGuardInstall.exe 测试。
    set "PW=" & set "PW2="
    pause
    exit /b %INSTALL_ERR%
)

echo [2/5] 禁用睡眠和休眠策略...
powercfg /change standby-timeout-ac 0 >nul 2>&1
powercfg /change standby-timeout-dc 0 >nul 2>&1
powercfg /change hibernate-timeout-ac 0 >nul 2>&1
powercfg /change hibernate-timeout-dc 0 >nul 2>&1
powercfg /hibernate off >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowSleepOption /t REG_DWORD /d 0 /f >nul 2>&1

echo [3/5] 等待服务启动...
timeout /t 3 /nobreak >nul

echo [4/5] 启动注入器...
start "" /b "%ProgramFiles%\ShutdownGuard\ShutdownGuardInjector.exe"
timeout /t 2 /nobreak >nul

echo [5/5] 启动 UI 守护...
start "" "%ProgramFiles%\ShutdownGuard\ShutdownGuardUI.exe"

:: 清除内存中的密码
set "PW="
set "PW2="
del /f /s /q %PWFILE%


echo.
echo ==========================================
echo   安装成功！
echo ------------------------------------------
echo   服务状态：已启动（开机自动运行）
echo   防护范围：关机 + 重启 + 睡眠 + 休眠
echo   卸载方式：运行 uninstall.bat
echo ==========================================
echo.
pause
