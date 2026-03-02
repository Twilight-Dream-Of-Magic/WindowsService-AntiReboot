# ShutdownGuard 卸载状态说明

本文说明卸载流程中可能出现的「阶段」与「残留」，以及如何判断是否正常、如何恢复到未安装状态。

---

## 安装 / 卸载对照（无遗漏）

卸载会还原安装时做过的所有变更（含两种安装入口：`ShutdownGuardInstall.exe` 与 `ShutdownGuard.exe --install`）：

| 安装时做的 | 卸载时对应 |
|------------|------------|
| 建立 ToolsDir、ApplyToolsDir ACL | 删除 ToolsDir（排程自删或重启后删）；卸载前锁一次 ACL（防伪造 token） |
| 建立安装目录、备份原始 ACL → `install_dir_acl.sddl`、写入 InstallDir/ToolsDir/InstallDirAclBackup | 还原 ACL（从 sddl 或继承）→ RemoveTree(安装目录)；失败则登记重启后删除 |
| 复制服务/UI/Injector/Hook、复制 Uninstall 到 ToolsDir | 终止带 Hook 的进程、终止 UI/Injector、停服务 → 删除安装目录、删除 ProgramData 状态 |
| 对安装目录做「防误删」ACL | 还原 ACL 后再删目录 |
| 写入 guard.ini（InstallDir/ToolsDir/UninstallExe 等）、BackupAuthToTools（auth_backup.ini） | 删除整个 ProgramData\ShutdownGuard（含 guard.ini、logs）；ToolsDir 连同 auth_backup 一并删除 |
| SaveAndDisableSleepPolicy（powercfg + ShowSleepOption 注册表） | RestoreSleepPolicyBestEffort（powercfg 还原 + ShowSleepOption 还原） |
| InstallOrUpdateService（SCM 服务）、CreateLogonTasks（schtasks UI/Injector） | 停止并删除服务；DeleteLogonTasksBestEffort；**DeleteRunKeysBestEffort**（Run 键由服务 --install 写入时） |

Run 键：若曾用 **ShutdownGuard.exe --install** 会写入 `HKLM\...\Run` 的 `ShutdownGuardUI`、`ShutdownGuardInjector`；独立卸载程序会一并删除，与安装对齐。

---

## 两阶段卸载（设计意图）

卸载分为：

- **阶段 A（在线卸载）**：验证维护密码 → 进入停止模式（一律放行、停止注入器）→ 解除已注入进程 → 停服务 → 删除能删的文件与目录。若目录仍被占用，则**登记为「重启后删除」**。
- **阶段 B（重启后清理）**：系统在下次重启时自动删除已登记的目录；或用户手动删除残留目录。

不强求「一键瞬间删光」，避免与 Windows 句柄/占用对抗，同时保持**可恢复、边界清楚**。

---

## 哪些组件可能延迟删除（句柄占用）

| 组件 | 原因 | 处理方式 |
|------|------|----------|
| 安装目录 `C:\Program Files\ShutdownGuard\` | 曾载入 `ShutdownGuardHook.dll` 的进程（如 WmiPrvSE、explorer、cmd）尚未全部结束，或文件仍被锁定 | 卸载程序会调用 `MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT)` 登记「重启后删除」；或重启后手动删除 |
| ProgramData 目录 `C:\ProgramData\ShutdownGuard\` | 同上，或日志/配置仍被读取 | 同上 |
| Tools 目录 `C:\ProgramData\ShutdownGuardTools\` | 卸载程序自身或脚本仍在使用 | 卸载程序会排程「退出后自删」；若残留可重启后手动删除 |

**服务、驱动、注入器逻辑**：在阶段 A 已停止并从 SCM 移除，**不会**延迟。关机/重启防护在阶段 A 结束后即已解除。

---

## 重启后必清 / 可选清理

- **必清**：若卸载时回传「部分目录已登记为重启后删除」，**重启后**系统会自动删除已登记路径；若未自动删除，可手动删除残留目录。
- **可选**：日志目录 `C:\ProgramData\ShutdownGuard\logs\` 若需审计可保留，否则可一并删除。

---

## 日志 / 配置残留是否保留

| 内容 | 建议 |
|------|------|
| `guard.ini`、`install_dir_acl.sddl` | 卸载成功后通常已随 ProgramData 目录删除；若目录残留则可手动删除或保留作审计 |
| `logs\*.log` | 可保留用于事后排查；不需审计则可删除 |

---

## 用户看到残留目录时该如何判断

- **卸载脚本已显示「卸载完成」且注明「部分目录将在重启后自动删除」**  
  → 属正常。防护已解除，不影响使用。重启后再检查目录是否消失；若仍在，可手动删除。

- **卸载脚本报错（例如错误代码 4/5/6）**  
  → 表示部分目录在线无法删除。若为 6，程序已尝试登记重启后删除；可重启后再观察或手动删除。若为 4/5，建议重启后再执行一次卸载脚本或手动删除。

- **仅剩空目录或少量文件**  
  → 不影响系统。可直接手动删除或留待重启后系统清理。

---

## 一键恢复到「未安装状态」的步骤

1. **以管理员身份**执行 `uninstall.bat`（或 `ShutdownGuardUninstall.exe` 并输入维护密码）。
2. 若脚本显示「部分目录已登记为重启后删除」：**重启电脑**。
3. 重启后检查：
   - `C:\Program Files\ShutdownGuard\` 是否已消失；若在，手动删除。
   - `C:\ProgramData\ShutdownGuard\` 是否已消失；若在，手动删除。
   - `C:\ProgramData\ShutdownGuardTools\` 是否已消失；若在，手动删除。
4. （可选）在「服务」中确认已无 `ShutdownGuard` 服务。

若在正常模式无法删除（罕见），可进**安全模式**，使用项目内 `emergency.bat` 的「完全移除」选项，再手动删除上述目录。

---

## 卸载完成状态提示（产品化口径）

卸载成功时，脚本会明确区分：

- **已完成**：服务已移除、注入器已停止、关机/重启/睡眠/休眠防护已解除、睡眠与休眠策略已还原。
- **待完成**（若有）：部分目录已登记为「重启后删除」，请重启以彻底清理；**当前不影响系统使用**。

对外口径建议：

- **未授权流程下不可直接删除核心组件**（ACL 与安装目录保护）。
- **必须通过维护密码与卸载流程进行移除**。
- **防止误删导致系统进入不一致状态**。

---

## 参考

- 安装/磁盘布局：见 `README.md` 的「磁盘文件布局」。
- 紧急恢复（安全模式）：见 `emergency.bat` 与 `README.md` 的「紧急恢复」。
