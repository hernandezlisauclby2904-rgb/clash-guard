#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param([switch]$SkipLegacyTaskPrompt)
$ErrorActionPreference = 'Stop'
$base = [IO.Path]::GetFullPath($PSScriptRoot)
$scriptPath = Join-Path $base 'clash_guard.ps1'
$configPath = Join-Path $base 'clash_guard_config.json'
$psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$watchTask = 'ClashGuard-Watch'
$pollTask = 'ClashGuard-Inspect'
if (-not (Test-Path -LiteralPath $scriptPath)) { throw "找不到主脚本：$scriptPath" }
if (-not (Test-Path -LiteralPath $configPath)) { throw "找不到配置文件：$configPath" }

$legacyNames = @('PersonalContext-ClashGuard-Watch','PersonalContext-ClashGuard')
$legacyFound = @()
foreach ($name in $legacyNames) {
    try { $legacyFound += Get-ScheduledTask -TaskName $name -ErrorAction Stop } catch {}
}
if ($legacyFound.Count -gt 0) {
    Write-Host '检测到旧版本计划任务：' -ForegroundColor Yellow
    $legacyFound | ForEach-Object { Write-Host ('  - ' + $_.TaskName) }
    if ($SkipLegacyTaskPrompt) { $disableLegacy = $true }
    else {
        $answer = Read-Host '为避免新旧守护同时拦截，是否禁用旧任务（保留定义，便于回滚）？输入 Y 确认'
        $disableLegacy = ($answer -match '^(?i:y|yes)$')
    }
    if ($disableLegacy) {
        foreach ($task in $legacyFound) {
            try { Stop-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue } catch {}
            try { Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue | Out-Null } catch {}
            Write-Host ("已停止/禁用旧任务：{0}" -f $task.TaskName) -ForegroundColor Yellow
        }
    } else {
        throw '安装已取消：旧版本 Watch/巡检任务仍处于启用状态。请确认允许禁用旧任务（任务定义会保留，可回滚），或先手动完成旧版迁移后再安装。为避免双守护同时运行，本安装器不会继续。'
    }
}

$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$watchAction = New-ScheduledTaskAction -Execute $psExe -Argument (('-NoProfile -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Watch' -f $scriptPath)) -WorkingDirectory $base
$pollAction = New-ScheduledTaskAction -Execute $psExe -Argument (('-NoProfile -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $scriptPath)) -WorkingDirectory $base
$watchTrigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
$pollTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
if ($PSCmdlet.ShouldProcess($watchTask, '注册登录时启动的 Watch 任务')) {
    Register-ScheduledTask -TaskName $watchTask -Action $watchAction -Trigger $watchTrigger -Principal $principal -Settings $settings -Description 'Clash Guard v2.0：监听 Claude 进程创建事件并按策略做响应式拦截。' -Force | Out-Null
}
if ($PSCmdlet.ShouldProcess($pollTask, '注册每 10 分钟巡检任务')) {
    Register-ScheduledTask -TaskName $pollTask -Action $pollAction -Trigger $pollTrigger -Principal $principal -Settings $settings -Description 'Clash Guard v2.0：检查 TUN、系统代理、IPv6 路由和 IP 风险参考。' -Force | Out-Null
}
Write-Host '计划任务已注册。下一步：运行 -Report 检查状态，再运行 -TestToast 测试通知按钮。' -ForegroundColor Green
Write-Host ("配置文件：{0}" -f $configPath)
Write-Host '注意：Watch 是进程创建后的响应式监控，不等同于 Windows 应用控制策略的启动前拦截。'
