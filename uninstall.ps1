#requires -Version 5.1
[CmdletBinding(SupportsShouldProcess=$true)]
param()
$ErrorActionPreference = 'Continue'
$watchTask = 'ClashGuard-Watch'
$pollTask = 'ClashGuard-Inspect'
foreach ($name in @($watchTask,$pollTask)) {
    try { Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue } catch {}
    try {
        if ($PSCmdlet.ShouldProcess($name, '删除 Clash Guard v2 计划任务')) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop }
        Write-Host ("已删除任务：{0}" -f $name)
    } catch { Write-Host ("任务不存在或删除失败：{0} - {1}" -f $name,$_.Exception.Message) -ForegroundColor Yellow }
}
$protocol = 'HKCU:\Software\Classes\clashguard'
$commandPath = "$protocol\shell\open\command"
# Delete only the protocol key if its command references this package's toast_action.vbs.
try {
    $commandKey = Get-Item -LiteralPath $commandPath -ErrorAction SilentlyContinue
    $defaultValue = if ($commandKey) { [string]$commandKey.GetValue('') } else { '' }
    if ($defaultValue -and $defaultValue -like ('*' + (Join-Path $PSScriptRoot 'toast_action.vbs') + '*')) {
        if ($PSCmdlet.ShouldProcess($protocol, '移除本包注册的 clashguard: 协议')) { Remove-Item -LiteralPath $protocol -Recurse -Force }
        Write-Host '已移除此包注册的 clashguard: 协议。'
    } else { Write-Host '协议注册不属于当前目录，未删除。' }
} catch { Write-Host ("检查协议注册失败：{0}" -f $_.Exception.Message) -ForegroundColor Yellow }
Write-Host '脚本、配置和 logs 未删除。若要彻底卸载，请在确认后手动删除本文件夹。'
