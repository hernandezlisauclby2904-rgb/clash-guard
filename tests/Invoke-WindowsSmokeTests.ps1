#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $base 'clash_guard.ps1'
$configPath = Join-Path $base 'clash_guard_config.json'
$vbsPath = Join-Path $base 'toast_action.vbs'
$failed = 0
function Assert-CG($Condition, [string]$Message) {
    if ($Condition) { Write-Host "[PASS] $Message" -ForegroundColor Green }
    else { Write-Host "[FAIL] $Message" -ForegroundColor Red; $script:failed++ }
}
Write-Host "PowerShell: $($PSVersionTable.PSVersion)"
Assert-CG ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -ge 1) '运行环境为 Windows PowerShell 5.1'
Assert-CG (Test-Path -LiteralPath $scriptPath) '主脚本存在'
Assert-CG (Test-Path -LiteralPath $configPath) 'JSON 配置存在'
Assert-CG (Test-Path -LiteralPath $vbsPath) 'Toast 白名单处理器存在'
try {
    $cfg = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    Assert-CG (@($cfg.ipEndpoints).Count -ge 1) '配置包含至少一个 IP 检测端点'
    Assert-CG (@($cfg.ipEndpoints | Where-Object { $_.url -notmatch '^https://' }).Count -eq 0) '检测端点全部使用 HTTPS'
    Assert-CG ($cfg.cacheFreshMinutes -gt 0) '缓存有效期大于 0'
} catch { Assert-CG $false "JSON 配置可解析（$($_.Exception.Message)）" }
$source = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8
# Ask the actual Windows PowerShell 5.1 parser to validate each PowerShell file before any functional test.
$psFiles = @(
    $scriptPath,
    (Join-Path $base 'install.ps1'),
    (Join-Path $base 'uninstall.ps1')
)
foreach ($target in $psFiles) {
    if (-not (Test-Path -LiteralPath $target)) { Assert-CG $false "PowerShell 文件存在：$target"; continue }
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$parseErrors) | Out-Null
    Assert-CG (@($parseErrors).Count -eq 0) ("PowerShell 语法解析：{0}" -f (Split-Path $target -Leaf))
    foreach ($parseError in @($parseErrors)) { Write-Host ("  Parser: {0} (Line {1})" -f $parseError.Message,$parseError.Extent.StartLineNumber) -ForegroundColor Red }
}
Assert-CG ($source.Contains('Win32_ProcessStartTrace')) 'Watch 使用 Win32_ProcessStartTrace'
Assert-CG ($source.Contains('App Paths\Claude.exe')) '受控启动器包含 Win32 Claude 安装路径回退'
Assert-CG (-not $source.Contains('__InstanceCreationEvent WITHIN 1')) '没有旧的 WITHIN 1 实例轮询查询'
Assert-CG ($source.Contains('if ($state.ipv6.leak)')) '自动修复复检包含 IPv6 违规判断'
Assert-CG ($source.Contains('if ($script:Config.blockPacProxy -and -not [string]::IsNullOrWhiteSpace($proxy.pacUrl))')) '门控检测 PAC 配置'
Assert-CG ($source.Contains("'UNKNOWN'")) '明确区分 UNKNOWN 状态'
Assert-CG ($source.Contains('$qualitySourceCount -ge 2')) 'IP PASS 需要至少两个独立风险数据源'
Assert-CG ($source.Contains('[System.Net.Sockets.AddressFamily]::InterNetwork')) 'expectedIPv4 限定为 IPv4 地址'
Assert-CG ($source.Contains('function Test-CGIPv4Address')) 'IPv4 地址采用严格点分十进制校验'
Assert-CG ($source.Contains('-4 -fsS --max-time $TimeoutSec')) '风险接口查询强制 IPv4'
Assert-CG ($source.Contains('-4 -sS --max-time 6')) 'TUN HTTPS 流量验证强制 IPv4'
Assert-CG ($source.Contains('$ipProviders = @($results | Where-Object { $_.ok -and $_.ip })')) '只统计真正返回有效 IP 的来源'
Assert-CG (-not $source.Contains('ensure_system_proxy.ps1')) '主程序不再调用会强制开启代理的旧辅助脚本'
Write-Host ''
Write-Host '此脚本只执行本地静态/配置冒烟检查，不改网络设置，也不声称完成真实节点验证。'
if ($failed -gt 0) { Write-Host "$failed 项检查失败。" -ForegroundColor Red; exit 1 }
Write-Host '全部 Windows 冒烟检查通过。下一步按 docs/REGRESSION_TEST_PLAN.md 实测。' -ForegroundColor Green
exit 0
