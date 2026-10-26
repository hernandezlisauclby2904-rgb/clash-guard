# ============================================================
# 代理健康检查
# 手动运行（计划任务已删除）
# 检查：系统代理是否开启 → Clash 端口是否监听 → 记录出口 IP
# 注意：不做节点切换，不排除任何地区（用户确认台湾出口可用）
# ============================================================
param(
    [string]$ControllerUrl  = "http://127.0.0.1:9097",
    [string]$ControllerSecret = "set-your-secret",
    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort    = 7897,
    [string]$IpCheckUrl = "https://ipinfo.io/json"
)

$baseDir   = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$logFile   = Join-Path $baseDir 'logs\proxy_health.log'
function Log($msg) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $msg
    Add-Content -Path $logFile -Value $line
    Write-Host $msg
}

Log "=== 代理健康检查开始 ==="

# 1. 确保系统代理开启
& "$PSScriptRoot\ensure_system_proxy.ps1" -ProxyHost $ProxyHost -ProxyPort $ProxyPort | Out-Host

# 2. Clash 端口监听
$portListening = Test-NetConnection -ComputerName $ProxyHost -Port $ProxyPort -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $portListening) {
    Log "[FATAL] Clash 端口 $ProxyPort 未监听，请启动 Clash Verge"
    exit 1
}
Log "[OK] Clash 端口 $ProxyPort 监听中"

# 3. 检查代理出口 IP
try {
    $resp = curl.exe -s --max-time 8 -x "http://${ProxyHost}:${ProxyPort}" $IpCheckUrl
    $ipInfo = $resp | ConvertFrom-Json -ErrorAction Stop
    $country = $ipInfo.country
    $ip = $ipInfo.ip
    Log "[出口] IP=$ip  Country=$country"

    if ($country -eq "TW") {
        Log "[OK] 出口在台湾（用户确认可用，不切换）"
    } else {
        Log "[OK] 出口地区: $country"
    }
} catch {
    Log "[错误] 出口检测失败：$($_.Exception.Message)"
}

Log "=== 检查结束 ==="
