# Clash 护卫（clash-guard）：面向 Claude 等高封禁/降智风险 AI 的出口环境看门狗 + 启动拦截
# 两个计划任务：
#   1. PersonalContext-ClashGuard — 每 10 分钟巡检（§十/§十一：Toast 去重提醒）
#   2. PersonalContext-ClashGuard-Watch — 登录时启动，监听 Claude.exe 启动并按硬/软规则拦截
#
# 硬规则（不满足 → 阻止 Claude 启动，全部实时检测，不依赖缓存）：
#   1. TUN（虚拟网卡）模式生效
#   2. 系统代理已关闭（ProxyEnable=0）
#   2.5 IPv6 泄露检测（物理网卡无全局 IPv6 地址，防止绕过 TUN 暴露真实位置）
#   3. 能直连 Claude 真实服务（TCP api.anthropic.com:443 / claude.ai:443，3秒超时，任一通即可）
# 软规则（不满足 → 默认阻止，可一键放行）：
#   - IP 质量不佳：fraudScore > fraudScoreMax，或非住宅 IP，或 Claude 风险分 > claudeScoreMax，或机房 IP
#   - 软规则读巡检缓存；缓存缺失/过期不阻断（fail-open），只异步触发巡检刷新
#
# 用法：
#   clash_guard.ps1                    # 巡检（默认）
#   clash_guard.ps1 -Report            # 手动报告（只读）
#   clash_guard.ps1 -Watch             # 常驻监听 Claude.exe 启动并拦截（单实例）
#   clash_guard.ps1 -AllowClaude       # 软规则临时放行 allowGraceMinutes 分钟（保留全部保护）
#   clash_guard.ps1 -EmergencyAllow    # 【紧急】所有规则（含硬规则）放行 allowGraceMinutes 分钟
#   clash_guard.ps1 -Stop              # 【应急】停用拦截守护（禁用任务+杀守护进程），不影响巡检
#   clash_guard.ps1 -Start             # 恢复拦截守护
#   clash_guard.ps1 -EmergencyLaunch   # 【应急逃生门】停用守护 + 立即启动 Claude（怀疑程序误判/bug 时用）
#   clash_guard.ps1 -Protect           # 切换「网络保护模式」：只检测+告警，暂停自动修复（门控拦截不受影响；再跑一次关闭）
# 彻底卸载：
#   Unregister-ScheduledTask -TaskName 'PersonalContext-ClashGuard-Watch' -Confirm:$false
#   Unregister-ScheduledTask -TaskName 'PersonalContext-ClashGuard' -Confirm:$false

param(
    [switch]$Report,
    [switch]$Watch,
    [switch]$AllowClaude,
    [switch]$EmergencyAllow,
    [switch]$Stop,
    [switch]$Start,
    [switch]$EmergencyLaunch,
    [switch]$Protect,
    [switch]$TestToast,
    [string]$ToastAction
)

$ErrorActionPreference = 'Continue'
# 路径全部基于脚本所在目录自动推断，迁移到任何位置都能工作
$base       = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$logsDir    = Join-Path $base 'logs'
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
$configFile = Join-Path $base 'clash_guard_config.json'
$stateFile  = Join-Path $logsDir 'clash_guard_state.json'
$logFile    = Join-Path $logsDir 'clash_guard.log'
$allowFlag  = Join-Path $logsDir 'clash_guard_allow.flag'
$emergFlag  = Join-Path $logsDir 'clash_guard_emergency.flag'
$stopFlag   = Join-Path $logsDir 'clash_guard_watch.stop'
$watchStopAlert = Join-Path $logsDir 'clash_guard_watchstop.alert'
$protectFlag = Join-Path $logsDir 'clash_guard_protect.flag'
$watchTask  = 'PersonalContext-ClashGuard-Watch'
$pollTask   = 'PersonalContext-ClashGuard'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    # 简单轮转：单进程只检查一次，日志超 1MB 则留存一份 .1（防长期膨胀）
    if (-not $global:cgLogRotated) {
        $global:cgLogRotated = $true
        try {
            if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 1MB) {
                Move-Item -Path $logFile -Destination "$logFile.1" -Force -ErrorAction Stop
            }
        } catch {}
    }
}

function Show-Toast($title, $body, $actions = $null) {
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $esc = { param($s) [string]$s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
        $actionsXml = ''
        if ($actions) {
            $actionsXml = "<actions>" + ((@($actions) | ForEach-Object { "<action activationType=""protocol"" arguments=""$( & $esc $_.args )"" content=""$( & $esc $_.label )""/>" }) -join '') + "</actions>"
        }
        $xmlText = "<toast><visual><binding template=""ToastGeneric""><text>$( & $esc $title )</text><text>$( & $esc $body )</text></binding></visual>$actionsXml</toast>"
        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xmlText)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $doc
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
    } catch { Log "Toast 失败: $($_.Exception.Message)" }
}

# ── 配置 ──
if (-not (Test-Path $configFile)) {
    @{
        ipEndpoints = @(
            @{ name = 'ip.sb';      url = 'https://api.ip.sb/geoip' },
            @{ name = 'ipinfo';     url = 'https://ipinfo.io/json' },
            @{ name = 'ipquery.io'; url = 'https://api.ipquery.io/?format=json' },
            @{ name = 'ipwho.is';   url = 'https://ipwho.is/' },
            @{ name = 'ippure';     url = 'https://my.ippure.com/v1/info' },
            @{ name = 'fuck-claude';url = 'https://fuck-claude.vercel.app/api/check?format=json' }
        )
        httpTimeoutSec = 12
        escalateAfterCycles = 3
        fraudScoreMax = 50             # 软规则：ippure fraudScore 上限
        claudeScoreMax = 50            # 软规则：fuck-claude 评分上限
        allowGraceMinutes = 10         # 放行时长（软放行/紧急总放行）
        reachableHosts = @('api.anthropic.com:443','claude.ai:443')  # 硬规则3：Claude 真实服务连通性
        cacheFreshMinutes = 30         # 软规则缓存有效期；过期只 fail-open + 异步刷新，不阻断
        autoFix = $true                # 自动修复：开 TUN + 关本地系统代理（安全顺序）
        autoFixCooldownMin = 10        # 自动修复冷却，避免反复切换网络弄崩浏览器
        autoStartClash = $false        # Clash 未运行时是否自动拉起（默认关，只弹窗提示）
        apiPorts = @(9097, 9090)       # Clash 内核 external-controller 探测端口
        apiSecret = ''                 # 留空则自动从 verge 配置目录读取
        recommendedIpSite = @{ name = 'fuck-claude（Claude 专用风险评分）'; url = 'https://fuck-claude.vercel.app' }
    } | ConvertTo-Json -Depth 5 | Set-Content -Path $configFile -Encoding UTF8
    Log "已生成默认配置 $configFile"
}
try { $cfg = Get-Content $configFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $cfg = $null; Log "配置解析失败: $($_.Exception.Message)" }
if (-not $cfg) {
    $cfg = [pscustomobject]@{ ipEndpoints=@(); httpTimeoutSec=12; escalateAfterCycles=3; fraudScoreMax=50; claudeScoreMax=50; allowGraceMinutes=10; reachableHosts=@('api.anthropic.com:443','claude.ai:443'); cacheFreshMinutes=30; autoFix=$true; autoFixCooldownMin=10; autoStartClash=$false; apiPorts=@(9097,9090); apiSecret=''; recommendedIpSite=@{ name='fuck-claude（Claude 专用风险评分）'; url='https://fuck-claude.vercel.app' } }
}
$graceMin = if ($cfg.allowGraceMinutes) { [int]$cfg.allowGraceMinutes } else { 10 }
$cacheFreshMin = if ($cfg.cacheFreshMinutes) { [int]$cfg.cacheFreshMinutes } else { 30 }
$autoFix      = if ($null -ne $cfg.autoFix) { [bool]$cfg.autoFix } else { $true }
$fixCooldown  = if ($cfg.autoFixCooldownMin) { [int]$cfg.autoFixCooldownMin } else { 10 }
$openUrl      = if ($cfg.recommendedIpSite -and $cfg.recommendedIpSite.url) { [string]$cfg.recommendedIpSite.url } else { 'https://fuck-claude.vercel.app' }
$openName     = if ($cfg.recommendedIpSite -and $cfg.recommendedIpSite.name) { [string]$cfg.recommendedIpSite.name } else { 'fuck-claude' }

# ── 放行标志（通用：$flag 文件内为时间戳，graceMin 分钟内有效）──
function Test-GraceFlag($flag) {
    if (-not (Test-Path $flag)) { return $false }
    try {
        $ts = [datetime](Get-Content $flag -Raw -Encoding UTF8).Trim()
        if (((Get-Date) - $ts) -lt (New-TimeSpan -Minutes $graceMin)) { return $true }
        Remove-Item $flag -Force -ErrorAction SilentlyContinue
    } catch {}
    return $false
}

# ── TCP 实时连通性（硬规则3，不走任何代理站点，直连 Claude 真实服务）──
function Test-TcpReachable($hostname, $port, $timeoutMs = 3000) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($hostname, [int]$port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($timeoutMs, $false)) {
            try { $client.EndConnect($iar); $client.Close(); return $true }
            catch { $client.Close(); return $false }
        }
        $client.Close()
        return $false
    } catch {
        try { $client.Close() } catch {}
        return $false
    }
}

function Test-ClaudeServiceLive {
    # 两轮检测：第一轮全部失败后隔 2 秒重试一轮，两轮都失败才判不可达（减少瞬时抖动误杀）
    for ($round = 1; $round -le 2; $round++) {
        $hosts = if ($cfg.reachableHosts) { @($cfg.reachableHosts) } else { @('api.anthropic.com:443') }
        foreach ($h in $hosts) {
            $parts = "$h" -split ':',2
            $hname = $parts[0]
            $port = if ($parts.Count -eq 2 -and $parts[1]) { [int]$parts[1] } else { 443 }
            if (Test-TcpReachable $hname $port 3000) { return $true }
        }
        if ($round -lt 2) { Start-Sleep -Seconds 2 }
    }
    return $false
}

# ── 从 JSON 递归提取 IP 质量字段 ──
$interesting = '^(ip|query|country.*|city|region|asn.*|org.*|company|isp|type|.*datacenter.*|.*abuse.*|.*fraud.*|.*risk.*|.*proxy.*|.*vpn.*|.*tor.*|.*crawler.*|.*hosting.*|.*mobile.*|.*residential.*|.*broadcast.*|.*score.*|.*verdict.*|.*band.*)$'
function Get-Interesting($o, [int]$depth) {
    $out = @()
    if ($depth -gt 4) { return $out }
    if ($o -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $o.PSObject.Properties) {
            $v = $p.Value
            if ($v -is [System.Management.Automation.PSCustomObject]) {
                $out += Get-Interesting $v ($depth + 1)
            } elseif ($v -isnot [string] -and $v -is [System.Collections.IEnumerable]) {
                $i = 0
                foreach ($e in $v) { if ($i -ge 3) { break }; $out += Get-Interesting $e ($depth + 1); $i++ }
            } elseif ("$($p.Name)" -match $interesting -and $null -ne $v -and "$v" -ne '') {
                $out += "$($p.Name)=$v"
            }
            if ($out.Count -ge 20) { break }
        }
    }
    return $out | Select-Object -Unique
}

# ── 环境检测（巡检用，含 IP 站点全量检测）──
function Get-EnvState {
    $procs   = Get-Process -Name 'clash-verge','clash-verge-service','verge-mihomo','mihomo' -ErrorAction SilentlyContinue
    $clashOk = [bool]$procs
    $proxyOn = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyEnable -eq 1
    # PAC 只读检测（AutoConfigURL）：只纳入告警，绝不修改
    $pacUrl = [string]((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).AutoConfigURL)
    $tunAdp  = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Meta Tunnel|Wintun|Mihomo|Clash' -and $_.Status -eq 'Up' }
    $tunOk   = [bool]$tunAdp
    $tunName = ($tunAdp | Select-Object -First 1).Name

    # IPv6 泄露检测：物理网卡有全局 IPv6 地址 = 流量可绕过 TUN 暴露真实位置
    $ipv6Leak = $false; $ipv6LeakIp = ''
    Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Meta Tunnel|Wintun|Mihomo|Clash|VMware' } | ForEach-Object {
        $v6 = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(fe80|::1)' }
        if ($v6) { $ipv6Leak = $true; $ipv6LeakIp = ($v6.IPAddress -join ', ') }
    }

    $endpoints = @(); $exitIps = @(); $okCount = 0
    foreach ($ep in @($cfg.ipEndpoints)) {
        $line = "$($ep.name): "
        try {
            $raw = $null
            try {
                $raw = (Invoke-RestMethod -Uri $ep.url -TimeoutSec ([int]$cfg.httpTimeoutSec) -Headers @{ 'User-Agent' = 'clash-guard/1.0' }) | ConvertTo-Json -Depth 6
            } catch {
                $raw = & curl.exe -sS -m ([int]$cfg.httpTimeoutSec) -A 'clash-guard/1.0' $ep.url 2>&1
            }
            $r = $raw | ConvertFrom-Json
            $fields = Get-Interesting $r 0
            $line += $fields -join '; '
            $ipHit = $fields | Where-Object { $_ -match '^(ip|query)=' } | Select-Object -First 1
            if ($ipHit) { $exitIps += ($ipHit -split '=', 2)[1] }
            $okCount++
            Log "IP检测 $line"
        } catch {
            $line += "请求失败（$($_.Exception.Message.Split("`n")[0])）"
        }
        $endpoints += $line
    }
    $exitIps = @($exitIps | Select-Object -Unique)

    # ── 软规则：IP 质量（仅提示/软拦截，永不硬阻断）──
    $softFail = $false; $softReason = ''
    $epText = $endpoints -join '; '
    if ($epText -match 'fraudScore=(\d+)') {
        if ([int]$Matches[1] -gt [int]$cfg.fraudScoreMax) { $softFail = $true; $softReason = "fraudScore=$($Matches[1]) > $($cfg.fraudScoreMax)" }
    }
    if ($epText -match 'isResidential=False') { $softFail = $true; $softReason = '非住宅 IP' }
    if ($epText -match 'is_datacenter=True') { $softFail = $true; $softReason = '机房 IP' }
    if ($epText -match 'fuck-claude.*score=(\d+)') {
        if ([int]$Matches[1] -gt [int]$cfg.claudeScoreMax) { $softFail = $true; $softReason = "Claude 风险分=$($Matches[1]) > $($cfg.claudeScoreMax)" }
    }

    return [pscustomobject]@{
        clashOk     = $clashOk
        tunOk       = $tunOk
        tunAdapter  = $tunName
        sysProxyOn  = $proxyOn
        pacUrl      = $pacUrl
        endpoints   = $endpoints
        exitIps     = $exitIps
        ipOkCount   = $okCount
        softFail    = $softFail
        softReason  = $softReason
        at          = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
}

# ── Claude 启动门控（全部实时快查 + 软规则读缓存 fail-open）──
# 返回: @{ decision='allow'|'block_hard'|'block_soft'; reason='...' }
function Test-ClashGate {
    # 0. 紧急总放行（覆盖一切规则，给"护卫自身误判/bug"场景兜底）
    if (Test-GraceFlag $emergFlag) {
        return [pscustomobject]@{ decision='allow'; reason='紧急总放行有效' }
    }

    # 硬规则 1：TUN 虚拟网卡（实时）
    $tunAdp = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Meta Tunnel|Wintun|Mihomo|Clash' -and $_.Status -eq 'Up' }
    if (-not $tunAdp) { return [pscustomobject]@{ decision='block_hard'; reason='TUN 虚拟网卡未开启' } }

    # 硬规则 2：系统代理关闭（实时）
    $proxyOn = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyEnable -eq 1
    if ($proxyOn) { return [pscustomobject]@{ decision='block_hard'; reason='系统代理未关闭' } }

    # 硬规则 2.5：IPv6 泄露检测（物理网卡有全局 IPv6 = 真实 IP 可被绕过 TUN 暴露）
    $v6Leak = $false
    Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Meta Tunnel|Wintun|Mihomo|Clash|VMware' } | ForEach-Object {
        $v6 = Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notmatch '^(fe80|::1)' }
        if ($v6) { $v6Leak = $true }
    }
    if ($v6Leak) { return [pscustomobject]@{ decision='block_hard'; reason='IPv6 泄露（物理网卡有全局 IPv6 地址，真实位置可被检测）' } }

    # 硬规则 3：Claude 真实服务 TCP 可达（实时，3 秒级；与第三方 IP 站点无关，IP 变动后立即反映真实状态）
    if (-not (Test-ClaudeServiceLive)) {
        return [pscustomobject]@{ decision='block_hard'; reason='无法连通 Claude 服务（api.anthropic.com:443 超时），请检查节点/网络后重试' }
    }

    # 软规则：IP 质量读缓存；缓存缺失/过期不阻断（fail-open），异步触发巡检刷新
    $cache = $null
    if (Test-Path $stateFile) {
        try { $cache = (Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json).gateCache } catch {}
    }
    $cacheStale = $true
    if ($cache -and $cache.at) {
        try { if (((Get-Date) - [datetime]::Parse($cache.at)).TotalMinutes -le $cacheFreshMin) { $cacheStale = $false } } catch {}
    }
    if ($cacheStale) {
        # 节流：5 分钟内最多踢一次巡检，避免每次启动 Claude 都触发
        if ($null -eq $global:cgLastKick) { $global:cgLastKick = [datetime]::MinValue }
        if (((Get-Date) - $global:cgLastKick).TotalMinutes -ge 5) {
            $global:cgLastKick = Get-Date
            try { Start-ScheduledTask -TaskName $pollTask -ErrorAction SilentlyContinue } catch {}
        }
        return [pscustomobject]@{ decision='allow'; reason='硬规则通过（IP质量缓存陈旧，已自动刷新，本次不拦截）' }
    }

    if ($cache.softFail) {
        if (Test-GraceFlag $allowFlag) {
            Log "软规则违规但软放行有效：$($cache.softReason)"
            return [pscustomobject]@{ decision='allow'; reason="软放行有效（$($cache.softReason)）" }
        }
        return [pscustomobject]@{ decision='block_soft'; reason=[string]$cache.softReason }
    }

    return [pscustomobject]@{ decision='allow'; reason='全部符合要求' }
}

# ── 启动 Microsoft Store 版 Claude（PFN 随版本变化，动态解析）──
function Start-ClaudeApp {
    try {
        $app = Get-StartApps -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Claude' -and $_.AppID -like '*!*' } | Select-Object -First 1
        if (-not $app) {
            $pkg = Get-AppxPackage -Name 'Claude*' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($pkg) {
                $appId = (Get-AppxPackageManifest $pkg -ErrorAction SilentlyContinue).Package.Applications.Application.Id | Select-Object -First 1
                if ($appId) { $app = [pscustomobject]@{ AppID = "$($pkg.PackageFamilyName)!$appId" } }
            }
        }
        if ($app) { Start-Process "shell:AppsFolder\$($app.AppID)"; return $true }
    } catch { Log "启动 Claude 失败: $($_.Exception.Message)" }
    return $false
}

# ── 停用拦截守护（应急；不影响每10分钟巡检）──
function Stop-GuardWatch {
    try { Disable-ScheduledTask -TaskName $watchTask -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Stop-ScheduledTask -TaskName $watchTask -ErrorAction SilentlyContinue } catch {}
    # stop flag 兜底（watcher 主循环会自杀）；写时间戳，超过 2 分钟视为陈旧标志自动失效
    (Get-Date).ToString('o') | Set-Content -Path $stopFlag -Encoding UTF8
    Remove-Item $watchStopAlert -Force -ErrorAction SilentlyContinue
    # 直接杀所有在跑的 watcher（排除自身）
    $me = $PID
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -match 'clash_guard\.ps1' -and $_.CommandLine -match '-Watch' -and $_.ProcessId -ne $me } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Log "已终止守护进程 PID=$($_.ProcessId)" }
    } catch {}
    Log "拦截守护已停用（-Stop）；巡检任务不受影响"
}

# ── 恢复拦截守护 ──
function Start-GuardWatch {
    Remove-Item $stopFlag -Force -ErrorAction SilentlyContinue
    Remove-Item $watchStopAlert -Force -ErrorAction SilentlyContinue
    try { Enable-ScheduledTask -TaskName $watchTask -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Start-ScheduledTask -TaskName $watchTask -ErrorAction SilentlyContinue } catch {}
    Log "拦截守护已恢复（-Start）"
}

# ── 巡检顺带照看拦截守护：任务禁用→提醒一次（带恢复按钮）；任务启用但进程不在→自动拉起 ──
function Invoke-WatchCare {
    try { $t = Get-ScheduledTask -TaskName $watchTask -ErrorAction Stop } catch { return }
    if ($t.State -eq 'Disabled') {
        if (-not (Test-Path $watchStopAlert)) {
            Show-Toast 'Clash 护卫 · 拦截守护处于停用状态' 'Claude 启动拦截当前未生效（应急停用后尚未恢复）。点「恢复护卫」立即恢复保护。' @(
                @{ label = '恢复护卫'; args = 'clashguard:start' }
            )
            (Get-Date).ToString('o') | Set-Content -Path $watchStopAlert -Encoding UTF8
            Log '提醒：拦截守护任务处于禁用状态（-Stop/应急逃生后未恢复），已 Toast 一次'
        }
        return
    }
    Remove-Item $watchStopAlert -Force -ErrorAction SilentlyContinue
    # 只认计划任务经 -File 启动的真实守护（排除 -Command/-EncodedCommand 探测壳，避免自匹配导致漏自愈）
    $running = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -notmatch '-Command|-EncodedCommand' -and $_.CommandLine -match 'clash_guard\.ps1' -and $_.CommandLine -match '-Watch' }
    if (-not $running) {
        try {
            Start-ScheduledTask -TaskName $watchTask -ErrorAction Stop
            Log '巡检发现拦截守护进程不在（任务仍启用），已自动拉起（自愈）'
        } catch { Log "守护自愈拉起失败: $($_.Exception.Message)" }
    }
}

# ── 自动修复：开 TUN（内核 API）+ 关本地系统代理（安全顺序，防浏览器崩）──
function Get-CGController {
    $ports = @(9097, 9090, 9095, 9091)
    if ($cfg.apiPorts) { $ports = @($cfg.apiPorts) + $ports }
    $secret = ''
    if ($cfg.apiSecret) { $secret = [string]$cfg.apiSecret }
    else {
        foreach ($dir in @("$env:APPDATA\io.github.clash-verge-rev.clash-verge-rev", "$env:APPDATA\clash-verge", "$env:APPDATA\clash-verge-rev")) {
            if (Test-Path $dir) {
                try {
                    # 优先读 clash-verge.yaml（应用主配置，secret 最准），再退而求其次
                    $files = @()
                    $main = Join-Path $dir 'clash-verge.yaml'
                    if (Test-Path $main) { $files += $main }
                    $files += (Get-ChildItem $dir -Filter *.yaml -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $main }).FullName
                    foreach ($f in $files) {
                        $yaml = Get-Content $f -Raw -ErrorAction SilentlyContinue
                        $m = [regex]::Match($yaml, '(?m)^\s*secret:\s*["'']?([^"''\r\n]+)')
                        if ($m.Success -and $m.Groups[1].Value.Trim() -ne '' -and $m.Groups[1].Value.Trim() -ne '""') { $secret = $m.Groups[1].Value.Trim(); break }
                    }
                    if ($secret) { break }
                } catch {}
            }
        }
    }
    foreach ($p in $ports) {
        try {
            $h = @{}
            if ($secret) { $h.Authorization = "Bearer $secret" }
            $v = Invoke-RestMethod -Uri "http://127.0.0.1:$p/version" -TimeoutSec 2 -Headers $h
            if ($v.version) { return [pscustomobject]@{ port = $p; secret = $secret } }
        } catch {}
    }
    return $null
}

function Test-TunUp {
    return [bool](Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Meta Tunnel|Wintun|Mihomo|Clash' -and $_.Status -eq 'Up' })
}

function Enable-TunViaApi {
    $c = Get-CGController
    if (-not $c) { Log '自动修复：未找到 Clash 内核 API（external-controller），无法开 TUN'; return $false }
    try {
        $h = @{ Authorization = "Bearer $($c.secret)" }
        Invoke-RestMethod -Method Patch -Uri "http://127.0.0.1:$($c.port)/configs" -ContentType 'application/json' -Body '{"tun":{"enable":true}}' -Headers $h -TimeoutSec 5 | Out-Null
        foreach ($i in 1..8) {
            Start-Sleep -Seconds 1
            if (Test-TunUp) { Log "自动修复：TUN 已通过内核 API 开启（:$($c.port)）"; return $true }
        }
        Log '自动修复：TUN PATCH 已下发但网卡未就绪'
        return $false
    } catch { Log "自动修复：TUN PATCH 失败: $($_.Exception.Message)"; return $false }
}

function Disable-LocalSystemProxy {
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $ip = Get-ItemProperty $reg -ErrorAction SilentlyContinue
    if ($ip.ProxyEnable -ne 1) { return 'already_off' }
    $srv = [string]$ip.ProxyServer
    # 只动本地 Clash 的代理；用户手动配的外部代理绝不碰
    if ($srv -notmatch '^(127\.0\.0\.1|localhost|\[::1\]|::1)(:|$)') { return 'external_skip' }
    Set-ItemProperty -Path $reg -Name ProxyEnable -Value 0
    # 广播 WinINET 设置变更，让 Chrome 立即平滑感知（比滞后感知更少报错）
    try {
        Add-Type -Namespace CG -Name INet -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);' -ErrorAction SilentlyContinue
        [CG.INet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null   # SETTINGS_CHANGED
        [CG.INet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null   # REFRESH
    } catch {}
    Log '自动修复：系统代理已关闭（本地 Clash 代理，已广播刷新）'
    return 'off'
}

# ── 真实流量验证（显式绕过系统代理，走 TUN 路由路径；候选端点任一通过即可）──
function Test-RealTrafficViaTun {
    foreach ($u in @('https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204')) {
        try {
            $code = & curl.exe -sS -m 8 --noproxy '*' -o NUL -w '%{http_code}' $u 2>$null
            if ("$code" -match '^(204|200)\s*$') { return $true }
        } catch {}
    }
    return $false
}

# ── 恢复修复前的系统代理（后置验证失败时调用；只恢复本地代理场景）──
function Restore-SystemProxy($pre) {
    try {
        if (-not $pre.wasOn) { return }
        $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        Set-ItemProperty -Path $reg -Name ProxyEnable -Value 1
        try {
            Add-Type -Namespace CG -Name INet -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);' -ErrorAction SilentlyContinue
            [CG.INet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null   # SETTINGS_CHANGED
            [CG.INet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null   # REFRESH
        } catch {}
        Log '自动修复：后置验证失败，已恢复修复前的系统代理状态'
    } catch { Log "自动修复：恢复系统代理失败: $($_.Exception.Message)" }
}

function Invoke-AutoFix {
    param([switch]$Force)
    # 网络保护模式：只检测不改动（网络零变更）
    if (Test-Path $protectFlag) {
        Log '自动修复跳过：保护模式开启（网络零变更）'
        return [pscustomobject]@{ attempted = $false; actions = @('保护模式开启中，已暂停自动修复（网络零变更）'); fixed = $false }
    }

    # 全局修复锁：计划任务巡检与 Toast 一键修复并发时只允许一个执行
    $fixMutex = New-Object System.Threading.Mutex($false, 'Global\ClashGuardFixMutex')
    $acquired = $false
    try { $acquired = $fixMutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $acquired = $true } catch {}
    if (-not $acquired) {
        Log '自动修复跳过：另有修复操作在执行（全局修复锁）'
        return [pscustomobject]@{ attempted = $false; actions = @('另有修复操作正在执行，本次跳过（全局修复锁）'); fixed = $false }
    }
    try {
        $cdFile = "$base\logs\clash_guard_fix.cooldown"
        if (-not $Force -and (Test-Path $cdFile)) {
            try {
                if (((Get-Date) - [datetime](Get-Content $cdFile -Raw -Encoding UTF8)).TotalMinutes -lt $fixCooldown) {
                    return [pscustomobject]@{ attempted = $false; actions = @("冷却中（$fixCooldown 分钟内不重复修复，保护浏览器连接）"); fixed = $false }
                }
            } catch {}
        }
        (Get-Date).ToString('o') | Set-Content -Path $cdFile -Encoding UTF8
        $actions = @(); $fixedAny = $false

        # 记录修复前状态（日志不含 secret）
        $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $preIp = Get-ItemProperty $reg -ErrorAction SilentlyContinue
        $pre = [pscustomobject]@{
            wasOn   = ($preIp.ProxyEnable -eq 1)
            isLocal = ([string]$preIp.ProxyServer -match '^(127\.0\.0\.1|localhost|\[::1\]|::1)(:|$)')
        }
        Log "自动修复开始（前状态: 代理=$(if ($pre.wasOn) { if ($pre.isLocal) { 'on(本地)' } else { 'on(外部)' } } else { 'off' }), TUN=$(if (Test-TunUp) { 'up' } else { 'down' })）"

        $clashProcs = Get-Process -Name 'clash-verge','clash-verge-service','verge-mihomo','mihomo' -ErrorAction SilentlyContinue
        if (-not $clashProcs) {
            if ($cfg.autoStartClash) {
                try {
                    $exe = Get-ChildItem "$env:LOCALAPPDATA\Clash Verge*" -Filter 'clash-verge.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($exe) { Start-Process $exe.FullName; $actions += '已自动启动 Clash Verge'; $fixedAny = $true }
                } catch {}
            }
            if (-not $fixedAny) { $actions += 'Clash 未运行，无法自动修复（可在配置开 autoStartClash）' }
            Log "自动修复结束：Clash 未运行，未做网络变更"
            return [pscustomobject]@{ attempted = $true; actions = $actions; fixed = $fixedAny }
        }

        # 顺序 1：先开 TUN（加路由，无破坏性）
        if (-not (Test-TunUp)) {
            if (Enable-TunViaApi) { $actions += '已自动开启 TUN'; $fixedAny = $true }
            else { $actions += 'TUN 自动开启失败（重启 Clash 后请在界面打开 TUN 开关）' }
        }

        # 顺序 2：TUN 就绪 + 真实 HTTPS 流量验证通过（走 TUN 路径）→ 才关系统代理
        if (Test-TunUp) {
            if (-not $pre.wasOn) {
                # 代理本来就关着，无需变更
            } elseif (Test-RealTrafficViaTun) {
                switch (Disable-LocalSystemProxy) {
                    'off' {
                        $actions += '已自动关闭系统代理'
                        Start-Sleep -Seconds 1
                        if (Test-RealTrafficViaTun) {
                            $actions += '关代理后流量验证通过'; $fixedAny = $true
                        } else {
                            # 后置验证失败 → 恢复原配置并停止后续操作
                            $actions += '关代理后流量验证失败，已恢复系统代理'
                            Restore-SystemProxy $pre
                        }
                    }
                    'external_skip'  { $actions += '检测到非本地代理，未自动修改（保守跳过）' }
                    'already_off'    { }
                }
            } else {
                $actions += 'TUN 路径 HTTPS 验证未通过，暂不关系统代理（避免断网，只提示）'
            }
        } else {
            $actions += 'TUN 未就绪，暂不关系统代理（避免断网，只提示）'
        }
        Log "自动修复结束（动作: $($actions -join '；')）"
        return [pscustomobject]@{ attempted = $true; actions = $actions; fixed = $fixedAny }
    } finally {
        try { $fixMutex.ReleaseMutex() | Out-Null } catch {}
        $fixMutex.Dispose()
    }
}

# ── Toast 按钮协议（clashguard:fix / clashguard:openip / clashguard:start）──
function Ensure-CGProtocol {
    $root = 'HKCU:\Software\Classes\clashguard'
    if (-not (Test-Path "$root\shell\open\command")) {
        New-Item -Path $root -Force | Out-Null
        Set-ItemProperty -Path $root -Name '(Default)' -Value 'URL:clashguard'
        Set-ItemProperty -Path $root -Name 'URL Protocol' -Value ''
        New-Item -Path "$root\shell\open\command" -Force | Out-Null
        $vbsPath = Join-Path $base 'run_hidden.vbs'
        $ps1Path = Join-Path $base 'clash_guard.ps1'
        $cmd = "wscript.exe `"$vbsPath`" `"powershell.exe -NoProfile -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -File ```"$ps1Path```" -ToastAction %1`""
        Set-ItemProperty -Path "$root\shell\open\command" -Name '(Default)' -Value $cmd
        Log '已注册 clashguard: 协议（Toast 按钮）'
    }
}

function Get-IpQualityLine($endpoints, $exitIps) {
    $t = $endpoints -join '; '
    $ipStr = if ($exitIps) { $exitIps[0] } else { '?' }
    $parts = @("出口 $ipStr")
    if ($t -match 'fraudScore=(\d+)') { $parts += "欺诈分$($Matches[1])" }
    if ($t -match 'isResidential=(\w+)') { $parts += $(if ($Matches[1] -eq 'True') { '住宅IP' } else { '非住宅' }) }
    if ($t -match 'fuck-claude.*score=(\d+)') { $parts += "Claude风险$($Matches[1])" }
    return ($parts -join ' · ')
}

# ══════════════════════════════════════════
# 模式：-EmergencyAllow 紧急总放行（覆盖所有规则 10 分钟）
# ══════════════════════════════════════════
if ($EmergencyAllow) {
    (Get-Date).ToString('o') | Set-Content -Path $emergFlag -Encoding UTF8
    Write-Host "[紧急放行] 未来 $graceMin 分钟内所有规则（含硬规则）均放行。标志：$emergFlag"
    Log "用户开启紧急总放行（$graceMin 分钟，覆盖全部规则）"
    exit 0
}

# ══════════════════════════════════════════
# 模式：-AllowClaude 软规则临时放行
# ══════════════════════════════════════════
if ($AllowClaude) {
    (Get-Date).ToString('o') | Set-Content -Path $allowFlag -Encoding UTF8
    Write-Host "[OK] 软规则临时放行 $graceMin 分钟（硬规则仍强制）。标志：$allowFlag"
    Log "用户软规则放行（$graceMin 分钟）"
    exit 0
}

# ══════════════════════════════════════════
# 模式：-Protect 切换网络保护模式（再跑一次关闭）
# ══════════════════════════════════════════
if ($Protect) {
    if (Test-Path $protectFlag) {
        Remove-Item $protectFlag -Force -ErrorAction SilentlyContinue
        Write-Host '[OK] 网络保护模式已关闭：恢复自动修复（违规时自动开 TUN/关本地系统代理）。'
        Log '保护模式已关闭（恢复自动修复）'
    } else {
        (Get-Date).ToString('o') | Set-Content -Path $protectFlag -Encoding UTF8
        Write-Host '[OK] 网络保护模式已开启：只检测+告警，暂停自动修复（网络零变更）；Claude 门控拦截不受影响。'
        Log '保护模式已开启（只检测不自动修）'
    }
    exit 0
}

# ══════════════════════════════════════════
# 模式：-Stop / -Start / -EmergencyLaunch
# ══════════════════════════════════════════
if ($Stop) {
    Stop-GuardWatch
    Write-Host "[OK] Clash 拦截守护已停用，现在可以自由打开 Claude。恢复请运行：clash_guard.ps1 -Start（或双击桌面「恢复Clash护卫」）"
    exit 0
}
if ($Start) {
    Start-GuardWatch
    Write-Host "[OK] Clash 拦截守护已恢复（计划任务已启用并启动）。"
    exit 0
}
if ($EmergencyLaunch) {
    Write-Host "[应急] 正在停用拦截守护..."
    Stop-GuardWatch
    Write-Host "[应急] 正在启动 Claude..."
    $ok = Start-ClaudeApp
    if ($ok) { Write-Host "[OK] Claude 已启动，护卫已停用。用完请双击桌面「恢复Clash护卫」恢复保护。" }
    else { Write-Host "[!] 未能自动找到 Claude 应用，请从开始菜单手动打开（护卫已停用，不会再被拦）。" }
    exit 0
}

# ══════════════════════════════════════════
# 模式：-Watch 常驻拦截（单实例 Mutex）
# ══════════════════════════════════════════
if ($Watch) {
    $script:watchMutex = New-Object System.Threading.Mutex($false, 'Global\ClashGuardWatchSingleton')
    if (-not $script:watchMutex.WaitOne(0)) {
        Log "已有守护实例在运行，本次启动退出（单实例）"
        exit 0
    }

    Log "Claude 启动拦截守护启动"
    # Toast 去重表：同一判定 30 秒内只弹一次（Store 应用激活重试/Electron 多进程会连触发）
    # 用 $global: 作用域：事件 Action 在独立 pipeline 执行，$script: 变量不可达
    $global:cgToastLast = @{}
    $global:cgGraceMin = $graceMin
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'Claude.exe'"
    try {
        Register-CimIndicationEvent -Query $query -SourceIdentifier 'ClaudeGuardWatch' -Action {
            try {
                $proc = $Event.SourceEventArgs.NewEvent.TargetInstance
                $cpid = $proc.ProcessId
                $gate = Test-ClashGate
                if ($gate.decision -eq 'allow') {
                    Log "Claude 放行：$($gate.reason)"
                    return
                }
                # 先留痕，再杀进程树（Electron 主进程 + 子进程），保证即使后续步骤失败也有记录
                Log "Claude 已阻止（$($gate.decision)）：$($gate.reason)"
                & taskkill.exe /PID $cpid /T /F 2>&1 | Out-Null
                Stop-Process -Id $cpid -Force -ErrorAction SilentlyContinue

                # Toast 去重（30 秒同判定只弹一次）；$global 变量在事件上下文里做防御性初始化
                if ($null -eq $global:cgToastLast) { $global:cgToastLast = @{} }
                $gmin = if ($global:cgGraceMin) { [int]$global:cgGraceMin } else { 10 }
                $key = "$($gate.decision)|$($gate.reason)"
                $now = Get-Date
                $shouldToast = -not ($global:cgToastLast.ContainsKey($key) -and ($now - $global:cgToastLast[$key]).TotalSeconds -lt 30)
                $global:cgToastLast[$key] = $now

                if ($shouldToast) {
                    if ($gate.decision -eq 'block_hard') {
                        Show-Toast 'Clash 护卫 · 已阻止启动' "硬规则未满足：$($gate.reason)。若确认网络正常仍被拦（可能是护卫误判），双击桌面「Claude紧急启动」逃生。"
                    } else {
                        Show-Toast 'Clash 护卫 · IP 质量不佳' "$($gate.reason)。双击桌面「Claude紧急启动」立即打开；或运行 clash_guard.ps1 -AllowClaude 保留保护放行 $gmin 分钟。"
                    }
                }
            } catch {
                Log "事件回调异常: $($_.Exception.Message)"
            }
        } | Out-Null
    } catch {
        Log "事件注册失败: $($_.Exception.Message)"
        exit 1
    }
    Log "Claude 启动事件监听已注册，等待 Claude.exe 启动..."

    # 主循环：Wait-Event 泵事件队列；每 60 秒自检停止标志（仅认 2 分钟内的新鲜标志，防陈旧标志误杀）
    while ($true) {
        if (Test-Path $stopFlag) {
            $honorStop = $false
            try {
                $ts = [datetime]((Get-Content $stopFlag -Raw -Encoding UTF8).Trim())
                if (((Get-Date) - $ts).TotalMinutes -le 2) { $honorStop = $true }
            } catch { $honorStop = $false }
            if ($honorStop) {
                Remove-Item $stopFlag -Force -ErrorAction SilentlyContinue
                Log "检测到停止标志，退出守护"
                break
            } else {
                Remove-Item $stopFlag -Force -ErrorAction SilentlyContinue
                Log "发现陈旧停止标志（>2 分钟），已忽略并清除，守护继续运行"
            }
        }
        Wait-Event -Timeout 60 | Out-Null
    }
    Unregister-Event -SourceIdentifier 'ClaudeGuardWatch' -ErrorAction SilentlyContinue
    exit 0
}

# ══════════════════════════════════════════
# 模式：-TestToast / -ToastAction（弹窗按钮回调）
# ══════════════════════════════════════════
if ($TestToast) {
    Ensure-CGProtocol
    Show-Toast 'Clash 护卫 · 测试弹窗' '这是一条带按钮的测试通知，点各按钮验证。' @(
        @{ label = '一键修复'; args = 'clashguard:fix' },
        @{ label = '查IP质量'; args = 'clashguard:openip' },
        @{ label = '泄露检测'; args = 'clashguard:checkleaks' },
        @{ label = '暂停自动修复'; args = 'clashguard:protect' }
    )
    Write-Host '[OK] 测试弹窗已发送（含四个按钮）'
    exit 0
}
if ($ToastAction) {
    $a = "$ToastAction" -replace '^(clashguard:|%1)', '' | ForEach-Object { $_.Trim() }
    Log "Toast 按钮触发: $a"
    switch -Regex ($a) {
        'fix' {
            $fx = Invoke-AutoFix -Force
            Show-Toast 'Clash 护卫 · 一键修复结果' (($fx.actions -join '；'))
        }
        'openip' { Start-Process $openUrl }
        'checkleaks' {
            # 生成轻量 HTML 导航页（不一次性开 7 个标签页，用户按需点）
            $html = "<!DOCTYPE html><meta charset=utf-8><title>泄露检测导航</title><style>body{font-family:system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 20px}h1{font-size:1.4em}table{width:100%;border-collapse:collapse}td{padding:8px 6px;border-bottom:1px solid #eee}a{color:#0066cc;text-decoration:none}a:hover{text-decoration:underline}.cat{color:#888;font-size:.85em}</style><h1>泄露检测导航</h1><p>根据实际需要点击，不必全测：</p><table>"
            $lastCat = ''
            foreach ($s in @($cfg.manualCheckSites)) {
                $cat = [string]$s.cat
                if ($cat -ne $lastCat) { $html += "<tr><td colspan=2 style='font-weight:bold;padding-top:12px'>$cat</td></tr>"; $lastCat = $cat }
                $html += "<tr><td><a href='$([string]$s.url)' target='_blank'>$([string]$s.name)</a></td><td class='cat'>$([string]$s.url)</td></tr>"
            }
            $html += "</table><p style='color:#999;font-size:.8em;margin-top:20px'>生成于 $(Get-Date -Format 'yyyy-MM-dd HH:mm') · clash_guard</p>"
            $tmp = "$env:TEMP\cg_leaks.html"
            [IO.File]::WriteAllText($tmp, $html, (New-Object Text.UTF8Encoding $true))
            Start-Process $tmp
            Log "已生成泄露检测导航页（$tmp），用户按需点击"
        }
        'start'  { Start-GuardWatch }
        'protect' {
            if (Test-Path $protectFlag) {
                Remove-Item $protectFlag -Force -ErrorAction SilentlyContinue
                Show-Toast 'Clash 护卫 · 保护模式已关闭' '已恢复自动修复：违规时将自动开 TUN/关本地系统代理。'
                Log '保护模式已关闭（恢复自动修复，Toast 按钮）'
            } else {
                (Get-Date).ToString('o') | Set-Content -Path $protectFlag -Encoding UTF8
                Show-Toast 'Clash 护卫 · 保护模式已开启' '只检测+告警，暂停自动修复（网络零变更）；Claude 门控拦截不受影响。'
                Log '保护模式已开启（只检测不自动修，Toast 按钮）'
            }
        }
        default  { }
    }
    exit 0
}

# ══════════════════════════════════════════
# 模式：巡检（默认）/ -Report
# ══════════════════════════════════════════
$env = Get-EnvState
$clashOk = $env.clashOk; $tunOk = $env.tunOk; $tunName = $env.tunAdapter
$proxyOn = $env.sysProxyOn; $exitIps = $env.exitIps
$protectOn = (Test-Path $protectFlag)
$advisories = @()
if ($env.pacUrl) { $advisories += "检测到 PAC 自动配置（$($env.pacUrl)），只提示不修改" }

# 软规则缓存：供 -Watch 使用（硬规则全部实时检测，不依赖此缓存）
$gateCache = [ordered]@{
    at         = $env.at
    exitIps    = $exitIps
    ipOkCount  = [int]$env.ipOkCount
    softFail   = $env.softFail
    softReason = $env.softReason
}

$violations = @()
if (-not $clashOk) { $violations += 'Clash 未运行' }
elseif (-not $tunOk) { $violations += 'TUN 模式未生效（虚拟网卡不在位）' }
if ($proxyOn) { $violations += '系统代理开启（应关闭）' }
if ($env.ipv6Leak) { $violations += "IPv6 泄露（物理网卡有全局 IPv6 地址: $($env.ipv6LeakIp)）" }
if ($env.softFail) { $violations += "IP 质量不佳：$($env.softReason)" }
$ok = ($violations.Count -eq 0)

$summary = "出口 IP：$(if ($exitIps) { $exitIps -join ' / ' } else { '未知' })"
$rep = [ordered]@{ at=$env.at; clashOk=$clashOk; tunOk=$tunOk; tunAdapter=$tunName; sysProxyOn=$proxyOn; endpoints=$env.endpoints; exitIps=$exitIps; violations=$violations }

if ($Report) {
    Write-Host "=== Clash 护卫报告 $($env.at) ==="
    Write-Host "Clash 进程 : $(if ($clashOk) { '运行中' } else { '未运行' })"
    Write-Host "TUN 虚拟网卡: $(if ($tunOk) { "开启（$tunName）" } else { '未生效' })"
    Write-Host "系统代理   : $(if ($proxyOn) { '开启 —— 应关闭！' } else { '关闭（符合要求）' })"
    Write-Host "PAC 自动配置: $(if ($env.pacUrl) { $env.pacUrl } else { '无' })"
    Write-Host "IPv6 泄露  : $(if ($env.ipv6Leak) { "是（$($env.ipv6LeakIp)）" } else { '无' })"
    Write-Host "网络保护模式: $(if ($protectOn) { '开启（只检测不自动修）' } else { '关闭' })"
    Write-Host "Claude 服务连通: $(if (Test-ClaudeServiceLive) { '可达' } else { '不可达 —— 会硬拦截' })"
    Write-Host "IP 质量检测:"
    foreach ($l in $env.endpoints) { Write-Host "  $l" }
    $extra = @(); if ($advisories) { $extra += $advisories }
    Write-Host "判定: $(if ($ok -and -not $extra) { '全部符合要求' } else { ($violations + $extra) -join '；' })"
    if ($cfg.manualCheckSites) {
        Write-Host "手动泄露检测站（需浏览器，点 Toast「泄露检测」一键打开）:"
        foreach ($s in @($cfg.manualCheckSites)) { Write-Host "  [$($s.cat)] $($s.name) - $($s.url)" }
    }
    exit 0
}

# ── 顺带照看拦截守护：任务被禁用→提醒恢复；进程不在→自愈拉起（只读巡检 -Report 不执行）──
Invoke-WatchCare

# ── 自动修复（违规时先尝试修，修完重估违规再通知；保护模式下跳过所有网络变更）──
if ($autoFix -and ($violations.Count -gt 0) -and -not $protectOn) {
    Ensure-CGProtocol
    $fx = Invoke-AutoFix
    if ($fx.attempted) {
        # 快速重估硬环境（IP 质量沿用本次巡检结果）
        $clashOk = [bool](Get-Process -Name 'clash-verge','clash-verge-service','verge-mihomo','mihomo' -ErrorAction SilentlyContinue)
        $tunAdp  = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Meta Tunnel|Wintun|Mihomo|Clash' -and $_.Status -eq 'Up' }
        $tunOk   = [bool]$tunAdp; $tunName = ($tunAdp | Select-Object -First 1).Name
        $proxyOn = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyEnable -eq 1
        $violations = @()
        if (-not $clashOk) { $violations += 'Clash 未运行' }
        elseif (-not $tunOk) { $violations += 'TUN 模式未生效（虚拟网卡不在位）' }
        if ($proxyOn) { $violations += '系统代理开启（应关闭）' }
        if ($env.softFail) { $violations += "IP 质量不佳：$($env.softReason)" }
        $ok = ($violations.Count -eq 0)
        $summary = "$summary（自动修复：$($fx.actions -join '；')）"
        $rep.sysProxyOn = $proxyOn; $rep.tunOk = $tunOk; $rep.violations = $violations
        Log "自动修复结果: $($fx.actions -join '；') → 重估后违规: $(if ($ok) { '无' } else { $violations -join '；' })"
    }
}

# ── 状态去重与通知 ──
$consecBad = 0; $alerted = $false; $escalated = $false; $lastSig = ''
if (Test-Path $stateFile) {
    try {
        $s = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $consecBad = [int]$s.consecBad; $alerted = [bool]$s.alerted; $escalated = [bool]$s.escalated; $lastSig = [string]$s.lastSignature
    } catch {}
}

$sig = "$($violations -join '|')#$($exitIps -join ',')"
$sigChanged = ($sig -ne $lastSig)

if ($ok) {
    if ($alerted -or $escalated) {
        Show-Toast 'Clash 护卫 · 已恢复' "TUN/系统代理/IP 质量已符合要求。$summary"
        Log '已恢复（此前已告警）'
    }
    @{ consecBad=0; alerted=$false; escalated=$false; lastSignature=$sig; lastReport=$rep; gateCache=$gateCache } | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding UTF8
    exit 0
}

$consecBad++
if ($sigChanged) { $consecBad = 1 }

$qline = Get-IpQualityLine $env.endpoints $exitIps
$btnActions = @(
    @{ label = '一键修复'; args = 'clashguard:fix' },
    @{ label = "查IP质量($openName)"; args = 'clashguard:openip' },
    @{ label = '泄露检测'; args = 'clashguard:checkleaks' },
    @{ label = $(if ($protectOn) { '关闭保护模式' } else { '暂停自动修复' }); args = 'clashguard:protect' }
)
$note = ''
if ($protectOn) { $note = '（保护模式：只检测不自动修，点「关闭保护模式」恢复）' }
elseif ($advisories.Count -gt 0) { $note = "（$($advisories -join '；')）" }

if (-not $alerted -or ($sigChanged -and $lastSig -ne '')) {
    Show-Toast 'Clash 护卫 · 需要处理' "$($violations -join '；')。$qline$note" $btnActions
    Log "告警: $($violations -join '；')$(if ($note) { " $note" })"
    $alerted = $true
} elseif ($consecBad -ge [int]$cfg.escalateAfterCycles -and -not $escalated) {
    Show-Toast 'Clash 护卫 · 持续未处理' "连续 $consecBad 个周期仍违规：$($violations -join '；')。$qline$note" $btnActions
    Log "升级提醒: 连续 $consecBad 周期未处理"
    $escalated = $true
} else {
    Log "违规持续（第 $consecBad 周期，静默）: $($violations -join '；')"
}

@{ consecBad=$consecBad; alerted=$alerted; escalated=$escalated; lastSignature=$sig; lastReport=$rep; gateCache=$gateCache } | ConvertTo-Json -Depth 5 | Set-Content -Path $stateFile -Encoding UTF8
