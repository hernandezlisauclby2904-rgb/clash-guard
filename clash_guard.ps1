#requires -Version 5.1
<#
.SYNOPSIS
  Clash Guard v2.0 - conservative Windows network-state guard for Claude Desktop/Claude Code.
.DESCRIPTION
  PowerShell 5.1, current-user configuration, no third-party PowerShell modules.
  IMPORTANT: process-start monitoring is reactive. Use -Launch for a preflight before a controlled launch.
#>
[CmdletBinding()]
param(
    [switch]$Report,
    [switch]$Watch,
    [switch]$Launch,
    [switch]$AllowClaude,
    [switch]$EmergencyAllow,
    [switch]$Stop,
    [switch]$Start,
    [switch]$EmergencyLaunch,
    [switch]$Protect,
    [switch]$TestToast,
    [string]$ToastAction
)

$ErrorActionPreference = 'Stop'
$script:AppName = 'Clash Guard'
$script:WatchTask = 'ClashGuard-Watch'
$script:PollTask = 'ClashGuard-Inspect'
$script:BaseDir = if ($PSScriptRoot) { [IO.Path]::GetFullPath($PSScriptRoot) } else { [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path)) }
$script:LogsDir = Join-Path $script:BaseDir 'logs'
$script:ConfigFile = Join-Path $script:BaseDir 'clash_guard_config.json'
$script:StateFile = Join-Path $script:LogsDir 'clash_guard_state.json'
$script:LogFile = Join-Path $script:LogsDir 'clash_guard.log'
$script:AllowFlag = Join-Path $script:LogsDir 'clash_guard_allow.flag'
$script:EmergencyFlag = Join-Path $script:LogsDir 'clash_guard_emergency.flag'
$script:StopFlag = Join-Path $script:LogsDir 'clash_guard_watch.stop'
$script:WatchStopAlert = Join-Path $script:LogsDir 'clash_guard_watchstop.alert'
$script:ProtectFlag = Join-Path $script:LogsDir 'clash_guard_protect.flag'
$script:CooldownFile = Join-Path $script:LogsDir 'clash_guard_fix.cooldown'
$script:Config = $null
$script:LogRotated = $false

if (-not (Test-Path -LiteralPath $script:LogsDir)) {
    New-Item -ItemType Directory -Path $script:LogsDir -Force | Out-Null
}

function Write-CGLog {
    param([Parameter(Mandatory=$true)][string]$Message)
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $PID, $Message
    try {
        if (-not $script:LogRotated -and (Test-Path -LiteralPath $script:LogFile)) {
            $length = (Get-Item -LiteralPath $script:LogFile).Length
            if ($length -gt 2MB) {
                $backup = "$($script:LogFile).1"
                if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
                Move-Item -LiteralPath $script:LogFile -Destination $backup -Force
            }
            $script:LogRotated = $true
        }
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    } catch {
        Write-Warning "无法写入 Clash Guard 日志：$($_.Exception.Message)"
    }
}

function Get-CGDefaultConfig {
    return [ordered]@{
        schemaVersion = 2
        ipEndpointTimeoutSec = 6
        cacheFreshMinutes = 30
        fraudScoreMax = 50
        claudeScoreMax = 50
        allowGraceMinutes = 10
        escalateAfterCycles = 3
        autoFix = $false
        autoFixCooldownMin = 10
        autoStartClash = $false
        blockPacProxy = $true
        blockAutoDetectProxy = $true
        tunAdapterPattern = '(?i)(Meta Tunnel|Wintun|Mihomo|Clash|sing-tun)'
        reachableHosts = @('api.anthropic.com:443','claude.ai:443')
        apiPorts = @(9097,9090,9095,9091)
        apiSecret = ''
        expectedIPv4 = ''
        ipEndpoints = @(
            @{ name='ip.sb'; url='https://api.ip.sb/geoip'; role='basic' },
            @{ name='ipinfo'; url='https://ipinfo.io/json'; role='basic' },
            @{ name='ipquery.io'; url='https://api.ipquery.io/?format=json'; role='network-risk' },
            @{ name='ipwho.is'; url='https://ipwho.is/'; role='basic' },
            @{ name='ippure'; url='https://my.ippure.com/v1/info'; role='fraud-risk' },
            @{ name='claude-risk'; url='https://fuck-claude.vercel.app/api/check?format=json'; role='claude-risk' },
            @{ name='ipleak.net'; url='https://ipleak.net/json/'; role='basic' }
        )
        recommendedIpSite = @{ name='IP / Claude 风险参考'; url='https://fuck-claude.vercel.app' }
        manualCheckSites = @(
            @{ cat='DNS 泄露'; name='DNS Leak Test'; url='https://dnsleaktest.com/' },
            @{ cat='DNS 泄露'; name='BrowserLeaks DNS'; url='https://browserleaks.com/dns' },
            @{ cat='DNS 泄露'; name='IPLeak'; url='https://ipleak.net/' },
            @{ cat='WebRTC'; name='BrowserLeaks WebRTC'; url='https://browserleaks.com/webrtc' },
            @{ cat='浏览器指纹'; name='EFF Cover Your Tracks'; url='https://coveryourtracks.eff.org/' }
        )
    }
}

function Save-CGJsonAtomic {
    param([Parameter(Mandatory=$true)][string]$Path, [Parameter(Mandatory=$true)]$Value, [int]$Depth=8)
    $temp = "$Path.$PID.tmp"
    $json = ConvertTo-Json -InputObject $Value -Depth $Depth
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($temp, $json, $encoding)
    if (Test-Path -LiteralPath $Path) {
        Move-Item -LiteralPath $temp -Destination $Path -Force
    } else {
        Move-Item -LiteralPath $temp -Destination $Path
    }
}

function Import-CGConfig {
    if (-not (Test-Path -LiteralPath $script:ConfigFile)) {
        Save-CGJsonAtomic -Path $script:ConfigFile -Value (Get-CGDefaultConfig) -Depth 8
        Write-CGLog "已创建默认配置：$($script:ConfigFile)"
    }
    try {
        $raw = Get-Content -LiteralPath $script:ConfigFile -Raw -Encoding UTF8
        $cfg = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        # Keep machine-specific values (API token / expected public IP) out of the tracked release config.
        # Local overrides are still validated by the same schema checks below.
        $localConfigFile = Join-Path $script:BaseDir 'clash_guard_config.local.json'
        if (Test-Path -LiteralPath $localConfigFile) {
            $localCfg = Get-Content -LiteralPath $localConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            if ($localCfg -isnot [System.Management.Automation.PSCustomObject]) { throw 'clash_guard_config.local.json 顶层必须是 JSON 对象。' }
            $allowedLocalKeys = @('autoFix','autoStartClash','blockPacProxy','blockAutoDetectProxy','tunAdapterPattern','reachableHosts','apiPorts','apiSecret','expectedIPv4','ipEndpoints','ipEndpointTimeoutSec','cacheFreshMinutes','fraudScoreMax','claudeScoreMax','allowGraceMinutes','escalateAfterCycles','autoFixCooldownMin','recommendedIpSite','manualCheckSites')
            foreach ($localProp in $localCfg.PSObject.Properties) {
                if ($allowedLocalKeys -notcontains [string]$localProp.Name) { throw ("本地配置包含不支持的字段：{0}" -f $localProp.Name) }
                $cfg | Add-Member -NotePropertyName $localProp.Name -NotePropertyValue $localProp.Value -Force
            }
            Write-CGLog '已加载 clash_guard_config.local.json（本地覆盖值不会自动上传）。'
        }
        if ($null -eq $cfg.ipEndpoints -or @($cfg.ipEndpoints).Count -eq 0) { throw 'ipEndpoints 必须至少包含一个检测端点。' }
        foreach ($ep in @($cfg.ipEndpoints)) {
            if ([string]::IsNullOrWhiteSpace([string]$ep.name) -or [string]$ep.url -notmatch '^https://') {
                throw '每个 ipEndpoints 项都必须具有 name 和 HTTPS url。'
            }
        }
        # Preserve user-supplied values, but backfill newly introduced optional keys from safe defaults.
        $defaults = Get-CGDefaultConfig
        foreach ($entry in $defaults.GetEnumerator()) {
            if (-not $cfg.PSObject.Properties[$entry.Key]) {
                $cfg | Add-Member -NotePropertyName $entry.Key -NotePropertyValue $entry.Value -Force
            }
        }
        if (-not [string]::IsNullOrWhiteSpace([string]$cfg.expectedIPv4)) {
            if (-not (Test-CGIPv4Address -Address ([string]$cfg.expectedIPv4).Trim())) {
                throw 'expectedIPv4 必须是标准点分十进制 IPv4 地址；不需要固定出口时请留空。'
            }
        }
        if (-not $cfg.reachableHosts) { $cfg | Add-Member -NotePropertyName reachableHosts -NotePropertyValue @('api.anthropic.com:443','claude.ai:443') -Force }
        if (-not $cfg.apiPorts) { $cfg | Add-Member -NotePropertyName apiPorts -NotePropertyValue @(9097,9090,9095,9091) -Force }
        if (-not $cfg.tunAdapterPattern) { $cfg | Add-Member -NotePropertyName tunAdapterPattern -NotePropertyValue '(?i)(Meta Tunnel|Wintun|Mihomo|Clash|sing-tun)' -Force }
        if ($null -eq $cfg.allowGraceMinutes) { $cfg | Add-Member -NotePropertyName allowGraceMinutes -NotePropertyValue 10 -Force }
        if ($null -eq $cfg.cacheFreshMinutes) { $cfg | Add-Member -NotePropertyName cacheFreshMinutes -NotePropertyValue 30 -Force }
        if ($null -eq $cfg.autoFix) { $cfg | Add-Member -NotePropertyName autoFix -NotePropertyValue $false -Force }
        if ($null -eq $cfg.blockPacProxy) { $cfg | Add-Member -NotePropertyName blockPacProxy -NotePropertyValue $true -Force }
        if ($null -eq $cfg.blockAutoDetectProxy) { $cfg | Add-Member -NotePropertyName blockAutoDetectProxy -NotePropertyValue $true -Force }
        foreach ($boolName in @('autoFix','autoStartClash','blockPacProxy','blockAutoDetectProxy')) {
            $boolValue = $cfg.PSObject.Properties[$boolName].Value
            if ($boolValue -isnot [bool]) { throw ("配置项 {0} 必须是 JSON true/false，不能写成字符串或数字。" -f $boolName) }
        }
        $numericRules = @(
            @{ name='ipEndpointTimeoutSec'; min=2; max=20; integer=$true },
            @{ name='cacheFreshMinutes'; min=1; max=1440; integer=$true },
            @{ name='fraudScoreMax'; min=0; max=100; integer=$false },
            @{ name='claudeScoreMax'; min=0; max=100; integer=$false },
            @{ name='allowGraceMinutes'; min=1; max=60; integer=$true },
            @{ name='escalateAfterCycles'; min=1; max=20; integer=$true },
            @{ name='autoFixCooldownMin'; min=1; max=240; integer=$true }
        )
        foreach ($rule in $numericRules) {
            $rawValue = $cfg.PSObject.Properties[[string]$rule.name].Value
            if ($rule.integer) {
                $parsedValue = 0
                if (-not [int]::TryParse([string]$rawValue, [ref]$parsedValue) -or $parsedValue -lt $rule.min -or $parsedValue -gt $rule.max) {
                    throw ("配置项 {0} 必须是 {1} 到 {2} 之间的整数。" -f $rule.name,$rule.min,$rule.max)
                }
            } else {
                $parsedValue = 0.0
                if (-not [double]::TryParse([string]$rawValue, [ref]$parsedValue) -or [double]::IsNaN($parsedValue) -or [double]::IsInfinity($parsedValue) -or $parsedValue -lt $rule.min -or $parsedValue -gt $rule.max) {
                    throw ("配置项 {0} 必须是 {1} 到 {2} 之间的有限数字。" -f $rule.name,$rule.min,$rule.max)
                }
            }
        }
        $script:Config = $cfg
        return $true
    } catch {
        Write-CGLog "配置错误，拒绝执行常规模式：$($_.Exception.Message)"
        Write-Host "配置文件无效：$($_.Exception.Message)`n请修复 $($script:ConfigFile)；紧急放行与停止/恢复命令仍可使用。" -ForegroundColor Red
        return $false
    }
}

function Test-CGGraceFlag {
    param([string]$Path, [int]$Minutes=10)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $ts = [datetimeoffset]::Parse((Get-Content -LiteralPath $Path -Raw -Encoding UTF8).Trim())
        if ((([datetimeoffset]::Now - $ts).TotalMinutes -ge 0) -and (([datetimeoffset]::Now - $ts).TotalMinutes -lt $Minutes)) { return $true }
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    } catch {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
    return $false
}

function Set-CGGraceFlag {
    param([string]$Path)
    [datetimeoffset]::Now.ToString('o') | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Get-CGEarlyGraceMinutes {
    try {
        if (Test-Path -LiteralPath $script:ConfigFile) {
            $early = Get-Content -LiteralPath $script:ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
            $minutes = [int]$early.allowGraceMinutes
            if ($minutes -ge 1 -and $minutes -le 60) { return $minutes }
        }
    } catch {}
    return 10
}

function ConvertTo-CGXmlText {
    param([AllowNull()][object]$Value)
    $s = [string]$Value
    $s = $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&apos;')
    return $s
}

function Show-CGToast {
    param([string]$Title, [string]$Body, [object[]]$Actions=@())
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
        $actionXml = ''
        foreach ($action in @($Actions)) {
            if ($null -eq $action) { continue }
            $id = ([string]$action.id).ToLowerInvariant()
            if ($id -notin @('fix','openip','checkleaks','start','protect')) { continue }
            $label = ConvertTo-CGXmlText $action.label
            $uri = ConvertTo-CGXmlText ("clashguard:$id")
            $actionXml += "<action activationType='protocol' arguments='$uri' content='$label'/>"
        }
        if ($actionXml) { $actionXml = "<actions>$actionXml</actions>" }
        $xmlText = "<toast><visual><binding template='ToastGeneric'><text>$(ConvertTo-CGXmlText $Title)</text><text>$(ConvertTo-CGXmlText $Body)</text></binding></visual>$actionXml</toast>"
        $doc = New-Object Windows.Data.Xml.Dom.XmlDocument
        $doc.LoadXml($xmlText)
        $toast = New-Object Windows.UI.Notifications.ToastNotification $doc
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
    } catch {
        Write-CGLog "Toast 发送失败：$($_.Exception.Message)"
    }
}

function Register-CGProtocol {
    $root = 'HKCU:\Software\Classes\clashguard'
    $vbs = Join-Path $script:BaseDir 'toast_action.vbs'
    if (-not (Test-Path -LiteralPath $vbs)) {
        Write-CGLog '缺少 toast_action.vbs，通知按钮不可用。'
        return $false
    }
    try {
        $commandPath = "$root\shell\open\command"
        $wscript = Join-Path $env:WINDIR 'System32\wscript.exe'
        $command = '"{0}" "{1}" "%1"' -f $wscript, $vbs
        if (-not (Test-Path -LiteralPath $root)) { New-Item -Path $root -Force | Out-Null }
        $rootKey = Get-Item -LiteralPath $root -ErrorAction Stop
        if ([string]$rootKey.GetValue('') -ne 'URL:Clash Guard Action') { Set-Item -LiteralPath $root -Value 'URL:Clash Guard Action' -Force }
        $protocolValue = $rootKey.GetValue('URL Protocol', $null, 'DoNotExpandEnvironmentNames')
        if ($null -eq $protocolValue) { New-ItemProperty -Path $root -Name 'URL Protocol' -Value '' -PropertyType String -Force | Out-Null }
        if (-not (Test-Path -LiteralPath $commandPath)) { New-Item -Path $commandPath -Force | Out-Null }
        $commandKey = Get-Item -LiteralPath $commandPath -ErrorAction Stop
        if ([string]$commandKey.GetValue('') -ne $command) { Set-ItemProperty -LiteralPath $commandPath -Name '(default)' -Value $command -Force }
        Write-CGLog '已确认 clashguard: 安全白名单动作协议。'
        return $true
    } catch {
        Write-CGLog "注册 clashguard 协议失败：$($_.Exception.Message)"
        return $false
    }
}

function Get-CGPropertyMap {
    param([AllowNull()]$Object, [int]$Depth=0, [hashtable]$Map=@{})
    if ($null -eq $Object -or $Depth -gt 5 -or $Map.Count -gt 100) { return $Map }
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in $Object.PSObject.Properties) {
            $key = ([string]$prop.Name).ToLowerInvariant()
            $value = $prop.Value
            if ($value -is [System.Management.Automation.PSCustomObject]) {
                Get-CGPropertyMap -Object $value -Depth ($Depth + 1) -Map $Map | Out-Null
            } elseif ($value -is [System.Collections.IDictionary]) {
                foreach ($k in $value.Keys) { $Map[([string]$k).ToLowerInvariant()] = $value[$k] }
            } elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                foreach ($entry in @($value | Select-Object -First 5)) {
                    if ($entry -is [System.Management.Automation.PSCustomObject]) { Get-CGPropertyMap -Object $entry -Depth ($Depth + 1) -Map $Map | Out-Null }
                }
            } else {
                if (-not $Map.ContainsKey($key)) { $Map[$key] = $value }
            }
            if ($Map.Count -gt 100) { break }
        }
    } elseif ($Object -is [System.Collections.IDictionary]) {
        foreach ($key in $Object.Keys) { $Map[([string]$key).ToLowerInvariant()] = $Object[$key] }
    }
    return $Map
}

function Get-CGFirstValue {
    param([hashtable]$Map, [string[]]$Names)
    foreach ($name in $Names) {
        $key = $name.ToLowerInvariant()
        if ($Map.ContainsKey($key) -and $null -ne $Map[$key] -and [string]$Map[$key] -ne '') { return $Map[$key] }
    }
    return $null
}

function ConvertTo-CGBoolOrNull {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if ($s -in @('true','1','yes','on')) { return $true }
    if ($s -in @('false','0','no','off')) { return $false }
    return $null
}

function Test-CGIpAddress {
    param([AllowNull()][string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $parsed = $null
    return [System.Net.IPAddress]::TryParse($Address.Trim(), [ref]$parsed)
}

function Test-CGIPv4Address {
    param([AllowNull()][string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    $candidate = $Address.Trim()
    # Require canonical dotted-decimal IPv4; reject abbreviated, integer, hexadecimal and IPv6 forms.
    $octet = '(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)'
    if ($candidate -notmatch "^(?:$octet\.){3}$octet$") { return $false }
    $parsed = $null
    return ([System.Net.IPAddress]::TryParse($candidate, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
}

function Invoke-CGJsonEndpoint {
    param([Parameter(Mandatory=$true)]$Endpoint, [int]$TimeoutSec=6)
    $result = [ordered]@{
        name = [string]$Endpoint.name
        role = [string]$Endpoint.role
        ok = $false
        error = ''
        ip = ''
        country = ''
        fields = @{}
    }
    try {
        $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
        if (-not $curl) { throw '未找到 Windows 自带 curl.exe；该端点状态记为 UNKNOWN。' }
        $bodyLines = & $curl.Source -4 -fsS --max-time $TimeoutSec --noproxy '*' -A 'clash-guard/2.0' ([string]$Endpoint.url) 2>$null
        $curlCode = $LASTEXITCODE
        if ($curlCode -ne 0 -or -not $bodyLines) { throw "curl.exe 失败，退出码 $curlCode" }
        $body = ($bodyLines -join "`n")
        $json = ConvertFrom-Json -InputObject $body -ErrorAction Stop
        $map = Get-CGPropertyMap -Object $json
        $successVal = Get-CGFirstValue -Map $map -Names @('success','ok')
        $successBool = ConvertTo-CGBoolOrNull $successVal
        if ($successBool -eq $false) { throw '接口返回 success=false。' }
        if ($map.Count -eq 0) { throw '响应不是可识别的 JSON 对象。' }
        $ip = Get-CGFirstValue -Map $map -Names @('ip','query','ip_address','ipaddress')
        if ($ip -and (Test-CGIpAddress ([string]$ip))) { $result.ip = [string]$ip }
        $country = Get-CGFirstValue -Map $map -Names @('country_code','countrycode','country')
        if ($country) { $result.country = [string]$country }
        $role = [string]$Endpoint.role
        if ([string]::IsNullOrWhiteSpace($role)) {
            if ([string]$Endpoint.name -match '(?i)ippure|fraud') { $role = 'fraud-risk' }
            elseif ([string]$Endpoint.name -match '(?i)ipquery') { $role = 'network-risk' }
            elseif ([string]$Endpoint.name -match '(?i)claude') { $role = 'claude-risk' }
            else { $role = 'basic' }
        }
        if ($role -eq 'basic' -and -not $result.ip) { throw '基础 IP 接口响应缺少有效 IP 字段。' }
        if ($role -eq 'fraud-risk' -and $null -eq (Get-CGFirstValue -Map $map -Names @('fraudscore','fraud_score','isresidential','is_residential','residential'))) { throw '响应缺少 fraudScore / isResidential 风险字段。' }
        if ($role -eq 'network-risk' -and $null -eq (Get-CGFirstValue -Map $map -Names @('is_datacenter','isdatacenter','datacenter'))) { throw '响应缺少可判断的 is_datacenter 字段。' }
        if ($role -eq 'claude-risk' -and $null -eq (Get-CGFirstValue -Map $map -Names @('score','claude_score','risk_score','riskscore','band','verdict'))) { throw '响应缺少第三方风险分/等级字段。' }
        $result.ok = $true
        $result.role = $role
        $result.fields = $map
    } catch {
        $result.error = $_.Exception.Message.Split("`n")[0]
    }
    return [pscustomobject]$result
}

function Get-CGIpQuality {
    $preflightError = ''
    if (@(Get-CGTunAdapters).Count -eq 0) {
        $preflightError = '未检测到 TUN 接口；为避免直接向第三方站点暴露真实出口 IP，跳过请求'
    } else {
        $ipv4Preflight = Get-CGIPv4RouteStatus
        $ipv6Preflight = Get-CGIPv6Status
        if ($ipv4Preflight.state -ne 'PASS') { $preflightError = 'IPv4 路由尚未验证通过；为避免向第三方站点暴露未确认的出口 IP，跳过请求：' + $ipv4Preflight.detail }
        elseif ($ipv6Preflight.leak) { $preflightError = 'IPv6 路由检查未通过；为避免旁路泄露，跳过第三方 IP 请求：' + $ipv6Preflight.detail }
    }
    if ($preflightError) {
        $skipped = @()
        foreach ($ep in @($script:Config.ipEndpoints)) {
            $skipped += [pscustomobject]@{ name=[string]$ep.name; role=[string]$ep.role; ok=$false; error=$preflightError; ip=''; country=''; fields=@{} }
        }
        Write-CGLog $preflightError
        return [pscustomobject]@{
            at=[datetimeoffset]::Now.ToString('o'); endpoints=$skipped; exitIps=@(); ipOkCount=0
            ipConsistency='UNKNOWN'; qualitySignals=0; qualitySources=0; qualityState='UNKNOWN'; softFail=$false; softReason=''
        }
    }
    $results = @()
    $timeout = 6
    if ($script:Config.ipEndpointTimeoutSec -and [int]$script:Config.ipEndpointTimeoutSec -ge 2 -and [int]$script:Config.ipEndpointTimeoutSec -le 20) {
        $timeout = [int]$script:Config.ipEndpointTimeoutSec
    }
    foreach ($endpoint in @($script:Config.ipEndpoints)) {
        $item = Invoke-CGJsonEndpoint -Endpoint $endpoint -TimeoutSec $timeout
        $results += $item
        if ($item.ok) { Write-CGLog ("IP 端点 {0}：ok={1}，ip={2}" -f $item.name,$item.ok,$item.ip) }
        else { Write-CGLog ("IP 端点 {0}：UNKNOWN，{1}" -f $item.name,$item.error) }
    }
    # Only providers returning a validated IPv4 address count toward IPv4 consensus. A v6-only response cannot satisfy IPv4 consensus.
    # If any endpoint reports an IPv6 address while this path expects IPv4, do not silently call the remaining IPv4s consistent.
    $allIpProviders = @($results | Where-Object { $_.ok -and $_.ip })
    $ipProviders = @($allIpProviders | Where-Object { Test-CGIPv4Address -Address ([string]$_.ip) })
    $nonIPv4ProviderCount = $allIpProviders.Count - $ipProviders.Count
    $ipSet = @($ipProviders | ForEach-Object { [string]$_.ip } | Select-Object -Unique)
    $ipOkCount = $ipProviders.Count
    $v4Set = @($ipProviders | ForEach-Object { [string]$_.ip } | Select-Object -Unique)
    if ($nonIPv4ProviderCount -gt 0) { $ipConsistency = 'MISMATCH' }
    elseif ($v4Set.Count -eq 1) { $ipConsistency = 'CONSISTENT' }
    elseif ($v4Set.Count -gt 1) { $ipConsistency = 'MISMATCH' }
    else { $ipConsistency = 'UNKNOWN' }
    $softFail = $false
    $reasons = @()
    $signals = 0
    # PASS 必须由至少两个不同的风险数据源支持，不能把同一供应商的两个字段当成两份独立佐证。
    $fraudSource = $false
    $networkSource = $false
    $claudeSource = $false

    $fraudEndpoint = $results | Where-Object { $_.name -match '(?i)ippure|fraud' } | Select-Object -First 1
    if ($fraudEndpoint -and $fraudEndpoint.ok) {
        $fraud = Get-CGFirstValue -Map $fraudEndpoint.fields -Names @('fraudscore','fraud_score')
        $residentValue = Get-CGFirstValue -Map $fraudEndpoint.fields -Names @('isresidential','is_residential','residential')
        if ($null -ne $fraud) {
            $num = 0.0
            if ([double]::TryParse([string]$fraud, [ref]$num) -and -not [double]::IsNaN($num) -and -not [double]::IsInfinity($num) -and $num -ge 0 -and $num -le 100) {
                $signals++
                $fraudSource = $true
                if ($num -gt [double]$script:Config.fraudScoreMax) { $softFail = $true; $reasons += "fraudScore=$num 超过阈值 $($script:Config.fraudScoreMax)" }
            } else { $reasons += 'fraudScore 字段无效或超出 0–100 范围，该信号不计入通过证据' }
        }
        $resident = ConvertTo-CGBoolOrNull $residentValue
        if ($null -ne $resident) {
            $signals++
            $fraudSource = $true
            if (-not $resident) { $softFail = $true; $reasons += '检测服务判断当前 IP 非住宅' }
        }
    }

    $networkEndpoint = $results | Where-Object { $_.name -match '(?i)ipquery' } | Select-Object -First 1
    if ($networkEndpoint -and $networkEndpoint.ok) {
        $dcVal = Get-CGFirstValue -Map $networkEndpoint.fields -Names @('is_datacenter','isdatacenter','datacenter')
        $dc = ConvertTo-CGBoolOrNull $dcVal
        if ($null -ne $dc) {
            $signals++
            $networkSource = $true
            if ($dc) { $softFail = $true; $reasons += '检测服务判断当前 IP 属于数据中心/机房' }
        }
    }

    $claudeEndpoint = $results | Where-Object { $_.name -match '(?i)claude' } | Select-Object -First 1
    if ($claudeEndpoint -and $claudeEndpoint.ok) {
        $score = Get-CGFirstValue -Map $claudeEndpoint.fields -Names @('score','claude_score','risk_score','riskscore')
        if ($null -ne $score) {
            $num = 0.0
            if ([double]::TryParse([string]$score, [ref]$num) -and -not [double]::IsNaN($num) -and -not [double]::IsInfinity($num) -and $num -ge 0 -and $num -le 100) {
                $signals++
                $claudeSource = $true
                if ($num -gt [double]$script:Config.claudeScoreMax) { $softFail = $true; $reasons += "第三方 Claude 风险参考分=$num 超过阈值 $($script:Config.claudeScoreMax)" }
            } else { $reasons += 'Claude 风险参考分无效或超出 0–100 范围，该信号不计入通过证据' }
        }
    }

    $qualitySourceCount = @(@($fraudSource,$networkSource,$claudeSource) | Where-Object { $_ }).Count
    $qualityState = 'UNKNOWN'
    if ($softFail) { $qualityState = 'FAIL' }
    elseif ($ipOkCount -ge 2 -and $qualitySourceCount -ge 2) { $qualityState = 'PASS' }
    if ($ipConsistency -ne 'CONSISTENT' -and $qualityState -ne 'FAIL') {
        $qualityState = 'UNKNOWN'
        if ($ipConsistency -eq 'MISMATCH') { $reasons += ("不同服务报告的 IPv4 出口不一致：" + ($v4Set -join ', ')) }
        else { $reasons += '没有足够的有效 IPv4 出口结果，无法确认各检测服务看到同一出口' }
    }
    $expected = [string]$script:Config.expectedIPv4
    if ($expected -and (Test-CGIpAddress $expected)) {
        if ($v4Set.Count -gt 0 -and $v4Set -notcontains $expected) {
            $qualityState = 'FAIL'
            $softFail = $true
            $reasons += '检测到的 IPv4 出口与配置的 expectedIPv4 不一致'
        } elseif ($v4Set.Count -eq 0) {
            if ($qualityState -ne 'FAIL') { $qualityState = 'UNKNOWN' }
        }
    }
    return [pscustomobject]@{
        at = [datetimeoffset]::Now.ToString('o')
        endpoints = $results
        exitIps = $ipSet
        ipOkCount = $ipOkCount
        ipConsistency = $ipConsistency
        qualitySignals = $signals
        qualitySources = $qualitySourceCount
        qualityState = $qualityState
        softFail = $softFail -or ($qualityState -eq 'FAIL')
        softReason = ($reasons | Select-Object -Unique) -join '；'
    }
}

function Get-CGProxyStatus {
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $settings = Get-ItemProperty -LiteralPath $reg -ErrorAction SilentlyContinue
    $proxyEnable = $false
    $pacUrl = ''
    $autoDetect = $false
    if ($settings) {
        $proxyEnable = ([int]$settings.ProxyEnable -eq 1)
        $pacUrl = [string]$settings.AutoConfigURL
        $autoDetect = ([int]$settings.AutoDetect -eq 1)
    }
    $blocked = $proxyEnable -or (($script:Config.blockPacProxy -eq $true) -and -not [string]::IsNullOrWhiteSpace($pacUrl)) -or (($script:Config.blockAutoDetectProxy -eq $true) -and $autoDetect)
    return [pscustomobject]@{ enabled=$proxyEnable; pacUrl=$pacUrl; autoDetect=$autoDetect; blocked=$blocked }
}

function Get-CGTunAdapters {
    $pattern = [string]$script:Config.tunAdapterPattern
    try {
        return @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -and (($_.InterfaceDescription -match $pattern) -or ($_.Name -match $pattern)) })
    } catch {
        Write-CGLog "读取网卡失败：$($_.Exception.Message)"
        return @()
    }
}

function Get-CGIPv4RouteStatus {
    # Verify the active IPv4 default or split-default routes really point at a detected TUN interface.
    # This check runs before third-party IP lookups so an unverified route does not send a public IP query directly.
    $tunAdapters = @(Get-CGTunAdapters)
    $tunIndexes = @($tunAdapters | ForEach-Object { [int]$_.ifIndex })
    if ($tunIndexes.Count -eq 0) {
        return [pscustomobject]@{ state='UNKNOWN'; verified=$false; detail='未检测到 TUN 接口，跳过第三方 IP 查询'; selectedRoutes=@() }
    }
    try {
        $candidates = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','0.0.0.0/1','128.0.0.0/1') })
    } catch {
        return [pscustomobject]@{ state='UNKNOWN'; verified=$false; detail='无法读取 IPv4 路由表；为避免未验证的出口查询，不访问第三方 IP 检测站'; selectedRoutes=@() }
    }
    $routeRows = @()
    foreach ($route in $candidates) {
        $iface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $iface) { continue }
        $routeRows += [pscustomobject]@{
            prefix=[string]$route.DestinationPrefix
            ifIndex=[int]$route.InterfaceIndex
            metric=([int]$route.RouteMetric + [int]$iface.InterfaceMetric)
        }
    }
    $splitExists = @($routeRows | Where-Object { $_.prefix -in @('0.0.0.0/1','128.0.0.0/1') }).Count -gt 0
    $targets = if ($splitExists) { @('0.0.0.0/1','128.0.0.0/1') } else { @('0.0.0.0/0') }
    $selected = @()
    $missingTargets = @()
    foreach ($target in $targets) {
        $matchingRoutes = @($routeRows | Where-Object { $_.prefix -eq $target })
        if ($matchingRoutes.Count -eq 0) { $missingTargets += $target; continue }
        $minMetric = ($matchingRoutes | Measure-Object -Property metric -Minimum).Minimum
        # Keep every equally preferred route: a physical route tied with TUN is not a confident PASS.
        $selected += @($matchingRoutes | Where-Object { $_.metric -eq $minMetric })
    }
    if ($missingTargets.Count -gt 0) {
        return [pscustomobject]@{ state='UNKNOWN'; verified=$false; detail=('无法完整确认 IPv4 默认/分流路由（缺少：' + ($missingTargets -join ', ') + '）；为避免未验证的出口查询，不访问第三方 IP 检测站'); selectedRoutes=$selected }
    }
    $outside = @($selected | Where-Object { $tunIndexes -notcontains $_.ifIndex })
    if ($outside.Count -gt 0) {
        $detail = ($outside | ForEach-Object { '{0} via ifIndex {1}' -f $_.prefix,$_.ifIndex }) -join ', '
        return [pscustomobject]@{ state='FAIL'; verified=$false; detail=('IPv4 默认/分流路由存在非 TUN 出口：' + $detail); selectedRoutes=$selected }
    }
    return [pscustomobject]@{ state='PASS'; verified=$true; detail='IPv4 默认/分流路由的有效下一跳均在 TUN 接口'; selectedRoutes=$selected }
}

function Get-CGIPv6Status {
    # Do not equate 'any IPv6 address exists' with a leak. Only global-unicast IPv6 plus an active physical default/split-default route is a risk.
    try { $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }) }
    catch { return [pscustomobject]@{ state='UNKNOWN'; leak=$true; detail=('无法枚举活动网卡，不能确认 IPv6 路径：' + $_.Exception.Message); physicalAddresses=@(); route='unknown' } }
    $tunAdapters = @(Get-CGTunAdapters)
    $tunIndexes = @($tunAdapters | ForEach-Object { [int]$_.ifIndex })
    $globalV6Physical = @()
    foreach ($adapter in $adapters) {
        if ($tunIndexes -contains [int]$adapter.ifIndex) { continue }
        if ($adapter.InterfaceDescription -match '(?i)Loopback' -or $adapter.Name -match '(?i)^Loopback') { continue }
        try { $addresses = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction Stop) }
        catch { return [pscustomobject]@{ state='UNKNOWN'; leak=$true; detail=("无法读取网卡 {0} 的 IPv6 地址，不能安全排除旁路：{1}" -f $adapter.Name,$_.Exception.Message); physicalAddresses=$globalV6Physical; route='unknown' } }
        foreach ($address in $addresses) {
            $ip = [string]$address.IPAddress
            # Global unicast 2000::/3; skip ULA (fc00::/7), link-local (fe80::/10), multicast, loopback and unspecified.
            if ($ip -match '^(?i:[23][0-9a-f]{0,3}:)' -and $ip -notmatch '^(?i:fe80:|ff|fc|fd|::1$|::$)') {
                $globalV6Physical += [pscustomobject]@{ ifIndex=[int]$adapter.ifIndex; adapter=[string]$adapter.Name; ip=$ip }
            }
        }
    }
    if ($globalV6Physical.Count -eq 0) {
        return [pscustomobject]@{ state='PASS'; leak=$false; detail='未发现物理网卡上的公网全局 IPv6 地址'; physicalAddresses=@(); route='none' }
    }

    $routeCandidates = @(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -in @('::/0','::/1','8000::/1') })
    $routes = @()
    foreach ($route in $routeCandidates) {
        $interface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue | Select-Object -First 1
        $interfaceMetric = if ($interface) { [int]$interface.InterfaceMetric } else { 999999 }
        $routes += [pscustomobject]@{ prefix=[string]$route.DestinationPrefix; ifIndex=[int]$route.InterfaceIndex; metric=([int]$route.RouteMetric + $interfaceMetric) }
    }
    $splitExists = @($routes | Where-Object { $_.prefix -in @('::/1','8000::/1') }).Count -gt 0
    $targets = if ($splitExists) { @('::/1','8000::/1') } else { @('::/0') }
    $selected = @()
    $missingTargets = @()
    foreach ($target in $targets) {
        $matchingRoutes = @($routes | Where-Object { $_.prefix -eq $target })
        if ($matchingRoutes.Count -eq 0) { $missingTargets += $target; continue }
        $minMetric = ($matchingRoutes | Measure-Object -Property metric -Minimum).Minimum
        # If the best metric is tied across TUN and a non-TUN adapter, preserve both paths as a risk.
        $selected += @($matchingRoutes | Where-Object { $_.metric -eq $minMetric })
    }
    if ($missingTargets.Count -gt 0) {
        return [pscustomobject]@{ state='UNKNOWN'; leak=$true; detail=('存在物理公网 IPv6 地址，但缺少完整默认/分流路由：' + ($missingTargets -join ', ') + '；按严格策略阻止启动'); physicalAddresses=$globalV6Physical; route='incomplete' }
    }
    $physicalRoute = @($selected | Where-Object { $tunIndexes -notcontains $_.ifIndex })
    if ($physicalRoute.Count -gt 0) {
        $routeText = ($physicalRoute | ForEach-Object { '{0} via ifIndex {1}' -f $_.prefix,$_.ifIndex }) -join ', '
        return [pscustomobject]@{ state='FAIL'; leak=$true; detail="IPv6 默认/分流路由仍指向非 TUN 接口：$routeText"; physicalAddresses=$globalV6Physical; route=$routeText }
    }
    return [pscustomobject]@{ state='PASS'; leak=$false; detail='检测到物理公网 IPv6 地址，但当前默认/分流路由由 TUN 接口承载'; physicalAddresses=$globalV6Physical; route='tunnel' }
}

function Test-CGTcpReachable {
    param([string]$HostName, [int]$Port=443, [int]$TimeoutMs=2500)
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $null
    try {
        $iar = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        if ($iar -and $iar.AsyncWaitHandle) { $iar.AsyncWaitHandle.Close() }
        $client.Close()
    }
}

function Test-CGClaudeConnectivity {
    # Two passes guard against transient packet loss; this is a TCP reachability signal, not an account/eligibility test.
    for ($round = 1; $round -le 2; $round++) {
        foreach ($entry in @($script:Config.reachableHosts)) {
            $parts = ([string]$entry) -split ':',2
            $hostname = $parts[0]
            $port = 443
            if ($parts.Count -eq 2 -and $parts[1] -match '^\d{1,5}$') { $port = [int]$parts[1] }
            if (Test-CGTcpReachable -HostName $hostname -Port $port -TimeoutMs 2500) { return $true }
        }
        if ($round -eq 1) { Start-Sleep -Seconds 1 }
    }
    return $false
}

function Get-CGCurrentExitIp {
    # Re-check routes immediately before the network lookup to reduce a route-change race after gate checks.
    $routeNow = Get-CGIPv4RouteStatus
    $ipv6Now = Get-CGIPv6Status
    if ($routeNow.state -ne 'PASS') { return [pscustomobject]@{ ok=$false; ip=''; error=('IPv4 路由未验证：' + $routeNow.detail) } }
    if ($ipv6Now.leak) { return [pscustomobject]@{ ok=$false; ip=''; error=('IPv6 路由未通过：' + $ipv6Now.detail) } }
    $endpoint = @($script:Config.ipEndpoints | Where-Object { ([string]$_.role -eq 'basic') -or ([string]$_.name -match '(?i)ip\.sb|ipinfo|ipwho') } | Select-Object -First 1)
    if ($endpoint.Count -eq 0) { return [pscustomobject]@{ ok=$false; ip=''; error='没有配置可用于出口确认的基础 IP 接口' } }
    $result = Invoke-CGJsonEndpoint -Endpoint $endpoint[0] -TimeoutSec 4
    if (-not $result.ok -or -not $result.ip) { return [pscustomobject]@{ ok=$false; ip=''; error=[string]$result.error } }
    if (-not (Test-CGIPv4Address -Address ([string]$result.ip))) {
        return [pscustomobject]@{ ok=$false; ip=''; error='基础接口未返回有效 IPv4 地址，无法将当前出口与 IPv4 质量缓存匹配' }
    }
    return [pscustomobject]@{ ok=$true; ip=[string]$result.ip; error='' }
}

function Get-CGStateSnapshot {
    $processes = @(Get-Process -Name 'clash-verge','clash-verge-service','verge-mihomo','mihomo' -ErrorAction SilentlyContinue)
    $tun = @(Get-CGTunAdapters)
    $proxy = Get-CGProxyStatus
    $ipv4Route = Get-CGIPv4RouteStatus
    $ipv6 = Get-CGIPv6Status
    $quality = Get-CGIpQuality
    return [pscustomobject]@{
        at = [datetimeoffset]::Now.ToString('o')
        clashOk = ($processes.Count -gt 0)
        tunOk = ($tun.Count -gt 0)
        tunAdapter = if ($tun.Count -gt 0) { [string]$tun[0].Name } else { '' }
        sysProxyOn = [bool]$proxy.enabled
        pacUrl = [string]$proxy.pacUrl
        autoDetectProxy = [bool]$proxy.autoDetect
        proxyBlocked = [bool]$proxy.blocked
        ipv4Route = $ipv4Route
        ipv6 = $ipv6
        endpoints = $quality.endpoints
        exitIps = $quality.exitIps
        ipOkCount = [int]$quality.ipOkCount
        ipConsistency = [string]$quality.ipConsistency
        qualitySignals = [int]$quality.qualitySignals
        qualitySources = [int]$quality.qualitySources
        qualityState = [string]$quality.qualityState
        softFail = [bool]$quality.softFail
        softReason = [string]$quality.softReason
        tcpReachable = $null
    }
}

function Read-CGState {
    if (-not (Test-Path -LiteralPath $script:StateFile)) { return $null }
    try { return (Get-Content -LiteralPath $script:StateFile -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop) } catch { Write-CGLog "状态缓存损坏，忽略并重建：$($_.Exception.Message)"; return $null }
}

function Save-CGState {
    param([Parameter(Mandatory=$true)]$State)
    try { Save-CGJsonAtomic -Path $script:StateFile -Value $State -Depth 10 } catch { Write-CGLog "写入状态缓存失败：$($_.Exception.Message)" }
}

function Test-CGGate {
    if (Test-CGGraceFlag -Path $script:EmergencyFlag -Minutes ([int]$script:Config.allowGraceMinutes)) {
        return [pscustomobject]@{ decision='allow'; reason='紧急总放行有效期内'; quality='UNKNOWN' }
    }
    $processes = @(Get-Process -Name 'clash-verge','clash-verge-service','verge-mihomo','mihomo' -ErrorAction SilentlyContinue)
    if ($processes.Count -eq 0) { return [pscustomobject]@{ decision='block_hard'; reason='未检测到 Clash Verge/Mihomo 进程'; quality='UNKNOWN' } }
    if (@(Get-CGTunAdapters).Count -eq 0) { return [pscustomobject]@{ decision='block_hard'; reason='未检测到已启动的 TUN 虚拟网卡'; quality='UNKNOWN' } }
    $ipv4Route = Get-CGIPv4RouteStatus
    if ($ipv4Route.state -ne 'PASS') { return [pscustomobject]@{ decision='block_hard'; reason=('IPv4 路由验证未通过：' + $ipv4Route.detail); quality='UNKNOWN' } }
    $proxy = Get-CGProxyStatus
    if ($proxy.enabled) { return [pscustomobject]@{ decision='block_hard'; reason='Windows 系统代理开关仍为开启'; quality='UNKNOWN' } }
    if ($script:Config.blockPacProxy -and -not [string]::IsNullOrWhiteSpace($proxy.pacUrl)) { return [pscustomobject]@{ decision='block_hard'; reason='检测到 PAC 自动代理配置；脚本不会自动清除该配置'; quality='UNKNOWN' } }
    if ($script:Config.blockAutoDetectProxy -and $proxy.autoDetect) { return [pscustomobject]@{ decision='block_hard'; reason='检测到 Windows 自动代理发现（WPAD）已启用'; quality='UNKNOWN' } }
    $ipv6 = Get-CGIPv6Status
    if ($ipv6.leak) { return [pscustomobject]@{ decision='block_hard'; reason="IPv6 路由检查未通过：$($ipv6.detail)"; quality='UNKNOWN' } }
    if (-not (Test-CGClaudeConnectivity)) { return [pscustomobject]@{ decision='block_hard'; reason='无法建立到 Claude 服务域名的 TCP/443 连接；请检查节点、DNS、路由或网络'; quality='UNKNOWN' } }

    $state = Read-CGState
    $cache = if ($state) { $state.gateCache } else { $null }
    $fresh = $false
    if ($cache -and $cache.at) {
        try {
            $age = ([datetimeoffset]::Now - [datetimeoffset]::Parse([string]$cache.at)).TotalMinutes
            $fresh = ($age -ge 0 -and $age -le [int]$script:Config.cacheFreshMinutes)
        } catch { $fresh = $false }
    }
    if (-not $fresh) {
        # We explicitly distinguish UNKNOWN from PASS. Unknown is fail-open by policy, not a green health verdict.
        try { Start-ScheduledTask -TaskName $script:PollTask -ErrorAction SilentlyContinue } catch {}
        return [pscustomobject]@{ decision='allow'; reason='硬性检查通过；IP 质量缓存缺失/过期，本次按 fail-open 放行，风险状态为 UNKNOWN'; quality='UNKNOWN' }
    }
    $currentExitIp = Get-CGCurrentExitIp
    if (-not $currentExitIp.ok) {
        try { Start-ScheduledTask -TaskName $script:PollTask -ErrorAction SilentlyContinue } catch {}
        return [pscustomobject]@{ decision='allow'; reason=('硬性检查通过；无法确认当前出口 IP 与缓存匹配（' + $currentExitIp.error + '），按 fail-open 放行，风险状态为 UNKNOWN'); quality='UNKNOWN' }
    }
    if (@($cache.exitIps) -notcontains [string]$currentExitIp.ip) {
        try { Start-ScheduledTask -TaskName $script:PollTask -ErrorAction SilentlyContinue } catch {}
        return [pscustomobject]@{ decision='allow'; reason=('检测到当前出口 IP 与质量缓存不匹配（当前出口 ' + $currentExitIp.ip + '）；触发重新巡检，本次按 fail-open 放行，风险状态为 UNKNOWN'); quality='UNKNOWN' }
    }
    $qualityState = [string]$cache.qualityState
    if ($qualityState -eq 'FAIL' -or [bool]$cache.softFail) {
        if (Test-CGGraceFlag -Path $script:AllowFlag -Minutes ([int]$script:Config.allowGraceMinutes)) {
            return [pscustomobject]@{ decision='allow'; reason="软规则临时放行有效：$([string]$cache.softReason)"; quality='FAIL' }
        }
        return [pscustomobject]@{ decision='block_soft'; reason=if ($cache.softReason) { [string]$cache.softReason } else { '第三方 IP 质量检查报告风险；该信号不是官方 Claude 判定' }; quality='FAIL' }
    }
    if ($qualityState -ne 'PASS') {
        return [pscustomobject]@{ decision='allow'; reason='硬性检查通过；IP 质量指标不足，风险状态为 UNKNOWN（fail-open）'; quality='UNKNOWN' }
    }
    return [pscustomobject]@{ decision='allow'; reason='硬性检查通过，IP 质量信号未触发配置阈值'; quality='PASS' }
}

function Get-CGController {
    $ports = @($script:Config.apiPorts) + @(9097,9090,9095,9091) | Select-Object -Unique
    $secret = [string]$script:Config.apiSecret
    if ([string]::IsNullOrEmpty($secret)) {
        $directories = @(
            (Join-Path $env:APPDATA 'io.github.clash-verge-rev.clash-verge-rev'),
            (Join-Path $env:APPDATA 'clash-verge'),
            (Join-Path $env:APPDATA 'clash-verge-rev')
        )
        foreach ($directory in $directories) {
            if (-not (Test-Path -LiteralPath $directory)) { continue }
            $yamlFiles = @()
            $mainYaml = Join-Path $directory 'clash-verge.yaml'
            if (Test-Path -LiteralPath $mainYaml) { $yamlFiles += $mainYaml }
            $yamlFiles += @(Get-ChildItem -LiteralPath $directory -Filter '*.yaml' -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $mainYaml } | ForEach-Object { $_.FullName })
            foreach ($yamlFile in $yamlFiles) {
                try {
                    $yaml = Get-Content -LiteralPath $yamlFile -Raw -Encoding UTF8
                    $match = [regex]::Match($yaml, '(?m)^\s*secret\s*:\s*(?:"([^"]*)"|''([^'']*)''|([^#\r\n]+))')
                    if ($match.Success) {
                        foreach ($idx in 1..3) { if ($match.Groups[$idx].Success) { $candidate = $match.Groups[$idx].Value.Trim(); if ($candidate -ne '""') { $secret = $candidate }; break } }
                    }
                    if ($secret) { break }
                } catch {}
            }
            if ($secret) { break }
        }
    }
    foreach ($port in $ports) {
        try {
            $headers = @{}
            if ($secret) { $headers.Authorization = "Bearer $secret" }
            $version = Invoke-RestMethod -Uri "http://127.0.0.1:$([int]$port)/version" -TimeoutSec 2 -Headers $headers -ErrorAction Stop
            if ($version.version) { return [pscustomobject]@{ port=[int]$port; secret=$secret } }
        } catch {}
    }
    return $null
}

function Enable-CGTunViaApi {
    $controller = Get-CGController
    if (-not $controller) { Write-CGLog '自动修复：未找到可访问的本地 Clash 内核 API。'; return $false }
    try {
        $headers = @{}
        if ($controller.secret) { $headers.Authorization = "Bearer $($controller.secret)" }
        Invoke-RestMethod -Method Patch -Uri "http://127.0.0.1:$($controller.port)/configs" -ContentType 'application/json' -Body '{"tun":{"enable":true}}' -Headers $headers -TimeoutSec 5 -ErrorAction Stop | Out-Null
        for ($i=0; $i -lt 8; $i++) {
            Start-Sleep -Seconds 1
            if (@(Get-CGTunAdapters).Count -gt 0) { Write-CGLog "自动修复：TUN 已启动（controller :$($controller.port)）。"; return $true }
        }
        Write-CGLog '自动修复：TUN 配置已下发，但网卡未在 8 秒内就绪。'
        return $false
    } catch {
        Write-CGLog "自动修复：开启 TUN 失败：$($_.Exception.Message)"
        return $false
    }
}

function Test-CGLocalProxyServer {
    param([string]$ProxyServer)
    if ([string]::IsNullOrWhiteSpace($ProxyServer)) { return $false }
    $parts = @($ProxyServer -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($parts.Count -eq 0) { return $false }
    foreach ($part in $parts) {
        $target = ($part -split '=',2)[-1].Trim()
        $target = $target -replace '^https?://',''
        if ($target -notmatch '^(?i:127\.0\.0\.1|localhost|\[::1\]|::1)(?::(\d{1,5}))?$') { return $false }
        if ($Matches[1]) {
            $portNumber = 0
            if (-not [int]::TryParse([string]$Matches[1], [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535) { return $false }
        }
    }
    return $true
}

function Test-CGRealTrafficViaTun {
    $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if (-not $curl) { return $false }
    foreach ($url in @('https://www.gstatic.com/generate_204','https://cp.cloudflare.com/generate_204')) {
        try {
            $code = & $curl.Source -4 -sS --max-time 6 --noproxy '*' -o NUL -w '%{http_code}' $url 2>$null
            if ($LASTEXITCODE -eq 0 -and "$code" -match '^(200|204)\s*$') { return $true }
        } catch {}
    }
    return $false
}

function Set-CGProxyEnable {
    param([bool]$Enabled)
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-ItemProperty -LiteralPath $reg -Name ProxyEnable -Value ([int]$Enabled) -ErrorAction Stop
    try {
        if (-not ('CG.NativeWinInet' -as [type])) {
            Add-Type -Namespace CG -Name NativeWinInet -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int length);' -ErrorAction Stop
        }
        [CG.NativeWinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
        [CG.NativeWinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
    } catch { Write-CGLog "WinINET 刷新广播失败：$($_.Exception.Message)" }
}

function Invoke-CGAutoFix {
    param([switch]$Force)
    if (Test-Path -LiteralPath $script:ProtectFlag) {
        Write-CGLog '自动修复跳过：网络保护模式已开启。'
        return [pscustomobject]@{ attempted=$false; fixed=$false; actions=@('保护模式开启：未修改网络') }
    }
    $mutex = New-Object System.Threading.Mutex($false, 'Global\ClashGuardFixMutex')
    $acquired = $false
    try { $acquired = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $acquired = $true } catch {}
    if (-not $acquired) {
        $mutex.Dispose()
        Write-CGLog '自动修复跳过：已有另一个修复流程执行。'
        return [pscustomobject]@{ attempted=$false; fixed=$false; actions=@('另一个修复流程正在执行，本次跳过') }
    }
    try {
        if (-not $Force -and (Test-Path -LiteralPath $script:CooldownFile)) {
            try {
                $last = [datetimeoffset]::Parse((Get-Content -LiteralPath $script:CooldownFile -Raw -Encoding UTF8).Trim())
                if (([datetimeoffset]::Now - $last).TotalMinutes -lt [int]$script:Config.autoFixCooldownMin) {
                    return [pscustomobject]@{ attempted=$false; fixed=$false; actions=@("自动修复冷却中（$($script:Config.autoFixCooldownMin) 分钟），本次未修改网络") }
                }
            } catch {}
        }
        [datetimeoffset]::Now.ToString('o') | Set-Content -LiteralPath $script:CooldownFile -Encoding UTF8
        $actions = @()
        $fixed = $false
        $processes = @(Get-Process -Name 'clash-verge','clash-verge-service','verge-mihomo','mihomo' -ErrorAction SilentlyContinue)
        if ($processes.Count -eq 0) {
            if ($script:Config.autoStartClash) {
                try {
                    $exe = Get-ChildItem -Path (Join-Path $env:LOCALAPPDATA 'Clash Verge*') -Filter 'clash-verge.exe' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($exe) { Start-Process -FilePath $exe.FullName; $actions += '已请求启动 Clash Verge'; $fixed = $true }
                    else { $actions += '未找到 Clash Verge 可执行文件；未更改代理设置' }
                } catch { $actions += '启动 Clash Verge 失败；未更改代理设置' }
            } else { $actions += 'Clash 未运行；未更改网络设置' }
            return [pscustomobject]@{ attempted=$true; fixed=$fixed; actions=$actions }
        }
        if (@(Get-CGTunAdapters).Count -eq 0) {
            if (Enable-CGTunViaApi) { $actions += '已启用 TUN'; $fixed = $true }
            else { $actions += 'TUN 自动启用失败；请在 Clash Verge 中手动开启' }
        }

        $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $settings = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
        $wasEnabled = ($settings -and [int]$settings.ProxyEnable -eq 1)
        $proxyServer = [string]$settings.ProxyServer
        $proxyBeforeChange = Get-CGProxyStatus
        $ipv4BeforeProxyChange = Get-CGIPv4RouteStatus
        $ipv6BeforeProxyChange = Get-CGIPv6Status
        if ($wasEnabled) {
            if (($script:Config.blockPacProxy -and $proxyBeforeChange.pacUrl) -or ($script:Config.blockAutoDetectProxy -and $proxyBeforeChange.autoDetect)) {
                $actions += '同时检测到 PAC/WPAD 设置；为避免改动代理策略，本次不关闭系统代理开关'
            } elseif ($ipv4BeforeProxyChange.state -ne 'PASS') {
                $actions += ('IPv4 默认/分流路由未验证通过；未关闭系统代理：' + $ipv4BeforeProxyChange.detail)
            } elseif ($ipv6BeforeProxyChange.leak) {
                $actions += 'IPv6 路由仍未验证通过；为避免扩大泄露风险，本次不关闭系统代理'
            } elseif (-not (Test-CGLocalProxyServer -ProxyServer $proxyServer)) {
                $actions += '发现非本地或无法确认的系统代理；为避免破坏用户设置，未自动关闭'
            } elseif (@(Get-CGTunAdapters).Count -eq 0) {
                $actions += 'TUN 未就绪；未关闭系统代理以避免断网'
            } elseif (-not (Test-CGRealTrafficViaTun)) {
                $actions += 'TUN 路径 HTTPS 验证未通过；未关闭系统代理'
            } else {
                try {
                    Set-CGProxyEnable -Enabled $false
                    Start-Sleep -Milliseconds 500
                    $ipv4AfterProxyChange = Get-CGIPv4RouteStatus
                    $ipv6AfterProxyChange = Get-CGIPv6Status
                    $postRouteVerified = ($ipv4AfterProxyChange.state -eq 'PASS' -and -not $ipv6AfterProxyChange.leak)
                    $postTrafficVerified = $false
                    if ($postRouteVerified) { $postTrafficVerified = Test-CGRealTrafficViaTun }
                    if ($postRouteVerified -and $postTrafficVerified) {
                        $actions += '已关闭本地 Clash 系统代理；IPv4/IPv6 路由复检与 HTTPS 验证均通过'
                        $fixed = $true
                    } else {
                        Set-CGProxyEnable -Enabled $true
                        if (-not $postRouteVerified) {
                            $actions += '关闭代理后路由复检未通过；已恢复修复前的代理开关状态'
                            Write-CGLog '自动修复后置路由复检失败，系统代理开关已恢复。'
                        } else {
                            $actions += '关闭代理后 HTTPS 验证失败；已恢复修复前的代理开关状态'
                            Write-CGLog '自动修复后置 HTTPS 验证失败，系统代理开关已恢复。'
                        }
                    }
                } catch {
                    try { if ($wasEnabled) { Set-CGProxyEnable -Enabled $true } } catch {}
                    $actions += "修改系统代理失败：$($_.Exception.Message)"
                }
            }
        }
        $proxyStatus = Get-CGProxyStatus
        if ($proxyStatus.pacUrl -and $script:Config.blockPacProxy) { $actions += '检测到 PAC 配置；脚本不会自动清除 PAC URL' }
        if ($proxyStatus.autoDetect -and $script:Config.blockAutoDetectProxy) { $actions += '检测到 WPAD 自动代理；脚本不会自动关闭自动检测' }
        Write-CGLog "自动修复结束：$($actions -join '；')"
        return [pscustomobject]@{ attempted=$true; fixed=$fixed; actions=$actions }
    } finally {
        try { $mutex.ReleaseMutex() | Out-Null } catch {}
        $mutex.Dispose()
    }
}

function Get-CGRecommendedActions {
    return @(
        @{ id='fix'; label='一键修复（谨慎）' },
        @{ id='openip'; label='查看 IP 风险参考' },
        @{ id='checkleaks'; label='手动泄露检查' },
        @{ id='protect'; label='切换保护模式' }
    )
}

function Get-CGIpSummary {
    param($State)
    $ips = @($State.exitIps)
    $ip = if ($ips.Count -gt 0) { $ips -join ' / ' } else { '未知' }
    $quality = if ($State.qualityState) { [string]$State.qualityState } else { 'UNKNOWN' }
    $consistency = if ($State.ipConsistency) { [string]$State.ipConsistency } else { 'UNKNOWN' }
    return "出口 IP：$ip；IPv4 一致性：$consistency；质量状态：$quality；有效 IP 来源：$($State.ipOkCount)；独立风险数据源：$($State.qualitySources)"
}

function Start-CGClaudeApp {
    # Prefer the packaged/Store app identity when available.
    try {
        $app = Get-StartApps -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Claude' -and $_.AppID -like '*!*' } | Select-Object -First 1
        if ($app) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList @('shell:AppsFolder\' + $app.AppID)
            return $true
        }
        $pkg = Get-AppxPackage -Name 'Claude*' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($pkg) {
            $manifest = Get-AppxPackageManifest -Package $pkg -ErrorAction SilentlyContinue
            $appId = $manifest.Package.Applications.Application.Id | Select-Object -First 1
            if ($appId) {
                Start-Process -FilePath 'explorer.exe' -ArgumentList @('shell:AppsFolder\' + $pkg.PackageFamilyName + '!' + $appId)
                return $true
            }
        }
    } catch { Write-CGLog "启动 Claude Store 应用失败：$($_.Exception.Message)" }

    # Fall back to the classic Win32 desktop installer. Use explicit known paths and App Paths;
    # never search all drives or launch an arbitrary executable based only on a filename match.
    $candidates = @()
    foreach ($registryPath in @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\Claude.exe',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\Claude.exe',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\Claude.exe'
    )) {
        try {
            $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
            $value = [string]$key.GetValue('')
            if ($value) { $candidates += $value }
        } catch {}
    }
    $candidates += @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Claude\Claude.exe'),
        (Join-Path $env:LOCALAPPDATA 'AnthropicClaude\Claude.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\Anthropic\Claude\Claude.exe'),
        (Join-Path $env:ProgramFiles 'Claude\Claude.exe')
    )
    if (${env:ProgramFiles(x86)}) { $candidates += (Join-Path ${env:ProgramFiles(x86)} 'Claude\Claude.exe') }
    foreach ($candidate in @($candidates | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }
        if ((Test-Path -LiteralPath $candidate -PathType Leaf) -and ([IO.Path]::GetFileName($candidate) -ieq 'Claude.exe')) {
            try { Start-Process -FilePath $candidate -ErrorAction Stop; Write-CGLog "已通过 Win32 安装路径启动 Claude：$candidate"; return $true }
            catch { Write-CGLog "尝试 Win32 Claude 路径失败：$candidate；$($_.Exception.Message)" }
        }
    }
    Write-CGLog '未能从 Store、App Paths 或常见 Win32 安装位置定位 Claude.exe。'
    return $false
}

function Stop-CGWatch {
    try { Disable-ScheduledTask -TaskName $script:WatchTask -ErrorAction SilentlyContinue | Out-Null } catch {}
    try { Stop-ScheduledTask -TaskName $script:WatchTask -ErrorAction SilentlyContinue } catch {}
    [datetimeoffset]::Now.ToString('o') | Set-Content -LiteralPath $script:StopFlag -Encoding UTF8
    Remove-Item -LiteralPath $script:WatchStopAlert -Force -ErrorAction SilentlyContinue
    $me = $PID
    try {
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                $cmdLine = [string]$_.CommandLine
                $_.ProcessId -ne $me -and $cmdLine -and
                $cmdLine.IndexOf($script:BaseDir, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                $cmdLine -match '(?i)clash_guard\.ps1"?\s+-Watch(?:\s|$)'
            } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue; Write-CGLog "已停止 Watch 进程 PID=$($_.ProcessId)" }
    } catch {}
    Write-CGLog 'Watch 守护已停止；巡检任务不受影响。'
}

function Start-CGWatch {
    Remove-Item -LiteralPath $script:StopFlag -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:WatchStopAlert -Force -ErrorAction SilentlyContinue
    try { Enable-ScheduledTask -TaskName $script:WatchTask -ErrorAction Stop | Out-Null } catch { Write-CGLog "启用 Watch 任务失败：$($_.Exception.Message)" }
    try { Start-ScheduledTask -TaskName $script:WatchTask -ErrorAction Stop; Write-CGLog '已请求恢复 Watch 守护。' } catch { Write-CGLog "启动 Watch 任务失败：$($_.Exception.Message)" }
}

function Invoke-CGWatchCare {
    try { $task = Get-ScheduledTask -TaskName $script:WatchTask -ErrorAction Stop } catch { return }
    if ($task.State -eq 'Disabled') {
        if (-not (Test-Path -LiteralPath $script:WatchStopAlert)) {
            Show-CGToast -Title 'Clash Guard · 监控已暂停' -Body 'Claude 启动事件监控当前未运行。若这是你主动执行的应急操作，请在用完后恢复监控。' -Actions @(@{id='start';label='恢复监控'})
            [datetimeoffset]::Now.ToString('o') | Set-Content -LiteralPath $script:WatchStopAlert -Encoding UTF8
        }
        return
    }
    Remove-Item -LiteralPath $script:WatchStopAlert -Force -ErrorAction SilentlyContinue
    $running = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue | Where-Object {
        $cmdLine = [string]$_.CommandLine
        $cmdLine -and $cmdLine -notmatch '(?i)-Command|-EncodedCommand' -and
        $cmdLine.IndexOf($script:BaseDir, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $cmdLine -match '(?i)clash_guard\.ps1"?\s+-Watch(?:\s|$)'
    })
    if ($running.Count -eq 0) {
        try { Start-ScheduledTask -TaskName $script:WatchTask -ErrorAction Stop; Write-CGLog '巡检发现 Watch 进程缺失，已请求自愈启动。' } catch { Write-CGLog "Watch 自愈启动失败：$($_.Exception.Message)" }
    }
}

function Invoke-CGInspect {
    $state = Get-CGStateSnapshot
    $proxy = Get-CGProxyStatus
    $violations = @()
    if (-not $state.clashOk) { $violations += 'Clash 未运行' }
    if (-not $state.tunOk) { $violations += 'TUN 未运行/未检测到' }
    if ($state.ipv4Route.state -ne 'PASS') { $violations += ('IPv4 路由验证未通过：' + $state.ipv4Route.detail) }
    if ($proxy.enabled) { $violations += 'Windows 系统代理开关开启' }
    if ($script:Config.blockPacProxy -and $proxy.pacUrl) { $violations += '存在 PAC 自动代理配置（未自动修改）' }
    if ($script:Config.blockAutoDetectProxy -and $proxy.autoDetect) { $violations += 'Windows 自动代理发现（WPAD）开启' }
    if ($state.ipv6.leak) { $violations += "IPv6 检查未通过：$($state.ipv6.detail)" }
    if ($state.softFail) { $violations += "IP 风险参考：$($state.softReason)" }
    $warnings = @()
    if ($state.qualityState -eq 'UNKNOWN') { $warnings += 'IP 质量未知（端点失败或有效风险信号不足；按 fail-open 策略，不单独触发自动修复或硬拦截）' }
    $state | Add-Member -NotePropertyName warnings -NotePropertyValue $warnings -Force
    $state | Add-Member -NotePropertyName violations -NotePropertyValue $violations -Force
    $state | Add-Member -NotePropertyName gateCache -NotePropertyValue ([pscustomobject]@{
        at = [string]$state.at
        exitIps = @($state.exitIps)
        ipOkCount = [int]$state.ipOkCount
        ipConsistency = [string]$state.ipConsistency
        qualitySources = [int]$state.qualitySources
        qualityState = [string]$state.qualityState
        softFail = [bool]$state.softFail
        softReason = [string]$state.softReason
    }) -Force
    $tcpReachable = $null
    if ($state.ipv4Route.state -eq 'PASS' -and -not $state.ipv6.leak) {
        $tcpReachable = Test-CGClaudeConnectivity
        if (-not $tcpReachable) { $violations += 'Claude 服务 TCP/443 不可达（可能是网络临时故障）' }
    } else {
        $warnings += 'IPv4/IPv6 路由未完成验证，已跳过 Claude TCP 探测，避免在未知路径下发起外部连接'
    }
    $state | Add-Member -NotePropertyName tcpReachable -NotePropertyValue $tcpReachable -Force
    $state | Add-Member -NotePropertyName warnings -NotePropertyValue $warnings -Force
    $ok = ($violations.Count -eq 0)
    $prior = Read-CGState
    $priorSignature = if ($prior -and $prior.lastSignature) { [string]$prior.lastSignature } else { '' }
    $signature = ($violations -join '|') + '#' + (@($state.exitIps) -join ',') + '#' + [string]$state.qualityState
    $same = ($signature -eq $priorSignature)
    $consecutive = 0
    $alerted = $false
    $escalated = $false
    if ($prior) { $consecutive = [int]$prior.consecBad; $alerted = [bool]$prior.alerted; $escalated = [bool]$prior.escalated }

    $repairableState = ((-not $state.clashOk) -or (-not $state.tunOk) -or [bool]$state.sysProxyOn)
    if ($script:Config.autoFix -and $repairableState -and $violations.Count -gt 0 -and -not (Test-Path -LiteralPath $script:ProtectFlag)) {
        $fix = Invoke-CGAutoFix
        $state | Add-Member -NotePropertyName autoFixActions -NotePropertyValue @($fix.actions) -Force
        if ($fix.attempted) {
            # Re-sample all gate-critical predicates after changes; never rebuild the violation list without IPv6/PAC/WPAD checks.
            $state = Get-CGStateSnapshot
            $proxy = Get-CGProxyStatus
            $violations = @()
            if (-not $state.clashOk) { $violations += 'Clash 未运行' }
            if (-not $state.tunOk) { $violations += 'TUN 未运行/未检测到' }
            if ($state.ipv4Route.state -ne 'PASS') { $violations += ('IPv4 路由复检未通过：' + $state.ipv4Route.detail) }
            if ($proxy.enabled) { $violations += 'Windows 系统代理开关开启' }
            if ($script:Config.blockPacProxy -and $proxy.pacUrl) { $violations += '存在 PAC 自动代理配置（未自动修改）' }
            if ($script:Config.blockAutoDetectProxy -and $proxy.autoDetect) { $violations += 'Windows 自动代理发现（WPAD）开启' }
            if ($state.ipv6.leak) { $violations += "IPv6 检查未通过：$($state.ipv6.detail)" }
            if ($state.softFail) { $violations += "IP 风险参考：$($state.softReason)" }
            $warnings = @()
            if ($state.qualityState -eq 'UNKNOWN') { $warnings += 'IP 质量未知（按 fail-open 策略，不单独触发自动修复或硬拦截）' }
            $tcpReachable = $null
            if ($state.ipv4Route.state -eq 'PASS' -and -not $state.ipv6.leak) {
                $tcpReachable = Test-CGClaudeConnectivity
                if (-not $tcpReachable) { $violations += 'Claude 服务 TCP/443 不可达' }
            } else {
                $warnings += 'IPv4/IPv6 路由未完成复检，已跳过 Claude TCP 探测'
            }
            $state | Add-Member -NotePropertyName warnings -NotePropertyValue $warnings -Force
            $state | Add-Member -NotePropertyName tcpReachable -NotePropertyValue $tcpReachable -Force
            $state | Add-Member -NotePropertyName autoFixActions -NotePropertyValue @($fix.actions) -Force
            $state | Add-Member -NotePropertyName gateCache -NotePropertyValue ([pscustomobject]@{
                at=[string]$state.at
                exitIps=@($state.exitIps)
                ipOkCount=[int]$state.ipOkCount
                ipConsistency=[string]$state.ipConsistency
                qualitySources=[int]$state.qualitySources
                qualityState=[string]$state.qualityState
                softFail=[bool]$state.softFail
                softReason=[string]$state.softReason
            }) -Force
        }
    }

    $signature = ($violations -join '|') + '#' + (@($state.exitIps) -join ',') + '#' + [string]$state.qualityState
    if ($signature -ne $priorSignature) { $consecutive = 1 } else { $consecutive++ }
    $isOkay = ($violations.Count -eq 0)
    $state | Add-Member -NotePropertyName violations -NotePropertyValue $violations -Force
    if (-not $state.warnings) { $state | Add-Member -NotePropertyName warnings -NotePropertyValue @() -Force }
    $state | Add-Member -NotePropertyName lastSignature -NotePropertyValue $signature -Force
    $state | Add-Member -NotePropertyName consecBad -NotePropertyValue $(if ($isOkay) { 0 } else { $consecutive }) -Force
    $state | Add-Member -NotePropertyName alerted -NotePropertyValue $(if ($isOkay) { $false } else { $alerted }) -Force
    $state | Add-Member -NotePropertyName escalated -NotePropertyValue $(if ($isOkay) { $false } else { $escalated }) -Force

    if ($isOkay) {
        if ($alerted -or $escalated) { Show-CGToast -Title 'Clash Guard · 状态已恢复' -Body (Get-CGIpSummary $state) }
        Save-CGState $state
        if (@($state.warnings).Count -gt 0) { Write-CGLog ('巡检无硬性违规，但有警告：{0}；{1}' -f (@($state.warnings) -join '；'),(Get-CGIpSummary $state)) }
        else { Write-CGLog ('巡检通过；{0}' -f (Get-CGIpSummary $state)) }
        return $state
    }
    if (-not $alerted -or ($signature -ne $priorSignature -and $priorSignature)) {
        $body = (($violations | Select-Object -First 3) -join '；') + '。' + (Get-CGIpSummary $state)
        if ($state.autoFixActions) { $body += '。修复动作：' + (@($state.autoFixActions) -join '；') }
        Show-CGToast -Title 'Clash Guard · 需要检查' -Body $body -Actions (Get-CGRecommendedActions)
        $state.alerted = $true
        Write-CGLog "告警：$($violations -join '；')"
    } elseif ($consecutive -ge [int]$script:Config.escalateAfterCycles -and -not $escalated) {
        Show-CGToast -Title 'Clash Guard · 问题仍持续' -Body "连续 $consecutive 个巡检周期仍未恢复。$($violations -join '；')" -Actions (Get-CGRecommendedActions)
        $state.escalated = $true
        Write-CGLog "升级告警：$($violations -join '；')"
    } else {
        Write-CGLog "违规仍存在（第 $consecutive 次）：$($violations -join '；')"
    }
    Save-CGState $state
    return $state
}

function Write-CGReport {
    param($State)
    Write-Host '=== Clash Guard v2.0 检查报告 ==='
    Write-Host "时间：$($State.at)"
    Write-Host ('Clash：' + $(if ($State.clashOk) {'运行中'} else {'未检测到'}))
    Write-Host ('TUN：' + $(if ($State.tunOk) {"已检测到（$($State.tunAdapter)）"} else {'未检测到'}))
    Write-Host ('系统代理开关：' + $(if ($State.sysProxyOn) {'开启'} else {'关闭'}))
    Write-Host "PAC：$(if ($State.pacUrl) {$State.pacUrl} else {'未配置'})"
    Write-Host ('WPAD：' + $(if ($State.autoDetectProxy) {'开启'} else {'关闭'}))
    Write-Host "IPv4 路由：$($State.ipv4Route.state) — $($State.ipv4Route.detail)"
    Write-Host "IPv6：$($State.ipv6.state) — $($State.ipv6.detail)"
    Write-Host "出口 IP：$(if (@($State.exitIps).Count -gt 0) {@($State.exitIps) -join ' / '} else {'未知'})"
    Write-Host "IPv4 一致性：$(if ($State.ipConsistency) {$State.ipConsistency} else {'UNKNOWN'})"
    Write-Host "IP 质量：$($State.qualityState)（有效接口 $($State.ipOkCount)，风险字段 $($State.qualitySignals)，独立风险数据源 $($State.qualitySources)）"
    Write-Host "Claude TCP：$(if ($null -eq $State.tcpReachable) {'UNKNOWN（路由未验证，已跳过）'} elseif ($State.tcpReachable) {'可达'} else {'不可达'})"
    Write-Host '接口结果：'
    foreach ($ep in @($State.endpoints)) {
        if ($ep.ok) { Write-Host ("  [OK] {0}: IP={1}, country={2}" -f $ep.name,$ep.ip,$ep.country) }
        else { Write-Host ("  [UNKNOWN] {0}: {1}" -f $ep.name,$ep.error) }
    }
    if ($State.violations -and @($State.violations).Count -gt 0) { Write-Host ('违规/阻断项：' + (@($State.violations) -join '；')) } else { Write-Host '违规/阻断项：无' }
    if ($State.warnings -and @($State.warnings).Count -gt 0) { Write-Host ('警告：' + (@($State.warnings) -join '；')) }
}

function Open-CGLeakNavigation {
    $htmlPath = Join-Path $env:TEMP 'clash_guard_leak_checks.html'
    $lines = @('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Clash Guard 手动检查</title><style>body{font:16px/1.6 system-ui,sans-serif;max-width:760px;margin:36px auto;padding:0 20px;color:#17202a}h1{font-size:26px}p{color:#5f6b7a}.group{margin:24px 0}a{display:inline-block;margin:5px 8px 5px 0;padding:9px 12px;border:1px solid #d8dee8;border-radius:9px;color:#155eef;text-decoration:none}a:hover{background:#f5f8ff}</style><h1>Clash Guard · 手动泄露检查</h1><p>这些是人工核验网站，不是自动安全判定。不同工具的测试结果可能不同，请先确认当前预期出口。</p>')
    $lastCategory = ''
    foreach ($site in @($script:Config.manualCheckSites)) {
        $category = [string]$site.cat
        $url = [string]$site.url
        if ($url -notmatch '^https://') { continue }
        if ($category -ne $lastCategory) {
            if ($lastCategory) { $lines += '</section>' }
            $lines += '<section class="group"><h2>' + [System.Net.WebUtility]::HtmlEncode($category) + '</h2>'
            $lastCategory = $category
        }
        $lines += '<a target="_blank" rel="noopener noreferrer" href="' + [System.Net.WebUtility]::HtmlEncode($url) + '">' + [System.Net.WebUtility]::HtmlEncode([string]$site.name) + '</a>'
    }
    if ($lastCategory) { $lines += '</section>' }
    $lines += '<p>该页面由本机脚本生成，不会上传检查结果。</p></html>'
    [IO.File]::WriteAllLines($htmlPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    Start-Process -FilePath $htmlPath
}

# Emergency / recovery operations run before reading config so they remain available when configuration is damaged.
if ($EmergencyAllow) {
    Set-CGGraceFlag -Path $script:EmergencyFlag
    Write-CGLog '用户启用紧急总放行。'
    Write-Host "[紧急放行] 未来 $(Get-CGEarlyGraceMinutes) 分钟跳过硬/软门控。此操作不修改代理或路由。"
    exit 0
}
if ($AllowClaude) {
    Set-CGGraceFlag -Path $script:AllowFlag
    Write-CGLog '用户启用软规则临时放行。'
    Write-Host "[软放行] 未来 $(Get-CGEarlyGraceMinutes) 分钟跳过 IP 质量软规则；TUN、代理、IPv6 与 TCP 硬规则仍生效。"
    exit 0
}
if ($Stop) { Stop-CGWatch; Write-Host 'Watch 已请求停止。'; exit 0 }
if ($Start) { Start-CGWatch; Write-Host 'Watch 已请求恢复。'; exit 0 }
if ($Protect) {
    if (Test-Path -LiteralPath $script:ProtectFlag) { Remove-Item -LiteralPath $script:ProtectFlag -Force; Write-CGLog '网络保护模式已关闭。'; Write-Host '保护模式已关闭；下一次巡检可执行自动修复。' }
    else { Set-CGGraceFlag -Path $script:ProtectFlag; Write-CGLog '网络保护模式已开启。'; Write-Host '保护模式已开启；巡检仅检测告警，不自动修改网络。' }
    exit 0
}
if ($EmergencyLaunch) {
    Set-CGGraceFlag -Path $script:EmergencyFlag
    $started = Start-CGClaudeApp
    if ($started) { Write-CGLog '紧急启动 Claude：已启用限时紧急总放行，Watch 仍保持运行。'; Write-Host "已请求启动 Claude；紧急放行有效 $((Get-CGEarlyGraceMinutes)) 分钟，Watch 没有被停用。" }
    else { Write-CGLog '紧急启动失败：未找到可启动的 Claude 应用。'; Write-Host ("未找到 Claude 应用；紧急放行仍有效 $((Get-CGEarlyGraceMinutes)) 分钟。"); exit 1 }
    exit 0
}

if (-not (Import-CGConfig)) { exit 2 }

if ($TestToast) {
    Register-CGProtocol | Out-Null
    Show-CGToast -Title 'Clash Guard · 通知测试' -Body '若能看到此通知，Toast 通道可用。请逐个测试按钮。' -Actions @(
        @{id='fix';label='一键修复（谨慎）'},
        @{id='openip';label='查看 IP 风险参考'},
        @{id='checkleaks';label='手动泄露检查'},
        @{id='protect';label='切换保护模式'}
    )
    Write-Host '已尝试发送 Toast。请确认弹窗是否出现，并逐个测试按钮。'
    exit 0
}

if ($ToastAction) {
    $action = ([string]$ToastAction).Trim().ToLowerInvariant() -replace '^clashguard:',''
    Write-CGLog "Toast 动作请求：$action"
    switch ($action) {
        'fix' {
            Register-CGProtocol | Out-Null
            $result = Invoke-CGAutoFix -Force
            Show-CGToast -Title 'Clash Guard · 修复结果' -Body (@($result.actions) -join '；')
        }
        'openip' {
            $url = [string]$script:Config.recommendedIpSite.url
            if ($url -match '^https://') { Start-Process -FilePath $url } else { Write-CGLog '推荐 IP 站点不是 HTTPS，已拒绝打开。' }
        }
        'checkleaks' { Open-CGLeakNavigation }
        'start' { Start-CGWatch }
        'protect' {
            if (Test-Path -LiteralPath $script:ProtectFlag) { Remove-Item -LiteralPath $script:ProtectFlag -Force; Show-CGToast -Title 'Clash Guard' -Body '保护模式已关闭；巡检可能自动修复网络。' }
            else { Set-CGGraceFlag -Path $script:ProtectFlag; Show-CGToast -Title 'Clash Guard' -Body '保护模式已开启；巡检不再自动修改网络。' }
        }
        default { Write-CGLog "拒绝未知 Toast 动作：$action" }
    }
    exit 0
}

if ($Launch) {
    $gate = Test-CGGate
    if ($gate.decision -ne 'allow') {
        Show-CGToast -Title 'Clash Guard · 启动被拦截' -Body "$($gate.decision)：$($gate.reason)。确认环境正确后再试；紧急情况下可使用 -EmergencyLaunch。"
        Write-CGLog "受控启动阻止：$($gate.decision)：$($gate.reason)"
        Write-Host "Claude 未启动：$($gate.reason)" -ForegroundColor Red
        exit 3
    }
    if ($gate.quality -eq 'UNKNOWN') { Write-CGLog "受控启动放行但 IP 质量 UNKNOWN：$($gate.reason)" }
    else { Write-CGLog "受控启动放行：$($gate.reason)" }
    if (Start-CGClaudeApp) { Write-Host 'Claude 启动请求已发送。'; exit 0 }
    Write-Host '未找到 Claude Desktop/Store 应用。请手动打开，或检查安装方式。' -ForegroundColor Red
    exit 4
}

if ($Watch) {
    $watchMutex = New-Object System.Threading.Mutex($false, 'Global\ClashGuardWatchSingleton')
    try { $ownsMutex = $watchMutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $ownsMutex = $true }
    if (-not $ownsMutex) { Write-CGLog '已有 Watch 实例运行，本实例退出。'; $watchMutex.Dispose(); exit 0 }
    $toastLast = @{}
    Write-CGLog 'Watch 守护启动，使用 Win32_ProcessStartTrace 事件（进程创建后响应；并非 OS 级启动前拦截）。'
    try {
        Register-CimIndicationEvent -Namespace 'root/cimv2' -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'Claude.exe'" -SourceIdentifier 'ClashGuardClaudeStart' | Out-Null
    } catch {
        Write-CGLog "无法注册 Win32_ProcessStartTrace 事件：$($_.Exception.Message)"
        try { $watchMutex.ReleaseMutex() } catch {}
        $watchMutex.Dispose()
        exit 5
    }
    Write-CGLog 'Claude 启动事件订阅已注册。'
    try {
        while ($true) {
            if (Test-Path -LiteralPath $script:StopFlag) {
                $stop = $false
                try {
                    $stamp = [datetimeoffset]::Parse((Get-Content -LiteralPath $script:StopFlag -Raw -Encoding UTF8).Trim())
                    $ageMinutes = ([datetimeoffset]::Now - $stamp).TotalMinutes
                    $stop = ($ageMinutes -ge 0 -and $ageMinutes -le 2)
                } catch {}
                Remove-Item -LiteralPath $script:StopFlag -Force -ErrorAction SilentlyContinue
                if ($stop) { Write-CGLog '收到 Watch 停止标志。'; break }
            }
            $eventRecord = Wait-Event -SourceIdentifier 'ClashGuardClaudeStart' -Timeout 2 -ErrorAction SilentlyContinue
            if ($null -eq $eventRecord) { continue }
            try {
                $newEvent = $eventRecord.SourceEventArgs.NewEvent
                $processId = [int]$newEvent.ProcessID
                if ($processId -le 0) { continue }
                try {
                    $gate = Test-CGGate
                } catch {
                    $gate = [pscustomobject]@{ decision='block_hard'; reason="门控检查异常：$($_.Exception.Message)"; quality='UNKNOWN' }
                    Write-CGLog "门控异常，按 fail-closed 处理 PID=$processId：$($_.Exception.Message)"
                }
                if ($gate.decision -eq 'allow') {
                    Write-CGLog "Claude 进程启动事件放行（PID=$processId，quality=$($gate.quality)）：$($gate.reason)"
                    continue
                }
                Write-CGLog "Claude 进程启动事件阻止（PID=$processId，$($gate.decision)）：$($gate.reason)"
                & "$env:WINDIR\System32\taskkill.exe" /PID $processId /T /F 2>&1 | Out-Null
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                $key = "$($gate.decision)|$($gate.reason)"
                $now = Get-Date
                $show = -not ($toastLast.ContainsKey($key) -and ($now - $toastLast[$key]).TotalSeconds -lt 30)
                $toastLast[$key] = $now
                if ($show) { Show-CGToast -Title 'Clash Guard · 已终止不合格的启动' -Body "$($gate.decision)：$($gate.reason)。此监听在进程创建后响应；更稳妥的方式是使用 -Launch 受控启动。" }
            } catch {
                Write-CGLog "处理 Claude 进程启动事件失败：$($_.Exception.Message)"
            } finally {
                try { Remove-Event -EventIdentifier $eventRecord.EventIdentifier -ErrorAction SilentlyContinue } catch {}
            }
        }
    } finally {
        Unregister-Event -SourceIdentifier 'ClashGuardClaudeStart' -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier 'ClashGuardClaudeStart' -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
        try { $watchMutex.ReleaseMutex() } catch {}
        $watchMutex.Dispose()
        Write-CGLog 'Watch 守护退出。'
    }
    exit 0
}

# Default: inspection. -Report explicitly disables auto-fix, scheduling repair, and notifications.
if ($Report) {
    $state = Get-CGStateSnapshot
    $tcpReachable = $null
    if ($state.ipv4Route.state -eq 'PASS' -and -not $state.ipv6.leak) { $tcpReachable = Test-CGClaudeConnectivity }
    $state | Add-Member -NotePropertyName tcpReachable -NotePropertyValue $tcpReachable -Force
    $violations = @()
    if (-not $state.clashOk) { $violations += 'Clash 未运行' }
    if (-not $state.tunOk) { $violations += 'TUN 未运行/未检测到' }
    if ($state.ipv4Route.state -ne 'PASS') { $violations += ('IPv4 路由验证未通过：' + $state.ipv4Route.detail) }
    if ($state.proxyBlocked) { $violations += 'Windows 系统代理/PAC/WPAD 配置需要检查' }
    if ($state.ipv6.leak) { $violations += "IPv6 检查未通过：$($state.ipv6.detail)" }
    if ($state.softFail) { $violations += "IP 风险参考：$($state.softReason)" }
    $warnings = @()
    if ($state.qualityState -eq 'UNKNOWN') { $warnings += 'IP 质量未知；不是安全通过结论，也不会单独触发硬拦截' }
    if ($null -eq $state.tcpReachable) { $warnings += 'IPv4/IPv6 路由未完成验证，已跳过 Claude TCP 探测' }
    elseif (-not $state.tcpReachable) { $violations += 'Claude 服务 TCP/443 不可达' }
    $state | Add-Member -NotePropertyName warnings -NotePropertyValue $warnings -Force
    $state | Add-Member -NotePropertyName violations -NotePropertyValue $violations -Force
    Write-CGReport $state
    if (@($violations).Count -gt 0) { exit 1 }
    exit 0
}

Register-CGProtocol | Out-Null
Invoke-CGWatchCare
$inspection = Invoke-CGInspect
if (@($inspection.violations).Count -gt 0) { exit 1 }
exit 0
