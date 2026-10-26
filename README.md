# Clash 护卫 · 节点出口检测与 Claude 启动门控系统

> **一句话**：每 10 分钟静默巡检 Clash 出口环境；**并在 Claude.exe 启动时按硬/软规则拦截**——硬规则不满足直接杀进程，软规则（IP 质量）需用户手动放行。
> 零第三方依赖（纯 PowerShell 5.1 + Windows Runtime Toast），单文件主程序。

---

## 一、系统定位

| 对比 | 说明 |
|---|---|
| 不是什么 | 不是 Clash 配置管理器、不是代理客户端、不是 VPN |
| 是什么 | **安全护栏**——保护使用 Claude 等有封禁风险 AI 的出口环境不被污染 |
| 核心防护 | ① 守护 TUN 模式生效 + 系统代理关闭的黄金状态 ② 拦截 IPv6 泄露真实位置 ③ 验证 TCP 直连 Claude 真实服务可达 ④ 检测出口 IP 质量（欺诈分/住宅/Claude 风险分） |

**风险背景**：Claude 对中国用户的账号封禁逻辑包含出口 IP 质量评分、系统代理特征、时区语言指纹等维度。一旦被识别，轻则降智（弱模型）重则封号。本系统在 AI 客户端启动前和运行中持续维护出口环境的纯净性。

---

## 二、文件清单

```
Clash护卫_节点检测系统/
├── README.md                    ← 本说明
├── clash_guard.ps1              ← 主程序（850 行，单文件 PowerShell 5.1）
├── clash_guard_config.json      ← 配置文件（端点/阈值/开关）
├── proxy_health_check.ps1       ← 辅助检测脚本
├── run_hidden.vbs               ← 静默启动器（所有计划任务引用）
│
│  ── 运行时自动生成，本包不包含 ──
│
├── logs/clash_guard.log         ← 运行日志
├── logs/clash_guard_state.json  ← 状态文件（gateCache IP质量缓存）
└── scripts/backup/              ← 历史版本备份
```

---

## 三、运行模式

主程序 `clash_guard.ps1` 是单脚本，通过参数切换运行模式：

| 模式 | 参数 | 触发方式 | 说明 |
|---|---|---|---|
| **巡检**（默认） | `-Run` | 计划任务每 10 分钟 | 检查 Clash 进程/TUN/系统代理/IPv6/IP 质量；违规自动修复（可配）+ Toast 通知 |
| **启动门控** | `-Watch` | 计划任务登录时 | **事件驱动**监听 Claude.exe 启动（CIM WMI Event，非轮询），按硬/软规则毫秒级拦截 |
| **手动报告** | `-Report` | 命令行 | 只读检查，输出当前出口环境完整状态 |
| **应急放行** | `-AllowClaude` | 命令行/桌面 bat | 10 分钟内只跳过软规则（IP质量），硬规则仍强制 |
| **紧急总放行** | `-EmergencyAllow` | 命令行/桌面 bat | 10 分钟内所有规则放行 |
| **逃生门** | `-EmergencyLaunch` | 桌面 bat | 彻底停用守护+启动 Claude |
| **恢复保护** | `-Start` | 命令行/桌面 bat | 重新启用守护任务 |
| **停止拦截** | `-Stop` | 命令行 | 只停 Watch 拦截，不影响巡检 |
| **网络保护模式** | `-Protect` | 命令行/Toast 按钮 | 只检测告警，暂停自动修复（门控拦截不受影响） |
| **Toast 测试** | `-TestToast` | 命令行 | 验证 Toast 通道 |

---

## 四、Claude 启动门控（核心防护）

在 Claude.exe 启动瞬间判定，不满足硬规则直接杀进程树 + Toast 阻止启动。

### 4.1 硬规则（不满足 → 强制阻止）

| # | 条件 | 检测方式 |
|---|---|---|
| 1 | TUN 虚拟网卡生效 | `Get-NetAdapter` Meta Tunnel / Wintun Status=Up |
| 2 | 系统代理关闭 | 注册表 `HKCU\...\Internet Settings\ProxyEnable=0` |
| 2.5 | 物理网卡无全局 IPv6（防泄露真实位置） | `Get-NetIPAddress -AddressFamily IPv6` |
| 3 | **TCP 直连 api.anthropic.com:443 / claude.ai:443 可达（3秒超时）** | `Test-NetConnection` |

**关键设计**：硬规则 3 **不依赖任何第三方 IP 检测站点或缓存**——直接 TCP 握手 Claude 真实服务。换节点/IP 变动后立即反映真实状态，不存在"缓存陈旧锁死 10 分钟"问题。两轮重试（隔 2 秒）防瞬时抖动误杀。

### 4.2 软规则（不满足 → 阻止但可放行）

| 条件 | 来源 |
|---|---|
| fraudScore ≤ 50 | ippure.com |
| 住宅 IP | ippure.com `isResidential` |
| Claude 风险分 ≤ 50 | fuck-claude.vercel.app |
| 非机房 IP | ipquery.io `is_datacenter` |

**fail-open 设计**：`gateCache` 缓存缺失/过期（>30 分钟）**不阻断启动**，只异步踢一次巡检刷新。IP 站点全挂也不影响打开 Claude。

### 4.3 杀进程

`taskkill /T /F` — Electron 进程树全部杀死。Mutex 单实例防多守护，Toast 30 秒去重防轰炸。

---

## 五、自动修复

巡检发现违规时**自动修复**（可配 `autoFix: true`），按安全顺序：

```
步骤 1：经 Clash 内核 API PATCH 开 TUN
        PATCH http://127.0.0.1:9097/configs
        body: {"tun":{"enable":true}}
        secret 自动读 clash-verge.yaml

步骤 2：TUN 就绪后，HTTPS 真实流量验证
        curl --noproxy '*' https://www.gstatic.com/generate_204
        （走 TUN 路径，两候选端点任一通即可）

步骤 3：关闭 127.0.0.1 本地系统代理
        只碰 ProxyEnable，外部代理绝不碰
        广播 WinINET 刷新让 Chrome 平滑感知

步骤 4：关代理后再验证 HTTPS
        失败则自动恢复原代理状态 + WinINET 广播
```

### 5.1 安全护栏

- **全局修复锁**：命名 Mutex `Global\ClashGuardFixMutex`，巡检与一键修复并发时只有一个执行
- **10 分钟冷却**：不反复切换折腾浏览器/网络
- **TUN 开启失败就不动代理**：只弹窗报警
- **日志不含 API secret**：只记修复前后状态（代理 on本地/on外部/off、TUN up/down）
- **TCP 直连两轮重试**：硬规则 3 隔 2 秒重试一轮

### 5.2 守护自愈（V2.1 新增）

每 10 分钟巡检顺带检查拦截守护进程——任务启用但进程不在（崩溃/被杀）则自动拉起。Mutex 保证不会重复。停止标志改为 2 分钟过期（防陈旧标志误杀新守护）。

---

## 六、IP 质量检测端点

配置文件 `clash_guard_config.json` 中的 `ipEndpoints` 数组，当前内置 7 个：

| 端点 | 用途 |
|---|---|
| `api.ip.sb/geoip` | IP/国家/ASN 基础信息 |
| `ipinfo.io/json` | IP/ASN/org |
| `api.ipquery.io` | **risk_score + is_vpn/is_proxy/is_tor/is_datacenter** |
| `ipwho.is` | 备用 |
| `my.ippure.com/v1/info` | **fraudScore + isResidential**（住宅 IP 是 AI 服务最友好的出口） |
| `fuck-claude.vercel.app/api/check` | **Claude 中国用户风险评分**：score + band + verdict |
| `ipleak.net/json` | 冗余后端 |

**PS5 兼容性**：部分站点 TLS 握手失败时自动降级 `curl.exe`。

---

## 七、Toast 通知（Windows Runtime）

用 `Windows.UI.Notifications.ToastNotificationManager` + ToastGeneric 模板，内嵌 PowerShell 调起：
- 标题："Clash 护卫 · 状态"
- 正文：IP 质量摘要（出口 IP · 欺诈分 · 住宅/Claude 风险分）
- **带按钮**（注册 `clashguard:` 协议处理器到 `HKCU\Software\Classes\`）：
  - 「一键修复」→ `clashguard:fix` 强制立即修复
  - 「查IP质量」→ `clashguard:check` 打开 fuck-claude.vercel.app
  - 「暂停自动修复」→ `clashguard:protect` 保护模式开关

**严格去重**：状态签名不变不弹，连续 3 周期未处理才再提醒，恢复时 Toast 一次。

---

## 八、三级应急通道

| 级别 | 操作 | 效果 |
|---|---|---|
| 1 软放行 | `-AllowClaude` / 桌面「Claude 软放行.bat」 | 10 分钟内跳过软规则（硬规则仍强制） |
| 2 紧急总放行 | `-EmergencyAllow` | 10 分钟内所有规则放行 |
| 3 逃生门 | 双击桌面「Claude紧急启动.bat」 | 彻底停用守护 + 启动 Claude |
| 恢复保护 | 双击桌面「恢复Clash护卫.bat」/ `-Start` | 重新启用守护 |

### 关键注意：桌面 bat 编码

必须是 **UTF-8 无 BOM + CRLF + 首行 `chcp 65001 >nul`**。本机已开 Windows「UTF-8 Beta」（ACP/OEM=65001），旧 GBK+LF 会被 cmd 拆词（`powershell`→`wershell`）导致双击无效。

### 彻底卸载

```powershell
Unregister-ScheduledTask -TaskName 'PersonalContext-ClashGuard-Watch','PersonalContext-ClashGuard' -Confirm:$false
```

---

## 九、计划任务配置

| 任务 | 触发器 | 操作 |
|---|---|---|
| `PersonalContext-ClashGuard` | 每 10 分钟 | `wscript.exe run_hidden.vbs "powershell -NoProfile -ExecutionPolicy Bypass -File clash_guard.ps1 -Run"` |
| `PersonalContext-ClashGuard-Watch` | 登录时（AtLogOn） | `wscript.exe run_hidden.vbs "powershell -NoProfile -ExecutionPolicy Bypass -File clash_guard.ps1 -Watch"` |

**为什么用 `run_hidden.vbs`**：`powershell -File` 直接经 `schtasks` 启动会闪一个黑色控制台窗口干扰用户。`wscript run_hidden.vbs "command"` 用 `WScript.Shell.Run cmd, 0, False` 完全隐藏启动。

---

## 十、运行时路径硬编码

脚本中默认路径（从 `clash_guard_config.json` 同级目录推断）：

```
logs/clash_guard.log
logs/clash_guard_state.json    # 含 gateCache IP 质量缓存
logs/clash_guard_protect.flag  # 保护模式标记
```

迁移到新机器时：脚本和配置放同一目录即可，自动按脚本所在目录定位日志目录。

---

## 十一、配置文件字段

```jsonc
{
  "ipEndpoints": [ /* 7 个 IP 检测端点 */ ],
  "httpTimeoutSec": 12,           // HTTP 请求超时
  "escalateAfterCycles": 3,        // 多少周期未处理升级提醒
  "fraudScoreMax": 50,             // 欺诈分阈值
  "claudeScoreMax": 50,            // Claude 风险分阈值
  "allowGraceMinutes": 10,         // 放行持续时间
  "cacheFreshMinutes": 30,         // gateCache 新鲜度
  "reachableHosts": [ "api.anthropic.com:443", "claude.ai:443" ],  // TCP 可达目标
  "autoFix": true,                 // 自动修复开关
  "autoFixCooldownMin": 10,        // 自动修复冷却
  "autoStartClash": false,         // Clash 没开时是否自动拉起
  "apiPorts": [ 9097, 9090 ],      // Clash 内核 API 端口（自动探测）
  "apiSecret": "",                 // Clash API secret（留空自动读 clash-verge.yaml）
  "recommendedIpSite": { ... },    // Toast 里推荐的 IP 质量检测站
  "manualCheckSites": [ ... ]      // 手动泄露检测站点（Toast 按钮一键打开）
}
```

---

## 十二、关键技术点

| 技术点 | 实现方式 |
|---|---|
| Clash 进程检测 | `Get-Process clash-verge, clash-verge-service, verge-mihomo` |
| TUN 网卡状态 | `Get-NetAdapter` 匹配 Meta Tunnel/Wintun，Status=Up |
| 系统代理读取 | 注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyEnable` |
| IPv6 泄露检测 | `Get-NetIPAddress -AddressFamily IPv6` 过滤物理网卡 |
| TCP 直连检测 | `Test-NetConnection`（3 秒超时，两轮重试） |
| Clash 内核 API | `Invoke-RestMethod` PATCH 9097 端口，secret 从 `clash-verge.yaml` 正则提取 |
| Claude 启动监听 | `Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='Claude.exe'"`（事件驱动，非轮询） |
| 单实例互斥 | `New-Object System.Threading.Mutex($false, 'Global\ClashGuardFixMutex')` |
| WinINET 刷新 | `wininet.dll InternetSetOption` 广播刷新让 Chrome 感知代理变化 |
| Toast 通知 | Windows Runtime `ToastNotificationManager`（内嵌 PowerShell，CREATE_NO_WINDOW 防闪窗） |
| 静默启动 | `wscript run_hidden.vbs "command"` 或 `powershell -WindowStyle Hidden` |
| 并发安全 | Watcher 单实例 Mutex + 修复流程全局 Mutex + 状态文件原子写 |

---

## 十三、边界与坑

1. **只碰本地系统代理**（127.0.0.1），外部代理绝不碰——不与用户手动配置打架
2. **TUN 开启时 IP 检测走代理出口**——测的就是 AI 服务看到的那个 IP
3. `ensure_system_proxy.ps1`（旧脚本，确保代理开启）与本程序目标相反，已无计划任务挂载，勿启用
4. API 开 TUN 是内核级，Clash 界面开关可能仍显示关——重启 Clash 后若复发请在界面手动打开
5. Toast 协议处理器 `clashguard:` 注册在 `HKCU\Software\Classes\`，首次安装需确认注册成功
6. V1 备份在 `scripts\backup\clash_guard_v1_20261015.ps1`，出问题可回滚

---

## 十四、迁移到新机器

```powershell
# 1. 确认 Clash Verge 已安装并配置好（TUN 模式）
# 2. 把本目录下所有文件放到一个固定目录（如 D:\Tools\clash_guard\）
# 3. 确认 clash-verge.yaml 里的 mixed-port 和 secret（脚本会自动探测）
# 4. 注册两个计划任务（XML 方式最稳）
# 5. 测试：
powershell -File clash_guard.ps1 -TestToast      # Toast 通道
powershell -File clash_guard.ps1 -Report         # 出口环境状态
powershell -File clash_guard.ps1 -Run            # 巡检一次（自动修复）
# 6. 打开 Claude.exe 测试门控
# 7. 制造违规（手动开系统代理），验证自动修复链路
```
