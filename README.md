<div align="center">

# Clash Guard 2.0
### Windows 网络环境检查与 Claude 启动守护

**先验证环境，再启动应用。检测未知就明确标未知，不把“没查到”说成“安全”。**

PowerShell 5.1 · Windows 10/11 · 无第三方 PowerShell 模块

[快速开始](#快速开始) · [功能与边界](#功能与边界) · [测试方式](#测试方式) · [安全说明](#安全说明)

</div>

---

## 这是什么？

Clash Guard 是一个面向个人 Windows 电脑的辅助检查工具：定时核对 Clash/TUN、Windows 代理设置、IPv4/IPv6 默认/分流路由、Claude 服务 TCP 可达性，并聚合几个第三方 IP 信息接口。它可以在检测到规则不满足时提醒、在有限条件下尝试自动修复，也能在 Claude 进程创建后进行响应式检查。只有在 IPv4 路由确认由 TUN 承载、且 IPv6 路由检查未发现旁路风险后，才会访问第三方 IP 信息接口，以避免在路由未知时无意查询并暴露出口 IP。

风险质量只有在至少两个独立风险数据源提供可用指标、至少两个 IP 来源都返回有效 IPv4 地址且结果一致时才可能标为 `PASS`；同一服务返回多个字段不能充当多个独立来源。缺少 IPv4 证据或来源不一致时显示 `UNKNOWN`。

它**不是 VPN、不是代理客户端，也不是 Claude 官方工具**。第三方 IP 风险分只是一种参考，不代表 Anthropic 的内部风控结论，更不保证不会封号。时区、语言、账号地区、服务政策和账号行为均不由本工具判断。

## 2.0 主要改动

- 修复自动修复后重建违规列表时遗漏 IPv6 检查的逻辑；复检会重新核对 TUN、代理、PAC/WPAD、IPv4/IPv6 路由、IP 质量与 TCP 可达性。
- 不再把任意 IPv6 地址都认定为公网泄露：区分公网全局 IPv6 与 ULA/链路本地地址，并检查活动默认/分流路由是否仍指向物理网卡。无法确认路由时按严格策略阻断并显示 `UNKNOWN` 原因。
- 启动门控会用一个基础 IP 接口确认当前出口是否仍与质量缓存匹配；切换节点/IP、缓存不匹配或无法验证时触发巡检，并按 `UNKNOWN` fail-open 处理，不把旧出口的风险评分套到新出口。
- IP 服务响应必须是可解析的 JSON，错误响应/字段缺失会标记为 `UNKNOWN`；**UNKNOWN 不等于 PASS**，也不会单独触发自动改网或硬拦截。真正检测到阈值风险才标记 `FAIL`。
- 采用 `Win32_ProcessStartTrace` 事件订阅，不再使用 `WITHIN 1` 的实例轮询查询；Watch 事件处理在主循环里完成，避免事件 Action 独立作用域的问题。
- Toast 协议动作增加白名单处理器；路径含空格时通过参数引用启动。协议注册每次更新到当前脚本目录，避免移动目录后沿用旧路径。
- `-Report` 只读检查网络状态，不自动关闭代理、不启用 TUN、不注册计划任务。
- 状态文件使用临时文件替换，降低写入中断造成 JSON 缓存损坏的概率。
- 复合代理字符串（例如 `http=127.0.0.1:7890;https=127.0.0.1:7890`）可识别；任何外部/不明代理、PAC 或 WPAD 都不会被自动清除。
- 附带任务安装/卸载脚本、静态回归检查、改写后的发布介绍和独立响应式产品介绍页。

## 快速开始

### 1. 准备

1. 确认本机已安装 Clash Verge Rev / Mihomo，并按自己的网络方案配置节点。
2. 解压整个文件夹到固定路径，例如 `D:\Tools\ClashGuard-v2`。**不要只复制主脚本**；配置与 `toast_action.vbs` 也需要同目录。
3. 使用 Windows PowerShell 5.1（系统自带）打开此目录。

### 2. 先做只读报告

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clash_guard.ps1 -Report
```

该命令不会修改代理/TUN 或注册任务，但会访问配置中的 IP 检测端点并更新本地日志。重点看 `PASS / FAIL / UNKNOWN`，不要只看最后一行。

### 3. 安装任务

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

安装脚本注册两个当前用户计划任务：

- `ClashGuard-Watch`：登录后启动进程创建事件监控。
- `ClashGuard-Inspect`：每 10 分钟巡检并按配置尝试自动修复。

如果检测到旧任务 `PersonalContext-ClashGuard*`，安装程序会询问是否停用旧任务，以避免新旧守护重复拦截。确认后只停止/禁用旧任务，不会立即删除，方便回滚；如果拒绝或无法确认，安装会中止，不会冒险叠加两套守护。

### 4. 测试通知按钮

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clash_guard.ps1 -TestToast
```

确认通知出现后，逐一测试按钮。特别留意：一键修复会尝试修改本地网络设置，不要在不了解当前代理用途时点击。

### 5. 推荐启动方式

如果希望在启动 Claude **之前**先进行一次门控检查，使用受控启动命令：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clash_guard.ps1 -Launch
```

`-Launch` 会先检查环境，通过后先尝试 Claude Store 应用，再尝试 Windows App Paths 与常见 Win32 安装目录中的 `Claude.exe`。如果仍无法定位你的安装方式，它会报告未找到应用；此时请从开始菜单手动启动，并按下面的限制说明理解 Watch 的能力。

## 常用命令

| 命令 | 用途 | 会自动改网吗 |
|---|---|---:|
| `-Report` | 生成当前状态报告 | 否 |
| 不带参数 | 执行一次巡检 | 可能，取决于 `autoFix` |
| `-Watch` | 前台运行启动事件监控 | 否 |
| `-Launch` | 检查后尝试启动 Claude | 否（但会启动应用） |
| `-AllowClaude` | 10 分钟内跳过 IP 质量软规则 | 否 |
| `-EmergencyAllow` | 10 分钟内跳过全部门控规则 | 否 |
| `-EmergencyLaunch` | 紧急放行并尝试启动 Claude，Watch 保持运行 | 否 |
| `-Protect` | 切换网络保护模式，暂停自动修复 | 否 |
| `-Stop` / `-Start` | 停止/恢复 Watch 任务 | 否 |
| `-TestToast` | 测试通知与按钮 | 否（按钮本身另论） |

紧急放行标志在 `logs` 下，超过 10 分钟自动过期。结束排障后，建议重新运行 `-Report` 确认环境状态。

## 检查判定

- **PASS**：该检查有足够有效信号，未触发配置阈值。
- **FAIL**：检测到明确违例，例如代理开关仍开、IPv6 默认路由指向物理网卡、或第三方风险信号超过阈值。
- **UNKNOWN**：接口失败、有效信号不足或路由证据不完整。默认 IP 质量策略是 fail-open：不会仅因 IP 端点全挂而永久锁住应用；但报告会显示 UNKNOWN，不能把它解读成安全通过。

### 硬性门控检查

1. 检测到 Clash/Mihomo 相关进程。
2. 检测到符合配置匹配式的已启动 TUN 网卡。
3. IPv4 默认/分流路由的有效最低 metric 路由指向 TUN；如果路由证据不完整或同优先级路线包含非 TUN，则阻断。
4. Windows 系统代理关闭；按默认配置，PAC URL 或 WPAD 自动发现开启也会阻断，但脚本不会自动清除它们。
5. 若物理网卡存在公网全局 IPv6 地址，则检查活动 IPv6 默认/分流路由；物理网卡仍承载相应路由，或路由证据不完整时阻断。
6. 能建立到配置中的 Claude 服务域名 TCP 443 连接。

TCP 可达只说明连接能够建立，不代表 Claude 账号可用、地区符合服务条款、出口 IP 一定是住宅 IP，也不代表已获得服务商认可。

**重要限制：** Windows 路由检查只能说明系统路由把 IPv4/IPv6 流量送入 TUN，不能证明 Mihomo 对每个检测域名最终选择了代理节点；Clash 规则仍可能对某个域名使用 `DIRECT`。第三方 IP 查询站点会看到它们实际收到请求时的出口地址。若你要验证是否使用预期节点，建议在 `expectedIPv4` 中配置已知的预期 IPv4，并手动确认 Clash 对相关域名的规则；留空时，本工具只能报告观测到的 IPv4 与风险信号，不能证明出口符合你的预期。请只向你信任的第三方服务发送 IP 查询。

## 配置

编辑同目录的 `clash_guard_config.json`：首次安装时 `autoFix` 默认是 `false`，建议先按回归测试计划验证状态判断；确认本机环境与预期一致后，再把它改为 `true` 启用有边界的自动修复。

- `autoFix`：巡检发现可修复的硬性违规时是否尝试自动修复。新安装默认 `false`，先完成回归测试；确认你的 Clash/TUN/代理环境后，再手动改为 `true` 启用周期自动修复。通知里的“一键修复”属于明确点击触发的手动操作。
- `blockPacProxy` / `blockAutoDetectProxy`：是否将 PAC/WPAD 配置视为系统代理违规。默认均为 `true`。
- `tunAdapterPattern`：用于识别 TUN 网卡的正则表达式。不同 Clash/Mihomo 版本可能需要调整。
- `expectedIPv4`：可选的期望 IPv4 出口。留空表示不强制固定出口；配置后，如果有效 IPv4 来源均未返回该地址会标记风险不符；没有有效 IPv4 结果或来源不一致时标记 UNKNOWN。
- `clash_guard_config.local.json`：可选的本机覆盖配置，优先级高于主配置；适合放 `apiSecret`、`expectedIPv4` 等机器特有值。该文件已加入 `.gitignore`。覆盖数组（如 `ipEndpoints`）会替换整个数组；主配置和本地配置都会经过相同校验。
- `fraudScoreMax` / `claudeScoreMax`：第三方接口返回的风险参考阈值，分数定义由数据提供方决定。
- `apiSecret`：Clash 内核 API secret。留空时脚本尝试从 Clash Verge Rev 配置文件读取。不要把真实 secret 上传到公开仓库。
- `ipEndpoints`：必须为 HTTPS。错误 JSON、服务超时、字段缺失会导致该端点为 UNKNOWN。

不要为了“通过检查”而随意关闭代理、删除 PAC 或改路由；先判断当前网络方案和这些设置的作用。

## 本地日志与状态

- `logs/clash_guard.log`：日志，超过 2 MB 时保留一份 `.1`。
- `logs/clash_guard_state.json`：最近巡检状态与启动门控使用的质量缓存。
- `logs/clash_guard_fix.cooldown`：自动修复冷却时间。
- `logs/clash_guard_allow.flag` / `clash_guard_emergency.flag`：临时放行时间戳。

日志会记录外显出口 IP 和检测状态。分享日志前请检查是否含有不想公开的 IP、网络信息或本机路径。

## 测试方式

1. 执行 `python -m unittest discover -s tests -v`：检查配置、发布文件和关键代码回归约束（不需要第三方 Python 包）。
2. 执行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-WindowsSmokeTests.ps1`：验证本机 PowerShell 版本、JSON 配置、协议处理器文件和只读报告入口。
3. 执行 `-Report`，确认 TUN、代理、IPv6 路由、出口 IP 和 TCP 结果符合预期。
4. 执行 `-TestToast`，测试所有通知按钮，包括目录带空格时。
5. 在备份当前配置后，按 `docs/REGRESSION_TEST_PLAN.md` 的故障注入步骤测试代理、TUN、IPv6、接口超时、紧急放行与恢复。
6. 测完后重新执行 `-Report`，并查看日志确认没有仍在运行的旧 Watch 进程。

静态测试通过不等于已在你的具体 Clash Verge、节点、Windows 版本和 Store Claude 安装上完成实机验证。该压缩包由开发容器生成，不能代替 Windows PowerShell 5.1 实测。

## 安全说明

- 此项目是个人辅助防错工具，不保证匿名、不保证绕过任何服务商限制，也不提供封号规避承诺。
- 自动修复会通过本机 Clash API 尝试启用 TUN，并且只在确认 `ProxyServer` 全部为本机地址、TUN 已就绪、HTTPS 验证成功时关闭系统代理。对外部代理、PAC 和 WPAD 不自动更改。
- Watch 默认监听 `Claude.exe`，通过进程创建事件工作，属于**进程创建后的响应式终止**，不是 Windows 内核级的启动前封锁。任何事件守护都存在启动竞态；希望严格控制启动入口时应使用 `-Launch` 并把快捷方式指向受控启动器，或采用 Windows 应用控制策略。
- “住宅 IP”“Claude 风险分”等指标来自第三方服务，可能过期、变化、错误或不可用。未知状态与通过状态分开显示。
- Toast 按钮协议仅接受固定动作白名单，不接受任意命令。

## 卸载

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\uninstall.ps1
```

卸载脚本只移除本版本注册的计划任务，并仅在协议命令确实指向当前目录时删除 `clashguard:` 注册。代码、配置和日志会保留，便于检查和回滚。
