# Clash Guard v2.0 回归测试计划

> 本计划用于本机 Windows 10/11 + Windows PowerShell 5.1 + Clash Verge Rev/Mihomo。所有破坏性测试均应先备份当前配置，并在你能自行恢复网络的前提下进行。

## 0. 测试安全准备

1. 先保存 `clash_guard_config.json`、当前 Clash 配置、当前 `ProxyEnable` / `ProxyServer` / `AutoConfigURL` / `AutoDetect` 的值。
2. 确认你知道如何通过 Clash Verge UI 恢复 TUN、如何从开始菜单启动 Claude、如何使用 `-EmergencyAllow` 和 `-Stop`。
3. 新版本默认 `autoFix=false`。先验证判断逻辑；只有报告准确且你明确决定要自动改网时，再设为 `true` 测试自动修复。
4. 不要在重要会议、在线考试、远程控制或需要稳定网络时故意断网测试。

## 1. 基础测试

| ID | 操作 | 预期结果 | 通过标准 |
|---|---|---|---|
| B-01 | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clash_guard.ps1 -Report` | 输出环境摘要、端点结果和 PASS/FAIL/UNKNOWN | 命令无未处理异常；UNKNOWN 明确展示 |
| B-02 | 打开 `clash_guard_config.json` | JSON 可解析，所有端点为 HTTPS | `ConvertFrom-Json` 成功 |
| B-03 | `-TestToast` | 出现测试通知 | 通知显示成功；按钮可逐个测试 |
| B-04 | 把项目放入含空格路径，例如 `D:\Tools\Clash Guard v2` | 报告和 Toast 按钮仍可运行 | 日志写入当前目录的 `logs`，按钮无命令行错误 |
| B-05 | 连续启动两个 `-Watch` | 第二个实例记录“已有实例运行”后退出 | 不出现重复 Watch |
| B-06 | 查看任务计划程序 | 可见 `ClashGuard-Watch` 与 `ClashGuard-Inspect` | 登录触发器与巡检间隔符合说明 |

## 2. IPv4 路由与 IP 查询隐私测试

| ID | 模拟状态 | 预期结果 |
|---|---|---|
| V4-01 | TUN 未检测到 | IPv4 路由 `UNKNOWN`；不请求任何第三方 IP 查询端点 |
| V4-02 | 有 TUN，但有效默认路由仍指向物理网卡 | 路由 `FAIL`，门控阻断，不请求第三方 IP 查询端点 |
| V4-03 | IPv4 默认/分流路由使用 `0.0.0.0/1` 与 `128.0.0.0/1`，两个有效最低 metric 路由均指向 TUN | 路由 `PASS`；其他硬检查通过后允许查询 IP 端点 |
| V4-04 | 同一目标有相同最低 metric 的 TUN 与非 TUN 路由 | 不可判为通过；路由检查阻断并显示原因 |
| V4-05 | 默认/分流路由缺一条或无法读取路由表 | `UNKNOWN`，不访问第三方 IP 查询端点 |

## 2.1 Clash 规则与预期出口测试

Windows 路由进入 TUN 不代表 Mihomo 对每个目的域名都使用代理节点；对应规则可能为 `DIRECT`。请在 Clash 中确认 IP 检测域名的命中规则，并执行以下测试：

| ID | 操作 | 预期结果 |
|---|---|---|
| ROUTE-01 | 配置 `expectedIPv4` 为已知预期出口，再执行 `-Report` | 结果与预期出口一致时不触发地址不符；不一致应标记风险不符或 UNKNOWN，不能假称符合预期 |
| ROUTE-02 | 将某一 IP 检测域名临时规则设为 `DIRECT`（仅在你理解风险且能恢复规则时测试） | 应能观察到该服务实际看到的出口变化；不能仅因为系统路由走 TUN 就宣称预期代理出口已验证 |
| ROUTE-03 | `expectedIPv4` 留空 | 报告只表示观测到的出口与风险信号，不得描述为“已验证使用预期节点” |

注意：IP 检测站点会收到其请求所经过的实际公网出口地址。若不希望把网络出口信息发送给第三方，请勿执行 IP 查询模式。

## 3. IPv6 逻辑测试

| ID | 模拟状态 | 预期结果 |
|---|---|---|
| V6-01 | 物理网卡只有 `fe80::/10` 链路本地地址 | 不判定为公网 IPv6 泄露 |
| V6-02 | 物理网卡只有 `fc00::/7` ULA 地址 | 不判定为公网 IPv6 泄露 |
| V6-03 | 物理网卡有公网全局 IPv6，`::/0` 由物理网卡承载 | `FAIL`，说明物理默认路由风险并阻止门控 |
| V6-04 | 有公网全局 IPv6，`::/1` 与 `8000::/1` 均由 TUN 承载 | 不因“地址存在”单独判定泄露 |
| V6-05 | 有公网全局 IPv6，但路由信息不完整 | `UNKNOWN` 路由详情，同时严格策略阻止启动 |
| V6-06 | 第一次巡检检测到 IPv6 违规，触发自动修复，复检后仍未改变 IPv6 路由 | 复检后的违规列表依旧包含 IPv6 问题，不得报告完全正常 |

如果你的 Clash 版本使用非标准 TUN 名称，先配置 `tunAdapterPattern`，再重复 V6 测试。不要把改变接口名称当作泄露检测通过。

## 4. 系统代理测试

| ID | 状态 | 预期结果 |
|---|---|---|
| PX-01 | `ProxyEnable=0` 且没有 PAC/WPAD | 不报告系统代理开关违规 |
| PX-02 | `ProxyEnable=1`，`ProxyServer=127.0.0.1:7897` | 报告代理开启；自动修复仅在 TUN 与真实 HTTPS 测试通过后关闭 |
| PX-03 | `ProxyServer=http=127.0.0.1:7890;https=127.0.0.1:7890` | 识别为全本地代理，不应误判为外部代理 |
| PX-04 | `ProxyServer=192.0.2.10:8080` | 不自动更改外部代理；明确记录保守跳过 |
| PX-05 | `AutoConfigURL` 非空 | 默认硬门控阻止；不删除 PAC URL |
| PX-06 | `AutoDetect=1` | 默认硬门控阻止；不自动修改 WPAD 设置 |
| PX-07 | TUN 未启动 | 自动修复不应在确认 TUN 成功前关闭系统代理 |
| PX-08 | TUN 已启动但 `curl --noproxy '*'` 无法通过两候选 HTTPS 端点 | 不关闭系统代理 |
| PX-09 | 关闭本地代理后 HTTPS 复验失败 | 恢复原 `ProxyEnable` 状态并记录日志 |

## 5. IP 端点与风险状态测试

| ID | 模拟状态 | 预期结果 |
|---|---|---|
| IP-01 | 端点返回正确 JSON 且风险字段正常 | 有足够有效风险信号时为 `PASS` |
| IP-02 | 端点超时、DNS 失败或返回非 JSON | 此端点为 `UNKNOWN`，其失败不能变成风险分 0 |
| IP-03 | 服务返回合法 JSON，但字段名变更/风险字段缺失 | 总体状态不足时为 `UNKNOWN`，不得隐式 `PASS` |
| IP-04 | `ippure` 明确返回超过阈值的 fraudScore | `FAIL`，软规则可被 `-AllowClaude` 临时绕过 |
| IP-05 | Claude 风险参考端点超阈值 | `FAIL`，提醒这是第三方参考，不是官方封禁判断 |
| IP-06 | 所有 IP 端点不可用 | `UNKNOWN`；按 fail-open 策略不只因这些端点故障而锁死 Claude；不自动改网 |
| IP-07 | 配置 `expectedIPv4`，接口报告的 IPv4 与期望地址不同 | `FAIL` 或无有效 IPv4 时 `UNKNOWN` |
| IP-08 | 所有端点状态未知但其他硬检查通过 | 不能在报告里标“IP 质量 PASS”，Watch 可按既定 fail-open 规则放行并记录 UNKNOWN |
| IP-09 | 切换 Clash 节点后，实时出口 IP 与 30 分钟内的质量缓存不同 | 不得把旧节点风险分用于新节点；触发巡检并将本次风险状态标为 `UNKNOWN` |
| IP-10 | 当前出口 IP 确认接口故障，但缓存时间仍新鲜 | 按 fail-open 规则标记 `UNKNOWN`，不把旧缓存当成已确认的当前出口 |

## 6. 启动与恢复

| ID | 操作 | 预期结果 |
|---|---|---|
| LA-01 | 使用 `-Launch`，硬规则全部通过 | 调用系统应用启动入口；若找不到 Store/Desktop 安装则报告未找到，而非假称启动成功 |
| LA-02 | 使用 `-Launch`，TUN 关闭 | 启动前返回失败，不启动 Claude |
| LA-03 | Watch 正常运行，手动启动 Claude，硬规则不通过 | Win32_ProcessStartTrace 事件被处理，尝试终止新建进程，并记录 PID/原因 |
| LA-04 | Watch 正常运行，IP 状态 UNKNOWN 而硬规则通过 | 按 fail-open 放行，日志与提示中保留 UNKNOWN |
| LA-05 | `-AllowClaude` | 10 分钟内跳过软规则，硬规则仍生效 |
| LA-06 | `-EmergencyAllow` | 10 分钟内跳过全部门控；不修改代理、路由或 TUN |
| LA-07 | `-EmergencyLaunch` | 启用 10 分钟总放行后尝试启动 Claude；不关闭 Watch 任务 |
| LA-08 | `-Stop` 后检查任务 | Watch 停止/禁用；巡检任务仍保留 |
| LA-09 | `-Start` | 清除停止标志并请求恢复 Watch |
| LA-10 | 开启 `-Protect` 后执行巡检 | 不触发自动修复；仍记录检查状态 |
| LA-11 | 配置损坏后运行 `-EmergencyAllow` 或 `-Stop` | 恢复命令依然可用；常规模式明确报配置错误 |

## 7. 自动修复并发与持久化

1. 同时从计划任务与 Toast 点击“一键修复”，确认全局互斥锁让其中一个操作跳过。
2. 在日志状态文件写入附近重启脚本，确认 JSON 缓存可恢复或明确被忽略，不应导致门控未捕获异常。
3. 观察修复冷却时间：默认 10 分钟内重复巡检不反复重置网络；Toast 的 `-Force` 按钮动作可有意绕过冷却，但仍受保护模式约束。
4. 检查日志不包含 Clash API secret。
5. 检查程序所在目录无权限写入时，日志/缓存写入失败应可见，不应错误显示“检查通过”。

## 8. 完成验收

必须全部满足：

- 所有静态 Python 测试通过。
- Windows PowerShell 5.1 能解析并执行 `-Report`、`-TestToast` 和 `-Watch`。
- V6-06 确认复检没有遗漏 IPv6。
- PX-02/PX-04/PX-05/PX-06 验证脚本只修改允许范围的代理设置。
- IP-02/IP-03/IP-06 验证 UNKNOWN 不会冒充 PASS，也不会仅因此改网。
- LA-02/LA-03/LA-06 验证受控启动、响应式 Watch 和紧急放行各自符合文档。
- 日志路径、任务名、卸载行为与文档一致。

此表的预期结果是验收标准，并不表示这些步骤已在用户电脑上执行过。
