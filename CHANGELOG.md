# 更新记录

## v2.0.0 — 2026-10-26

- 修复自动修复后复检遗漏 IPv6 状态、PAC/WPAD 等 gate-critical 状态的问题。
- IPv6 判断过滤 ULA/链路本地/多播地址；使用活动默认/分流路由判断潜在物理出口，不再仅凭“物理网卡有任意 IPv6 地址”就下结论。
- 将第三方 IP 质量结果分为 PASS / FAIL / UNKNOWN，接口超时/结构变化不再隐式视为安全通过；UNKNOWN 按已声明的 fail-open 策略处理且不触发自动改网。
- 使用 Win32_ProcessStartTrace，并把事件处理放到 Watch 主循环中以避免 Action 的上下文歧义。
- 为通知 URI 引入独立白名单处理器，修复旧注册路径可能滞留、路径空格引用与任意动作透传风险。
- 为状态 JSON 写入增加临时文件替换；增强本地复合代理字符串识别；对非本地代理/PAC/WPAD 坚持不自动修改。
- 新增受控 `-Launch`、计划任务安装/卸载脚本、静态/Windows 冒烟测试、回归计划、发布文案和响应式介绍页面。
- 重写 README，删除未经证实的“零 CPU、毫秒级启动前拦截、Claude 风险评分等于官方风控”等暗示。

### 验证范围

在开发容器中执行了文件完整性、JSON、HTML、链接/参数、脚本关键不变量和打包测试。当前环境不包含 Windows PowerShell 5.1、Clash Verge/Mihomo、Windows Toast 运行时或 Claude Store 应用，因此本版本仍需按测试计划在目标 Windows 主机进行实机回归；不能宣称已达到零 Bug。
- IP 查询与 TUN 流量探测显式强制 IPv4；只允许至少两个有效 IPv4 来源达成一致时满足 IPv4 共识，IPv6-only/非标准地址不计入。
- 当前出口缓存复核前再次检查 IPv4/IPv6 路由；Watch 进程定位改用字面路径匹配，避免安装路径中的通配符干扰。
- 新安装默认关闭周期自动改网（`autoFix=false`）；完成本机回归后由用户明确启用，Toast 的一键修复仍需手动点击。
- `-Launch` 增加 Win32 Claude Desktop 安装路径回退（App Paths 与有限常见目录），不再只依赖 Store 包检测。
- 发布文案新增明确限制：系统路由进入 TUN 不等于 Mihomo 对每个 IP 检测域名都选择代理；补充 expectedIPv4 与 DIRECT 规则的验收步骤。
