# Clash Guard 2.0.0 — 检查与测试报告

日期：2026-10-26

## 本次已执行

- Python 静态回归测试：**31/31 通过**，命令为 `python -m unittest discover -s tests -p 'test_*.py' -v`。
- `clash_guard_config.json`：标准 JSON 解析通过；全部配置的 IP 检测端点使用 HTTPS。
- `docs/landing.html`：HTML 标记解析未发现未闭合/异常标签；包含移动端 viewport 元数据。
- PowerShell 源码轻量分隔符扫描：大括号/中括号/圆括号平衡。
- 文件完整性与安全边界检查：自动修复默认关闭；Toast 只接受固定动作；无真实 API secret 被打包；报告模式未调用自动修复函数。
- 当前 31 项静态回归覆盖：IPv6 复检、路由状态 UNKNOWN、IPv4 来源一致性、缓存失效、代理解析、安装器保护、Toast 动作白名单、介绍页边界声明等。
- 最终 ZIP 生成后会执行 `unzip -t` 完整性测试，并核对 SHA-256 与包内文件清单。

## 本次未能执行

当前构建环境不是 Windows，未安装 Windows PowerShell 5.1，也没有 Clash Verge/Mihomo、Windows Toast Runtime 或 Claude Store/Desktop 应用。因此：

- **未能调用 PowerShell 官方解析器验证 `.ps1` 语法**；轻量分隔符扫描不能替代 PowerShell parser。
- 未在真实 Windows 网络路由表上验证 IPv4/IPv6 规则。
- 未实测 Clash 内核 API、Windows 代理设置修改/恢复、计划任务、Toast 按钮及 Claude 进程事件。
- 未验证所有第三方 IP 服务当前返回的真实 JSON 字段是否与脚本映射完全一致。

## 建议的本机验收顺序

1. 将整个文件夹解压到固定路径（先使用包含空格的测试路径也可以）。
2. 在 Windows PowerShell 5.1 中执行 `python -m unittest discover -s tests -p 'test_*.py' -v`。
3. 执行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Invoke-WindowsSmokeTests.ps1`，让 Windows PowerShell parser 真正解析三个 `.ps1` 文件。
4. 执行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\clash_guard.ps1 -Report`。首次安装默认 `autoFix=false`，不会周期性自动改网。
5. 执行 `-TestToast` 并逐个点击通知按钮；随后按 `docs/REGRESSION_TEST_PLAN.md` 完成 IPv4/IPv6、代理、缓存、应急放行和卸载测试。
6. 全部回归通过后，若确实需要周期自动修复，再手动把配置 `autoFix` 改为 `true`。

## 结论

这是一份经过静态回归和包完整性检查的候选 2.0.0 版本，不是经过 Windows 实机验收的“零 Bug”发行版。请以本机测试结果作为最终准入条件。
