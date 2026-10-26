# 发布页面文案（可复制到网站作品详情页）

## 标题

Clash Guard 2.0｜Windows 网络环境检查与 Claude 启动守护

## 一句话简介

为 Windows + Clash Verge/Mihomo 提供 TUN、系统代理、IPv6 路由与出口 IP 状态检查；支持定时巡检、有限自动修复与 Claude 进程创建后的响应式门控。

## 详细介绍

Clash Guard 是一个面向个人 Windows 电脑的辅助防错工具。它会检查 Clash/TUN 状态、Windows 系统代理/PAC/WPAD、IPv6 默认/分流路由，以及到 Claude 服务域名的 TCP 可达性；同时聚合多个第三方 IP 信息接口，并明确区分 PASS、FAIL 和 UNKNOWN。

自动修复默认关闭。完成本机回归测试并由用户显式启用后，程序才会在确认 TUN 已准备好、代理服务器全为本机地址、IPv4/IPv6 路由和真实 HTTPS 请求通过验证后，尝试关闭 Windows 本地系统代理。外部代理、PAC URL 和 WPAD 不会被自动清除。任何自动网络变更都应先备份设置并按测试计划验证。

**重要说明：** 本工具不是 VPN、不是 Claude 官方工具，也不保证匿名或不被封号。第三方风险评分不是 Anthropic 官方判定。Windows 路由表显示流量进入 TUN，并不能证明 Mihomo 对每个检测域名都选择代理节点；规则仍可能将某个域名 `DIRECT`。配置 `expectedIPv4` 并核对 Clash 规则，可辅助验证预期出口。第三方 IP 查询服务会收到实际出口地址，请只使用你信任的服务。Watch 是进程创建后的响应式检查，不是 Windows 内核级启动前封锁；想在启动前检查，请通过 `-Launch` 受控启动入口。

## 版本亮点

- IPv6 地址类型与活动默认/分流路由检查，减少把 ULA/链路本地地址误判成公网泄露。
- 第三方端点失败或返回结构变化时，明确显示 UNKNOWN，不把“没有数据”伪装成 PASS。
- 自动修复后完整复检，避免重建违规列表时漏掉 IPv6/PAC/WPAD 项。
- Toast 按钮采用固定动作白名单；状态 JSON 使用临时文件替换。
- 内含安装/卸载脚本、Windows 回归测试计划和独立 HTML 介绍页。

## 标签

Windows、PowerShell、Clash、Mihomo、Claude、网络诊断、安全工具、开源工具

## 推荐封面/视觉方向

采用深海军蓝底色、青蓝色路由线、简洁盾牌/网卡示意；避免使用红色警报大面积铺底或暗示“百分百防封”。主视觉标题突出“网络状态检查 / 启动前校验”，副标题写“本地运行 · PASS / FAIL / UNKNOWN”。
