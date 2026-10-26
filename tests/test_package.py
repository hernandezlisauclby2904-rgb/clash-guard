import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class PackageRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = (ROOT / 'clash_guard.ps1').read_text(encoding='utf-8')
        cls.readme = (ROOT / 'README.md').read_text(encoding='utf-8')
        cls.vbs = (ROOT / 'toast_action.vbs').read_text(encoding='utf-8')
        cls.config = json.loads((ROOT / 'clash_guard_config.json').read_text(encoding='utf-8'))
        cls.landing = (ROOT / 'docs' / 'landing.html').read_text(encoding='utf-8') if (ROOT / 'docs' / 'landing.html').exists() else ''

    def test_json_configuration_parses_and_uses_https(self):
        self.assertGreaterEqual(len(self.config['ipEndpoints']), 1)
        self.assertTrue(all(x['url'].startswith('https://') for x in self.config['ipEndpoints']))
        self.assertIn('expectedIPv4', self.config)
        self.assertIn('blockPacProxy', self.config)
        self.assertFalse(self.config['autoFix'], '新安装默认不应自动改动网络')
        self.assertIn('autoFix = $false', self.script)

    def test_uses_process_start_trace_not_instance_polling(self):
        self.assertIn('Win32_ProcessStartTrace', self.script)
        self.assertNotIn('__InstanceCreationEvent WITHIN 1', self.script)

    def test_ipv6_is_checked_again_after_autofix(self):
        self.assertGreaterEqual(self.script.count('if ($state.ipv6.leak)'), 2)
        self.assertIn('Get-CGIPv6Status', self.script)

    def test_ipv4_routes_are_verified_before_ip_queries(self):
        self.assertIn('function Get-CGIPv4RouteStatus', self.script)
        self.assertIn('$ipv4Preflight = Get-CGIPv4RouteStatus', self.script)
        self.assertIn('至少两个 IP 来源都返回有效 IPv4 地址', self.readme)
        self.assertIn('IPv4 默认/分流路由', (ROOT / 'docs' / 'REGRESSION_TEST_PLAN.md').read_text(encoding='utf-8'))

    def test_equal_metric_routes_do_not_pick_arbitrary_tun_only_winner(self):
        self.assertGreaterEqual(self.script.count('$matchingRoutes | Measure-Object -Property metric -Minimum'), 2)
        self.assertIn('equally preferred route', self.script)

    def test_unknown_is_distinct_and_fail_open_is_explicit(self):
        self.assertIn("qualityState = 'UNKNOWN'", self.script)
        self.assertIn('风险状态为 UNKNOWN', self.script)
        self.assertIn('UNKNOWN 不等于 PASS', self.__class__.readme)

    def test_ip_pass_requires_distinct_risk_sources_and_real_ip_providers(self):
        self.assertIn('$qualitySourceCount -ge 2', self.script)
        self.assertIn('$ipProviders = @($allIpProviders | Where-Object { Test-CGIPv4Address -Address ([string]$_.ip) })', self.script)
        self.assertIn('Only providers returning a validated IPv4 address count toward IPv4 consensus', self.script)
        self.assertIn('-4 -fsS --max-time $TimeoutSec', self.script)
        self.assertIn('-4 -sS --max-time 6', self.script)
        self.assertIn('qualitySources = $qualitySourceCount', self.script)
        self.assertIn('至少两个 IP 来源都返回有效 IPv4 地址', self.readme)

    def test_expected_ipv4_rejects_ipv6_and_invalid_values(self):
        self.assertIn('[System.Net.Sockets.AddressFamily]::InterNetwork', self.script)
        self.assertIn('function Test-CGIPv4Address', self.script)
        self.assertIn('$octet =', self.script)
        self.assertIn('expectedIPv4 必须是标准点分十进制 IPv4 地址', self.script)

    def test_protocol_registration_is_idempotent(self):
        self.assertIn("$rootKey.GetValue('')", self.script)
        self.assertIn("$commandKey.GetValue('') -ne $command", self.script)

    def test_autofix_gate_cache_keeps_consistency_and_source_count(self):
        self.assertGreaterEqual(self.script.count('ipConsistency=[string]$state.ipConsistency'), 1)
        self.assertGreaterEqual(self.script.count('qualitySources=[int]$state.qualitySources'), 1)

    def test_cached_ip_quality_is_invalidated_when_exit_ip_changes(self):
        self.assertIn('function Get-CGCurrentExitIp', self.script)
        self.assertIn('@($cache.exitIps) -notcontains [string]$currentExitIp.ip', self.script)
        self.assertIn('当前出口 IP 与质量缓存不匹配', self.script)

    def test_direct_probe_and_autofix_require_verified_routes(self):
        self.assertIn("$ipv4BeforeProxyChange.state -ne 'PASS'", self.script)
        self.assertIn("$ipv4AfterProxyChange.state -eq 'PASS' -and -not $ipv6AfterProxyChange.leak", self.script)
        self.assertGreaterEqual(self.script.count("if ($state.ipv4Route.state -eq 'PASS' -and -not $state.ipv6.leak)"), 2)


    def test_ipv4_quality_cannot_pass_with_ipv6_endpoint_mixed_in(self):
        self.assertIn('$nonIPv4ProviderCount -gt 0', self.script)
        self.assertIn("$ipConsistency = 'MISMATCH'", self.script)
        self.assertIn("if (-not (Test-CGIPv4Address -Address ([string]$result.ip)))", self.script)

    def test_installer_aborts_when_legacy_tasks_are_not_disabled(self):
        installer = (ROOT / 'install.ps1').read_text(encoding='utf-8')
        self.assertIn('安装已取消', installer)
        self.assertIn('不会继续', installer)


    def test_auto_fix_is_opt_in_for_first_run(self):
        self.assertFalse(self.config['autoFix'])
        self.assertIn('autoFix = $false', self.script)
        self.assertIn('autoFix` 默认是 `false`', self.__class__.readme)


    def test_missing_autofix_setting_defaults_to_false_and_types_are_validated(self):
        self.assertIn('NotePropertyName autoFix -NotePropertyValue $false', self.script)
        self.assertIn("foreach ($boolName in @('autoFix','autoStartClash','blockPacProxy','blockAutoDetectProxy'))", self.script)
        self.assertIn("$numericRules = @(", self.script)

    def test_local_proxy_port_must_be_valid(self):
        self.assertIn('$portNumber -lt 1 -or $portNumber -gt 65535', self.script)


    def test_ipv6_enumeration_errors_are_unknown_not_pass(self):
        self.assertIn("Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' }", self.script)
        self.assertIn('不能安全排除旁路', self.script)

    def test_external_ip_queries_force_ipv4(self):
        self.assertIn("$curl.Source -4 -fsS --max-time $TimeoutSec --noproxy '*'", self.script)

    def test_launch_supports_classic_win32_install_locations(self):
        self.assertIn('App Paths\\Claude.exe', self.script)
        self.assertIn('Programs\\Claude\\Claude.exe', self.script)
        self.assertIn('function Start-CGClaudeApp', self.script)


    def test_local_secret_override_is_supported_and_gitignored(self):
        self.assertIn("clash_guard_config.local.json", self.script)
        self.assertIn('本地覆盖值不会自动上传', self.script)
        self.assertIn('clash_guard_config.local.json', (ROOT / '.gitignore').read_text(encoding='utf-8'))

    def test_external_risk_scores_must_be_finite_0_to_100(self):
        self.assertGreaterEqual(self.script.count('[double]::IsNaN($num)'), 2)
        self.assertGreaterEqual(self.script.count('$num -le 100'), 2)

    def test_report_has_no_auto_fix_call(self):
        report_start = self.script.index('if ($Report) {', self.script.index('# Default: inspection.'))
        report_end = self.script.find('\nInvoke-CGWatchCare', report_start)
        report_block = self.script[report_start:report_end if report_end >= 0 else None]
        self.assertNotIn('Invoke-CGAutoFix', report_block)

    def test_proxy_parser_supports_compound_local_values(self):
        self.assertIn('function Test-CGLocalProxyServer', self.script)
        self.assertIn("$ProxyServer -split ';'", self.script)
        self.assertIn('Test-CGLocalProxyServer -ProxyServer $proxyServer', self.script)

    def test_toast_protocol_is_allow_listed(self):
        self.assertIn('Case "fix", "openip", "checkleaks", "start", "protect"', self.vbs)
        self.assertIn('Case Else', self.vbs)
        self.assertIn('never forwards arbitrary URI text', self.vbs)
        self.assertIn("$id -notin @('fix','openip','checkleaks','start','protect')", self.script)

    def test_old_proxy_enforcer_not_referenced(self):
        self.assertNotIn('ensure_system_proxy.ps1', self.script)
        self.assertIn('不会被自动清除', self.__class__.readme)

    def test_docs_do_not_claim_zero_cpu_or_startup_before_guarantee(self):
        self.assertNotRegex(self.readme, r'零\s*CPU')
        self.assertNotIn('毫秒级拦截', self.readme)
        self.assertIn('并非 OS 级启动前拦截', self.script)

    def test_docs_explain_tun_route_does_not_prove_mihomo_proxy_rule(self):
        self.assertIn('规则仍可能', self.readme)
        self.assertIn('DIRECT', self.readme)
        self.assertIn('实际出口地址', self.landing)
        self.assertIn('ROUTE-02', (ROOT / 'docs' / 'REGRESSION_TEST_PLAN.md').read_text(encoding='utf-8'))

    def test_landing_page_is_accessible_and_contains_scope_limitations(self):
        self.assertTrue(self.landing, 'landing.html must exist')
        self.assertIn('<meta name="viewport"', self.landing)
        self.assertIn('UNKNOWN', self.landing)
        self.assertIn('不是 Claude 官方产品', self.landing)
        self.assertIn('GitHub', self.landing)

    def test_installer_and_uninstaller_exist(self):
        self.assertTrue((ROOT / 'install.ps1').exists())
        self.assertTrue((ROOT / 'uninstall.ps1').exists())
        self.assertIn('ClashGuard-Watch', (ROOT / 'install.ps1').read_text(encoding='utf-8'))
        self.assertIn('ClashGuard-Inspect', (ROOT / 'uninstall.ps1').read_text(encoding='utf-8'))

    def test_html_escape_present_for_generated_navigation(self):
        self.assertIn('[System.Net.WebUtility]::HtmlEncode', self.script)
        self.assertIn('rel="noopener noreferrer"', self.script)

if __name__ == '__main__':
    unittest.main(verbosity=2)
