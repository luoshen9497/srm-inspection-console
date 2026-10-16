import re
import unittest
from pathlib import Path


class StaticUiTests(unittest.TestCase):
    def test_frontend_has_no_read_only_policy_or_confirmation(self):
        root = Path(__file__).resolve().parents[1]
        for filename in ("index.html", "login.html", "app.js", "login.js"):
            with self.subTest(file=filename):
                text = (root / "static" / filename).read_text()
                self.assertNotIn("只读", text)
                self.assertNotIn("read_only", text)
                self.assertNotIn("check-read-only", text)
                self.assertNotIn("ui-scene-read-only", text)
        html = (root / "static" / "index.html").read_text()
        for method in ("PUT", "PATCH", "DELETE"):
            self.assertIn(f"<option>{method}</option>", html)

    def test_login_page_and_authenticated_shell_are_wired(self):
        root = Path(__file__).resolve().parents[1]
        login = (root / "static" / "login.html").read_text()
        login_js = (root / "static" / "login.js").read_text()
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        for marker in (
            'id="login-form"', 'id="username"', 'id="password"',
            'id="password-toggle"', 'id="login-error"', 'id="login-submit"',
        ):
            self.assertIn(marker, login)
        self.assertIn("/api/auth/login", login_js)
        self.assertIn('id="user-menu-trigger"', html)
        self.assertIn('id="logout"', html)
        self.assertIn("/api/auth/session", javascript)
        self.assertIn("X-CSRF-Token", javascript)

    def test_javascript_id_selectors_exist_and_html_ids_are_unique(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        ids = re.findall(r'\bid="([^"]+)"', html)
        self.assertEqual(len(ids), len(set(ids)), "HTML 中存在重复 id")
        referenced = set(re.findall(r"\$\('#([A-Za-z0-9_-]+)'\)", javascript))
        self.assertEqual(sorted(referenced - set(ids)), [])

    def test_admin_shell_and_data_views_keep_required_controls(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        for marker in (
            'id="sidebar-toggle"', 'id="mobile-menu"', 'id="command-layer"',
            'id="system-switcher-trigger"', 'id="system-switcher-menu"',
            'id="system-switcher-name"', 'id="system-options"',
            'id="message-dialog"', 'id="message-title"', 'id="message-confirm"',
            'id="check-search"', 'id="check-category-filter"',
            'id="report-status-filter"', 'data-settings-tab="environment"',
            'id="run-retry-enabled"', 'id="run-retry-max"', 'id="run-retry-delay"',
            'data-settings-tab="operations"', 'data-view="api-checks"',
            'data-settings-tab="advanced"', 'data-incident-tab="deliveries"',
            'id="analytics-range"', 'id="analytics-compare"',
            'id="health-card"', 'id="current-health-value"',
            'id="overview-runtime-status"', 'id="attention-panel"',
            'id="attention-items"', 'id="trend-current-duration"',
            'id="pass-rate-chart"', 'id="result-mix-chart"',
            'id="category-health"', 'id="slow-checks"',
            'id="checks-total-count"', 'id="check-filter-result"',
            'id="report-search"', 'id="report-success-rate"',
            'data-report-check-filter="failed"', 'id="incident-open-count"',
            'id="incident-search"', 'id="notification-pending-count"',
            'id="settings-save-state"', 'id="settings-readiness"',
            'id="settings-env-state"', 'id="settings-api-state"',
            'id="settings-ui-state"', 'id="api-check-search"',
            'id="api-check-result"', 'id="api-checks-body"',
            'id="run-menu-trigger"', 'id="run-menu-popover"',
            'data-run-targets="api,ui"', 'data-run-targets="api"',
            'data-run-targets="ui"', 'id="schedule-target-api"',
            'id="schedule-target-ui"',
            'id="alerts-report-base-url"',
            'data-setting-toggle="schedule"', 'data-setting-toggle="retry"',
            'data-setting-toggle="alerts"', 'data-setting-toggle="success"',
            'id="add-check"', 'id="check-save-draft"', 'id="check-test"',
            'id="check-save-enable"', 'id="check-expected-status"',
            '<span class="console-mark" aria-hidden="true">SRM</span>',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, html)

    def test_system_switcher_is_in_global_topbar_not_sidebar(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        sidebar = html[html.index('<aside id="sidebar"'):html.index('</aside>')]
        topbar = html[html.index('<header class="topbar"'):html.index('</header>')]
        self.assertNotIn('id="system-switcher-trigger"', sidebar)
        self.assertIn('class="brand-home"', sidebar)
        self.assertIn('class="context-switcher topbar-context-switcher"', topbar)
        self.assertIn('id="system-switcher-trigger"', topbar)

    def test_runtime_feedback_uses_the_shared_dialog(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        self.assertIn('id="message-dialog"', html)
        self.assertIn("function showMessage(options)", javascript)
        self.assertIn("function showConfirm(options)", javascript)
        self.assertIn("function showProgress(options)", javascript)
        self.assertIn("options.mode === 'message'", javascript)
        self.assertIn("else dialog.show()", javascript)
        self.assertIn("dialog.close('dismiss')", javascript)
        self.assertNotIn('id="notice"', html)
        self.assertIn('id="check-test-result"', html)
        self.assertIn("function renderApiTestResult(result)", javascript)

    def test_message_title_shares_the_header_row_with_the_status_icon(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        stylesheet = (root / "static" / "style.css").read_text()
        header_start = html.index('<div class="message-dialog-head">')
        header_end = html.index('</div>', header_start)
        header = html[header_start:header_end]
        self.assertIn('id="message-icon"', header)
        self.assertIn('id="message-title"', header)
        self.assertIn('id="message-close"', header)
        self.assertIn('.message-dialog.confirm .message-dialog-head h2 { font-size: 20px;', stylesheet)
        self.assertIn('.message-dialog.confirm p { font-size: 14px;', stylesheet)
        self.assertIn('.message-dialog.confirm .message-meta { gap: 14px 16px; padding: 16px; font-size: 14px;', stylesheet)

    def test_report_download_button_is_part_of_the_filter_toolbar(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        toolbar_start = html.index('<div class="report-toolbar')
        toolbar_end = html.index('</div>', toolbar_start)
        toolbar = html[toolbar_start:toolbar_end]
        self.assertLess(toolbar.index('id="report-trigger-filter"'), toolbar.index('id="download-report"'))

    def test_report_supports_ui_step_timeline_and_artifact_previews(self):
        root = Path(__file__).resolve().parents[1]
        javascript = (root / "static" / "app.js").read_text()
        stylesheet = (root / "static" / "style.css").read_text()
        self.assertIn("function artifactUrl(runId, artifactId)", javascript)
        self.assertIn("function renderUiSteps(report, item)", javascript)
        self.assertIn("failure_screenshot", javascript)
        self.assertIn(".ui-step-list", stylesheet)
        self.assertIn(".step-screenshot", stylesheet)

    def test_report_center_exposes_independent_api_and_ui_views(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        stylesheet = (root / "static" / "style.css").read_text()
        self.assertGreaterEqual(html.count('data-report-kind="api"'), 2)
        self.assertGreaterEqual(html.count('data-report-kind="ui"'), 2)
        self.assertIn("/api/reports/${kind}", javascript)
        self.assertIn("function setReportKind(kind)", javascript)
        self.assertIn("function requestedReportDeepLink()", javascript)
        self.assertIn("function syncReportDeepLink(runId)", javascript)
        self.assertIn("function openRequestedReport()", javascript)
        self.assertIn("reportViewStates", javascript)
        self.assertIn(".report-kind-switcher", stylesheet)
        self.assertIn(".report-nav-children", stylesheet)
        self.assertIn('aria-controls="report-nav-children"', html)
        self.assertIn('class="report-nav-group is-collapsed"', html)
        self.assertIn('title="报告中心" aria-expanded="false"', html)
        self.assertIn("function setReportNavExpanded(expanded)", javascript)
        self.assertIn(".report-nav-group.is-collapsed .report-nav-children", stylesheet)
        self.assertIn("font-size: 13px", stylesheet)

    def test_check_center_exposes_independent_api_and_ui_views(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        stylesheet = (root / "static" / "style.css").read_text()
        self.assertGreaterEqual(html.count('data-check-kind="api"'), 2)
        self.assertGreaterEqual(html.count('data-check-kind="ui"'), 2)
        self.assertIn('aria-controls="check-nav-children"', html)
        self.assertIn("function setCheckKind(kind)", javascript)
        self.assertIn("function setCheckNavExpanded(expanded)", javascript)
        self.assertIn("checkViewStates", javascript)
        self.assertIn("function typedChecks()", javascript)
        self.assertIn(".check-nav-group.is-collapsed .check-nav-children", stylesheet)
        self.assertIn(".check-nav-child", stylesheet)
        self.assertIn("font-size: 13px", stylesheet)

    def test_ui_scene_editor_keeps_the_sidebar_visible(self):
        root = Path(__file__).resolve().parents[1]
        stylesheet = (root / "static" / "style.css").read_text()
        self.assertIn(
            ".ui-editor-layer { position: fixed; inset: 0 0 0 var(--sidebar-width);",
            stylesheet,
        )
        self.assertNotIn(".ui-editor-layer { position: fixed; inset: 0;", stylesheet)

    def test_api_editor_uses_full_workspace_with_persistent_test_panel(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        stylesheet = (root / "static" / "style.css").read_text()
        self.assertIn('id="api-editor-layer"', html)
        self.assertIn('class="api-section-rail"', html)
        self.assertIn('class="api-test-panel"', html)
        self.assertIn('id="check-test-result"', html)
        self.assertIn("function syncApiEditorDirtyState()", javascript)
        self.assertIn("function renderApiTestResult(result)", javascript)
        self.assertIn(
            ".api-editor-layer { position: fixed; inset: 0 0 0 var(--sidebar-width);",
            stylesheet,
        )

    def test_api_json_editors_show_safe_example_templates(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        self.assertIn('"Authorization": "Bearer ${ticket}"', html)
        self.assertIn('"pageNum": 1', html)
        self.assertIn('{"path": "$.code", "op": "equals", "value": 100000000}', html)
        self.assertIn('{"variable": "supplier_id", "path": "$.data.id"}', html)
        self.assertIn("留空表示不额外添加请求头", html)
        self.assertIn("$('#check-headers').value = isNew ? ''", javascript)
        self.assertIn("$('#check-body').value = isNew ? ''", javascript)
        self.assertIn("$('#check-assertions').value = isNew ? ''", javascript)
        self.assertIn("$('#check-extract').value = isNew ? ''", javascript)
        self.assertIn("parseEditor('#check-headers', '请求头', {})", javascript)
        self.assertIn("parseEditor('#check-body', '请求体', {})", javascript)
        self.assertIn("parseEditor('#check-assertions', '业务断言', [])", javascript)
        self.assertIn("parseEditor('#check-extract', '响应变量提取', [])", javascript)
        self.assertIn("请求头必须是 JSON 对象", javascript)
        self.assertIn("业务断言必须是 JSON 数组", javascript)
        self.assertIn("响应变量提取必须是 JSON 数组", javascript)
        self.assertRegex(html, r'<script src="\./app\.js\?v=[A-Za-z0-9-]+"></script>')

    def test_ui_scene_editor_supports_named_login_dependency(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "static" / "index.html").read_text()
        javascript = (root / "static" / "app.js").read_text()
        self.assertIn('id="ui-scene-auth-dependency"', html)
        self.assertIn('id="ui-auth-dependency-item"', html)
        self.assertIn("scene.auth_dependency", javascript)
        self.assertIn("share_browser_context: true", javascript)

    def test_ui_scene_login_relationship_badges_are_highlighted(self):
        root = Path(__file__).resolve().parents[1]
        javascript = (root / "static" / "app.js").read_text()
        stylesheet = (root / "static" / "style.css").read_text()
        self.assertIn('<span class="badge accent">登录前置</span>', javascript)
        self.assertIn('<span class="badge accent">前置：', javascript)
        self.assertIn(".badge.accent", stylesheet)

    def test_ui_scene_editor_persists_login_result_marker_for_assert_url(self):
        root = Path(__file__).resolve().parents[1]
        javascript = (root / "static" / "app.js").read_text()
        start = javascript.index("function commitUiStepForm()")
        end = javascript.index("function uiLoginProviders", start)
        commit_step = javascript[start:end]

        self.assertIn("} else if (action === 'assert_url') {", commit_step)
        self.assertIn(
            "\n  if (action.startsWith('assert_') && $('#ui-step-authentication').checked) "
            "step.authentication_assertion = true;",
            commit_step,
        )


if __name__ == "__main__":
    unittest.main()
