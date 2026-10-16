import hashlib
import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from http.server import ThreadingHTTPServer
from sys import path as sys_path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse
from urllib.request import HTTPRedirectHandler, build_opener, urlopen

sys_path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import AuthManager, InspectionState, make_handler, run_inspection, validate_config
from artifact_store import ArtifactStore, resolve_artifact
from browser_executor import execute_ui_check, run_ui_checks


class FakeResponse:
    status = 200


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class FakeLocator:
    def __init__(self, page, identity):
        self.page = page
        self.identity = identity

    def click(self, timeout):
        self.page.actions.append(("click", self.identity, timeout))

    def fill(self, value, timeout):
        self.page.actions.append(("fill", self.identity, value, timeout))

    def select_option(self, value, timeout):
        self.page.actions.append(("select", self.identity, value, timeout))

    def wait_for(self, state, timeout):
        if self.identity in self.page.wait_errors:
            raise TimeoutError("locator timeout")
        self.page.actions.append(("wait", self.identity, state, timeout))

    def inner_text(self, timeout):
        return self.page.texts.get(self.identity, "")

    def count(self):
        return self.page.counts.get(self.identity, 1)


class FakePage:
    def __init__(self):
        self.url = "https://srm.example.local/start?ticket=must-not-be-reported"
        self.main_frame = self
        self.frames = [self]
        self.actions = []
        self.texts = {}
        self.counts = {}
        self.screenshots = []
        self.handlers = {}
        self.wait_errors = set()
        self.render_wait_error = None
        self.network_idle_error = None
        self.wait_hook = None

    def get_by_test_id(self, value):
        return FakeLocator(self, ("test_id", value))

    def get_by_role(self, role, name=None, exact=False):
        return FakeLocator(self, ("role", role, name, exact))

    def get_by_label(self, value, exact=False):
        return FakeLocator(self, ("label", value, exact))

    def get_by_placeholder(self, value, exact=False):
        return FakeLocator(self, ("placeholder", value, exact))

    def get_by_text(self, value, exact=False):
        return FakeLocator(self, ("text", value, exact))

    def locator(self, value):
        return FakeLocator(self, ("css", value))

    def goto(self, url, wait_until, timeout):
        self.url = url + "?ticket=secret"
        self.actions.append(("goto", url, wait_until, timeout))
        return FakeResponse()

    def wait_for_function(self, _expression, timeout):
        if self.render_wait_error:
            raise self.render_wait_error
        self.actions.append(("wait_for_visible_content", timeout))

    def wait_for_load_state(self, state, timeout):
        if self.network_idle_error:
            raise self.network_idle_error
        self.actions.append(("wait_for_load_state", state, timeout))

    def wait_for_timeout(self, timeout):
        self.actions.append(("wait_for_timeout", timeout))
        if self.wait_hook:
            self.wait_hook()

    def screenshot(self, **kwargs):
        self.screenshots.append(kwargs)
        Path(kwargs["path"]).write_bytes(b"fake-png-evidence")

    def title(self):
        return "SRM 工作台"

    def on(self, event, handler):
        self.handlers[event] = handler


class FakeTracing:
    def __init__(self):
        self.started = False
        self.stopped = False

    def start(self, **_kwargs):
        self.started = True

    def stop(self, path=None):
        self.stopped = True
        if path:
            Path(path).write_bytes(b"fake-trace")


class FakeContext:
    def __init__(self, page):
        self.page = page
        self.tracing = FakeTracing()
        self.closed = False

    def new_page(self):
        return self.page

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self, context):
        self.context = context
        self.closed = False

    def new_context(self, **_kwargs):
        return self.context

    def close(self):
        self.closed = True


class FakeChromium:
    def __init__(self, browser):
        self.browser = browser

    def launch(self, **_kwargs):
        return self.browser


class FallbackChromium(FakeChromium):
    def __init__(self, browser):
        super().__init__(browser)
        self.launches = []

    def launch(self, **kwargs):
        self.launches.append(kwargs)
        if "channel" not in kwargs:
            raise RuntimeError("Executable doesn't exist at managed browser path")
        return self.browser


class FakeRuntime:
    def __init__(self, browser):
        self.chromium = FakeChromium(browser)


class UiInspectionTests(unittest.TestCase):
    def config(self):
        return {
            "system_id": "mock-srm",
            "environment": "test",
            "base_url": "https://srm.example.local",
            "ui": {
                "headless": True,
                "default_timeout_seconds": 10,
                "viewport": {"width": 1440, "height": 900},
                "screenshot_masks": [{"test_id": "current-user"}],
            },
            "checks": [self.check()],
        }

    def check(self):
        return {
            "id": "ui-login", "type": "ui", "name": "UI 登录",
            "category": "访问与会话", "enabled": True, "read_only": True,
            "login_precheck": True, "steps": [
                {"id": "open-login", "description": "打开登录页", "action": "goto", "path": "/login"},
                {"id": "fill-password", "description": "填写密码", "action": "fill",
                 "locator": {"label": "密码"}, "value": "${SRM_PASSWORD}", "sensitive": True},
                {"id": "verify-workbench", "description": "确认工作台", "action": "assert_visible",
                 "authentication_assertion": True, "locator": {"test_id": "workbench"}},
            ],
        }

    def test_ui_check_emits_screenshot_for_every_step_and_masks_secret_input(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            result = execute_ui_check(
                self.check(), self.config(), page, {"SRM_PASSWORD": "private-password"}, store
            )

            self.assertEqual(result["status"], "passed")
            self.assertEqual(len(result["steps"]), 3)
            self.assertEqual(result["evidence"]["screenshot_count"], 3)
            self.assertEqual(len(page.screenshots), 3)
            self.assertEqual(len(page.screenshots[1]["mask"]), 2)
            self.assertNotIn("private-password", json.dumps(result))
            self.assertEqual(result["evidence"]["page_url"], "https://srm.example.local/login")

    def test_failed_assertion_has_normal_and_full_page_evidence(self):
        check = self.check()
        check["login_precheck"] = False
        check["steps"] = [{
            "id": "verify-title", "description": "确认标题", "action": "assert_text",
            "locator": {"test_id": "title"}, "expected": "采购申请", "match": "equals",
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.texts[("test_id", "title")] = "需求池"
            result = execute_ui_check(check, self.config(), page, {}, store)

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["classification"], "assertion_failed")
            self.assertIn("screenshot", result["steps"][0])
            self.assertIn("failure_screenshot", result["steps"][0])
            self.assertTrue(page.screenshots[-1]["full_page"])

    def test_locator_searches_all_nested_iframes(self):
        check = self.check()
        check["login_precheck"] = False
        check["steps"] = [{
            "id": "verify-column", "description": "确认采购申请表头",
            "action": "assert_visible",
            "locator": {"text": "采购申请行号", "exact": True},
        }]
        page = FakePage()
        child_frame = FakePage()
        nested_frame = FakePage()
        identity = ("text", "采购申请行号", True)
        page.counts[identity] = 0
        child_frame.counts[identity] = 0
        nested_frame.counts[identity] = 1
        page.frames = [page, child_frame, nested_frame]

        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            result = execute_ui_check(check, self.config(), page, {}, store)

        self.assertEqual(result["status"], "passed")
        self.assertIn(("wait", identity, "visible", 10000), nested_frame.actions)
        self.assertNotIn(("wait", identity, "visible", 10000), page.actions)

    def test_locator_rescans_when_iframe_attaches_late(self):
        check = self.check()
        check["login_precheck"] = False
        check["steps"] = [{
            "id": "verify-column", "description": "等待采购申请表头",
            "action": "assert_visible", "timeout_seconds": 1,
            "locator": {"text": "采购申请行号", "exact": True},
        }]
        page = FakePage()
        child_frame = FakePage()
        identity = ("text", "采购申请行号", True)
        page.counts[identity] = 0
        child_frame.counts[identity] = 1

        def attach_child_frame():
            page.frames = [page, child_frame]
            page.wait_hook = None

        page.wait_hook = attach_child_frame
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            result = execute_ui_check(check, self.config(), page, {}, store)

        self.assertEqual(result["status"], "passed")
        self.assertIn(("wait", identity, "visible", 1000), child_frame.actions)

    def test_login_contract_failure_is_distinct_from_authentication_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.wait_errors.add(("test_id", "workbench"))
            result = execute_ui_check(
                self.check(), self.config(), page, {"SRM_PASSWORD": "secret"}, store
            )
            self.assertEqual(result["classification"], "authentication_failed")

            contract_check = self.check()
            contract_check["steps"] = [{
                "id": "verify-menu", "description": "定位菜单", "action": "assert_visible",
                "locator": {"test_id": "missing-menu"},
            }]
            page = FakePage()
            page.wait_errors.add(("test_id", "missing-menu"))
            result = execute_ui_check(contract_check, self.config(), page, {}, store)
            self.assertEqual(result["classification"], "automation_contract_changed")

    def test_business_locator_timeout_on_login_page_reports_authentication_failure(self):
        check = self.check()
        check["login_precheck"] = False
        check["steps"] = [{
            "id": "open-purchase", "description": "点击采购申请", "action": "click",
            "locator": {"text": "采购申请"},
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.url = "https://srm.example.local/login"

            def fail_click(timeout):
                raise TimeoutError("locator timeout")

            locator = FakeLocator(page, ("text", "采购申请", False))
            locator.click = fail_click
            with patch("browser_executor._locator", return_value=locator):
                result = execute_ui_check(check, self.config(), page, {}, store)

            self.assertEqual(result["classification"], "authentication_failed")
            self.assertEqual(result["reason"], "当前仍停留在登录页，前置登录未成功或登录态已失效")

    def test_negative_url_match_supports_login_success_assertion(self):
        check = self.check()
        check["steps"] = [{
            "id": "verify-login", "description": "确认已离开登录页", "action": "assert_url",
            "expected": "/login", "match": "not_contains", "authentication_assertion": True,
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.url = "https://srm.example.local/#/workbench"
            result = execute_ui_check(check, self.config(), page, {}, store)

            self.assertEqual(result["status"], "passed")

    def test_url_assertion_preserves_spa_hash_route_for_exact_match(self):
        check = self.check()
        check["steps"] = [{
            "id": "verify-login", "description": "确认首页路由", "action": "assert_url",
            "expected": "https://srm.example.local/#/workbench", "match": "equals",
            "authentication_assertion": True,
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.url = "https://srm.example.local/#/workbench"
            result = execute_ui_check(check, self.config(), page, {}, store)

            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["evidence"]["page_url"], "https://srm.example.local/")

    def test_ui_runner_reuses_context_and_releases_browser(self):
        page = FakePage()
        context = FakeContext(page)
        browser = FakeBrowser(context)

        @contextmanager
        def runtime_factory():
            yield FakeRuntime(browser)

        second = {
            "id": "ui-list", "type": "ui", "name": "UI 列表", "category": "采购申请",
            "enabled": True, "read_only": True, "steps": [{
                "id": "verify-table", "description": "确认列表", "action": "assert_visible",
                "locator": {"test_id": "table"},
            }],
        }
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            results = run_ui_checks(
                [self.check(), second], self.config(), {"SRM_PASSWORD": "secret"},
                store, runtime_factory=runtime_factory,
            )

        self.assertEqual([item["status"] for item in results], ["passed", "passed"])
        self.assertTrue(context.closed)
        self.assertTrue(browser.closed)

    def test_ui_runner_resolves_named_login_dependency_before_business_scene(self):
        page = FakePage()
        context = FakeContext(page)
        browser = FakeBrowser(context)

        @contextmanager
        def runtime_factory():
            yield FakeRuntime(browser)

        login = self.check()
        business = {
            "id": "purchase-list", "type": "ui", "name": "采购申请列表",
            "category": "采购申请", "enabled": True, "read_only": True,
            "auth_dependency": {
                "scene_id": "ui-login", "run_policy": "when-invalid",
                "share_browser_context": True,
            },
            "steps": [{
                "id": "open-purchase-list", "description": "打开采购申请列表",
                "action": "goto", "path": "/purchase-list",
            }],
        }
        config = self.config()
        config["checks"] = [login, business]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            results = run_ui_checks(
                [business, login], config, {"SRM_PASSWORD": "secret"}, store,
                runtime_factory=runtime_factory,
            )

        self.assertEqual([item["id"] for item in results], ["ui-login", "purchase-list"])
        navigations = [action[1] for action in page.actions if action[0] == "goto"]
        self.assertEqual(navigations, ["https://srm.example.local/login", "https://srm.example.local/purchase-list"])
        self.assertTrue(context.closed)

    def test_ui_auth_dependency_requires_enabled_login_provider(self):
        login = self.check()
        business = {
            "id": "purchase-list", "type": "ui", "name": "采购申请列表",
            "category": "采购申请", "enabled": True, "read_only": True,
            "auth_dependency": {
                "scene_id": "ui-login", "run_policy": "when-invalid",
                "share_browser_context": True,
            },
            "steps": [{
                "id": "open-purchase-list", "description": "打开采购申请列表",
                "action": "goto", "path": "/purchase-list",
            }],
        }
        config = self.config()
        config["checks"] = [login, business]
        validate_config(config)

        config["checks"][0]["enabled"] = False
        with self.assertRaisesRegex(ValueError, "必须先启用前置登录场景"):
            validate_config(config)

        config["checks"][0]["enabled"] = True
        config["checks"][0]["login_precheck"] = False
        config["checks"][0]["steps"][-1].pop("authentication_assertion")
        with self.assertRaisesRegex(ValueError, "未标记为可作为登录前置"):
            validate_config(config)

    def test_enabled_login_provider_requires_authentication_assertion(self):
        config = self.config()
        config["checks"][0]["steps"][-1].pop("authentication_assertion")

        with self.assertRaisesRegex(ValueError, "登录成功断言"):
            validate_config(config)

    def test_ui_runner_falls_back_to_installed_chrome(self):
        page = FakePage()
        context = FakeContext(page)
        browser = FakeBrowser(context)
        chromium = FallbackChromium(browser)

        @contextmanager
        def runtime_factory():
            runtime = FakeRuntime(browser)
            runtime.chromium = chromium
            yield runtime

        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            results = run_ui_checks(
                [self.check()], self.config(), {"SRM_PASSWORD": "secret"},
                store, runtime_factory=runtime_factory,
            )

        self.assertEqual(results[0]["status"], "passed")
        self.assertEqual(chromium.launches[-1]["channel"], "chrome")

    def test_failure_trace_is_attached_only_when_explicitly_acknowledged(self):
        page = FakePage()
        page.texts[("test_id", "title")] = "错误页面"
        context = FakeContext(page)
        browser = FakeBrowser(context)

        @contextmanager
        def runtime_factory():
            yield FakeRuntime(browser)

        check = {
            "id": "ui-detail", "type": "ui", "name": "详情页", "category": "采购申请",
            "enabled": True, "read_only": True, "steps": [{
                "id": "verify-title", "description": "确认详情标题", "action": "assert_text",
                "locator": {"test_id": "title"}, "expected": "采购申请详情", "match": "equals",
            }],
        }
        config = self.config()
        config["ui"]["trace_on_failure"] = True
        config["ui"]["trace_sensitive_data_acknowledged"] = True
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            results = run_ui_checks([check], config, {}, store, runtime_factory=runtime_factory)
            self.assertTrue((store.run_dir / "browser-trace.zip").exists())
        self.assertEqual(results[0]["status"], "failed")
        self.assertEqual(results[0]["evidence"]["trace"]["artifact_id"], "browser-trace.zip")
        self.assertTrue(context.tracing.started)
        self.assertTrue(context.tracing.stopped)

    def test_artifact_resolution_blocks_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            target = store.screenshot_path("ui-login", 1, "open-login")
            target.write_bytes(b"png")
            artifact = store.metadata(target)
            self.assertEqual(resolve_artifact(Path(temp), store.run_id, artifact["artifact_id"]), target.resolve())
            with self.assertRaisesRegex(ValueError, "artifact_id"):
                resolve_artifact(Path(temp), store.run_id, "../secrets.json")

    def test_ui_configuration_enforces_evidence_and_trace_acknowledgement(self):
        config = self.config()
        validate_config(config)

        config["checks"][0]["steps"][0]["screenshot"] = False
        with self.assertRaisesRegex(ValueError, "截图证据"):
            validate_config(config)

        config = self.config()
        config["ui"]["trace_on_failure"] = True
        with self.assertRaisesRegex(ValueError, "trace_sensitive_data_acknowledged"):
            validate_config(config)

    def test_ui_configuration_and_execution_allow_business_clicks(self):
        locators = [{"test_id": "submitButton"}, {"css": "button[type=submit]"}] + [
            {"role": "button", "name": name} for name in (
                "保存", "提交", "删除", "审批", "支付", "上传", "新建", "save", "delete",
            )
        ]
        for legacy_value in (True, False, None):
            with self.subTest(read_only=legacy_value):
                config = self.config()
                check = config["checks"][0]
                check["login_precheck"] = False
                if legacy_value is None:
                    check.pop("read_only")
                else:
                    check["read_only"] = legacy_value
                check["steps"] = [
                    {"id": f"click-{index}", "description": "业务操作", "action": "click", "locator": locator}
                    for index, locator in enumerate(locators)
                ]
                validate_config(config)
                with tempfile.TemporaryDirectory() as temp:
                    store = ArtifactStore(Path(temp), "20261013T010000Z-1234abcd")
                    store.reset()
                    page = FakePage()
                    result = execute_ui_check(check, config, page, {}, store)
                    self.assertEqual(result["status"], "passed")
                    self.assertEqual(len([action for action in page.actions if action[0] == "click"]), len(locators))
                    self.assertEqual(result["evidence"]["screenshot_count"], len(locators))

    def test_ui_navigation_accepts_spa_hash_and_same_origin_absolute_url(self):
        config = self.config()
        config["checks"][0]["steps"][0]["path"] = "/login#/login"
        validate_config(config)

        config["checks"][0]["steps"][0]["path"] = "https://srm.example.local/login#/login"
        validate_config(config)

        config["checks"][0]["steps"][0]["path"] = "https://malicious.example/login"
        with self.assertRaisesRegex(ValueError, "同源"):
            validate_config(config)

    def test_ui_runner_opens_same_origin_absolute_url_without_prefixing_base(self):
        check = self.check()
        check["steps"] = [{
            "id": "open-login", "description": "打开登录页", "action": "goto",
            "path": "https://srm.example.local/login#/login",
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            result = execute_ui_check(check, self.config(), page, {}, store)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(page.actions[0][1], "https://srm.example.local/login#/login")
        self.assertEqual(page.actions[1][0], "wait_for_visible_content")
        self.assertEqual(page.actions[2][0:2], ("wait_for_load_state", "networkidle"))

    def test_ui_navigation_keeps_rendered_page_when_network_never_becomes_idle(self):
        check = self.check()
        check["steps"] = [{
            "id": "open-login", "description": "打开登录页", "action": "goto",
            "path": "/login", "wait_until": "domcontentloaded",
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.network_idle_error = TimeoutError("network idle timeout")
            result = execute_ui_check(check, self.config(), page, {}, store)

        self.assertEqual(result["status"], "passed")
        self.assertFalse(result["steps"][0]["assertion"]["network_settled"])

    def test_ui_navigation_fails_when_page_never_renders_visible_content(self):
        check = self.check()
        check["steps"] = [{
            "id": "open-login", "description": "打开登录页", "action": "goto",
            "path": "/login", "wait_until": "domcontentloaded",
        }]
        with tempfile.TemporaryDirectory() as temp:
            store = ArtifactStore(Path(temp), "20260928T010000Z-1234abcd")
            store.reset()
            page = FakePage()
            page.render_wait_error = TimeoutError("visible content timeout")
            result = execute_ui_check(check, self.config(), page, {}, store)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["classification"], "timeout")
        self.assertIn("screenshot", result["steps"][0])

    def test_full_ui_verification_is_bound_to_content_without_blocking_enablement(self):
        config = self.config()
        config["checks"][0]["enabled"] = False
        config["checks"][0].pop("read_only")
        passed = {
            "id": "ui-login", "name": "UI 登录", "type": "ui", "status": "passed",
            "classification": None, "steps": [], "evidence": {}, "duration_ms": 4,
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(config))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            candidate = self.check()
            candidate["enabled"] = False
            candidate.pop("read_only")
            with patch("app.run_ui_checks", return_value=[passed]):
                tested = state.test_ui_check({"check": candidate})
            self.assertTrue(tested["verified"])
            self.assertFalse(state.ui_capabilities()["read_only_enforced"])

            document = state.config_document()
            enabled = json.loads(json.dumps(document["config"]))
            enabled["checks"][0]["enabled"] = True
            saved = state.update_config({
                "config_version": document["config_version"], "config": enabled,
            })
            self.assertTrue(saved["config"]["checks"][0]["enabled"])

            changed = json.loads(json.dumps(saved["config"]))
            changed["checks"][0]["steps"][0]["description"] = "打开新的登录页"
            updated = state.update_config({
                "config_version": saved["config_version"], "config": changed,
            })
            self.assertTrue(updated["config"]["checks"][0]["enabled"])
            self.assertFalse(updated["ui_verification"]["ui-login"]["verified"])

    def test_legacy_ui_verification_survives_policy_removal_without_accepting_step_changes(self):
        for legacy_value in (True, False):
            with self.subTest(read_only=legacy_value), tempfile.TemporaryDirectory() as temp:
                config = self.config()
                check = config["checks"][0]
                check["read_only"] = legacy_value
                check["enabled"] = False
                legacy = json.loads(json.dumps(check))
                legacy.pop("enabled")
                old_hash = hashlib.sha256(json.dumps(
                    legacy, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                ).encode()).hexdigest()
                root = Path(temp)
                config_path = root / "checks.json"
                config_path.write_text(json.dumps(config))
                state = InspectionState(config_path, root / "runs", root / "secrets.json")
                state.runtime.set_metadata("ui_verification:ui-login", {"check_hash": old_hash})
                aggregate = state.config_document()
                document = state.ui_scenes_document()
                self.assertNotIn("read_only", aggregate["config"]["checks"][0])
                self.assertNotIn("read_only", document["items"][0])
                self.assertTrue(aggregate["ui_verification"]["ui-login"]["verified"])
                self.assertTrue(document["verification"]["ui-login"]["verified"])
                document["items"][0]["enabled"] = True
                saved = state.update_ui_scenes({"version": document["version"], "items": document["items"]})
                self.assertTrue(saved["items"][0]["enabled"])
                self.assertTrue(saved["verification"]["ui-login"]["verified"])
                saved["items"][0]["steps"][0]["path"] = "/other-page"
                updated = state.update_ui_scenes({"version": saved["version"], "items": saved["items"]})
                self.assertTrue(updated["items"][0]["enabled"])
                self.assertFalse(updated["verification"]["ui-login"]["verified"])

    def test_untested_and_failed_ui_scenes_can_be_enabled_through_both_save_paths(self):
        for save_path in ("aggregate", "collection"):
            for outcome in ("untested", "failed"):
                with self.subTest(save_path=save_path, outcome=outcome), tempfile.TemporaryDirectory() as temp:
                    config = self.config()
                    config["checks"][0]["enabled"] = False
                    root = Path(temp)
                    config_path = root / "checks.json"
                    config_path.write_text(json.dumps(config))
                    state = InspectionState(config_path, root / "runs", root / "secrets.json")
                    self.assertFalse(state.ui_capabilities()["test_before_enable"])
                    if outcome == "failed":
                        failed = {"id": "ui-login", "name": "UI 登录", "type": "ui",
                                  "status": "failed", "reason": "目标元素未找到", "steps": []}
                        with patch("app.run_ui_checks", return_value=[failed]):
                            result = state.test_ui_check({"check": config["checks"][0]})
                        self.assertEqual(result["status"], "failed")
                        self.assertFalse(result["verified"])
                    if save_path == "aggregate":
                        document = state.config_document()
                        document["config"]["checks"][0]["enabled"] = True
                        saved = state.update_config({"config_version": document["config_version"],
                                                     "config": document["config"]})
                        self.assertTrue(saved["config"]["checks"][0]["enabled"])
                        self.assertFalse(saved["ui_verification"]["ui-login"]["verified"])
                    else:
                        document = state.ui_scenes_document()
                        document["items"][0]["enabled"] = True
                        saved = state.update_ui_scenes({"version": document["version"], "items": document["items"]})
                        self.assertTrue(saved["items"][0]["enabled"])
                        self.assertFalse(saved["verification"]["ui-login"]["verified"])
                    # Enablement is persisted without generating an inspection report.
                    self.assertTrue(state.repository.load()[0]["checks"][0]["enabled"])
                    self.assertEqual(list((root / "runs").glob("*.json")), [])

    def test_ui_enablement_still_rejects_invalid_steps_through_both_save_paths(self):
        for save_path in ("aggregate", "collection"):
            with self.subTest(save_path=save_path), tempfile.TemporaryDirectory() as temp:
                config = self.config()
                config["checks"][0]["enabled"] = False
                root = Path(temp)
                config_path = root / "checks.json"
                config_path.write_text(json.dumps(config))
                state = InspectionState(config_path, root / "runs", root / "secrets.json")
                if save_path == "aggregate":
                    document = state.config_document()
                    scene = document["config"]["checks"][0]
                    scene["enabled"] = True
                    scene["steps"][0]["action"] = "invalid-action"
                    with self.assertRaises(ValueError):
                        state.update_config({"config_version": document["config_version"],
                                             "config": document["config"]})
                else:
                    document = state.ui_scenes_document()
                    scene = document["items"][0]
                    scene["enabled"] = True
                    scene["steps"][0]["action"] = "invalid-action"
                    with self.assertRaises(ValueError):
                        state.update_ui_scenes({"version": document["version"], "items": document["items"]})
                self.assertFalse(state.repository.load()[0]["checks"][0]["enabled"])

    def test_business_scene_runs_full_test_and_saves_enabled_without_policy_field(self):
        config = self.config()
        scene = {
            "id": "business-flow", "type": "ui", "name": "业务操作", "category": "业务操作", "enabled": False,
            "steps": [{"id": "open-page", "description": "打开业务页面", "action": "goto", "path": "/"}] + [
                {"id": f"click-{index}", "description": "业务点击", "action": "click", "locator": {"test_id": target}}
                for index, target in enumerate(("submitButton", "saveButton", "deleteButton"))
            ],
        }
        config["checks"] = [scene]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(config))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            page = FakePage()
            browser = FakeBrowser(FakeContext(page))

            @contextmanager
            def runtime_factory():
                yield FakeRuntime(browser)

            def runner(checks, config, variables, store):
                return run_ui_checks(checks, config, variables, store, runtime_factory=runtime_factory)

            with patch("app.run_ui_checks", side_effect=runner):
                result = state.test_ui_check({"check": scene})
            self.assertTrue(result["verified"])
            self.assertEqual(len([action for action in page.actions if action[0] == "click"]), 3)
            self.assertEqual(result["check"]["evidence"]["screenshot_count"], 4)
            document = state.ui_scenes_document()
            document["items"][0]["enabled"] = True
            saved = state.update_ui_scenes({"version": document["version"], "items": document["items"]})
            self.assertTrue(saved["items"][0]["enabled"])
            self.assertNotIn("read_only", saved["items"][0])
            self.assertTrue(saved["verification"]["business-flow"]["verified"])
            self.assertEqual(list((root / "runs").glob("*.json")), [])

    def test_through_step_test_allows_enablement_without_full_verification(self):
        config = self.config()
        config["checks"][0]["enabled"] = False
        first_step_result = {
            "id": "ui-login", "name": "UI 登录", "type": "ui", "status": "passed",
            "classification": None, "steps": [], "evidence": {}, "duration_ms": 2,
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(config))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            candidate = self.check()
            candidate["enabled"] = False
            with patch("app.run_ui_checks", return_value=[first_step_result]) as runner:
                tested = state.test_ui_check(
                    {"check": candidate, "through_step_id": "open-login"}, through_step=True,
                )
            self.assertFalse(tested["verified"])
            self.assertEqual(len(runner.call_args.args[0][0]["steps"]), 1)

            document = state.config_document()
            enabled = json.loads(json.dumps(document["config"]))
            enabled["checks"][0]["enabled"] = True
            saved = state.update_config({
                "config_version": document["config_version"], "config": enabled,
            })
            self.assertTrue(saved["config"]["checks"][0]["enabled"])
            self.assertFalse(saved["ui_verification"]["ui-login"]["verified"])

    def test_run_report_combines_ui_result_with_existing_schema(self):
        config = self.config()
        ui_result = {
            "id": "ui-login", "name": "UI 登录", "type": "ui", "status": "passed",
            "classification": None, "steps": [], "evidence": {}, "duration_ms": 5,
        }
        with tempfile.TemporaryDirectory() as temp, patch("app.run_ui_checks", return_value=[ui_result]):
            report = run_inspection(
                config, "ui-version", run_id="20260928T010000Z-1234abcd",
                artifact_root=Path(temp),
            )
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"], {"passed": 1, "failed": 0, "skipped": 0})
        self.assertEqual(report["checks"][0]["type"], "ui")

    def test_preflight_runs_ui_login_without_persisting_temporary_screenshots(self):
        config = self.config()
        result = {
            "id": "ui-login", "name": "UI 登录", "type": "ui", "status": "passed",
            "classification": None,
            "steps": [{"id": "open-login", "status": "passed", "screenshot": {"artifact_id": "temporary.png"}}],
            "evidence": {"screenshot_count": 1}, "duration_ms": 7,
        }
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(config))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            with patch("app.run_ui_checks", return_value=[result]):
                preflight = state.preflight()
        self.assertEqual(preflight["status"], "passed")
        self.assertNotIn("screenshot", preflight["check"]["steps"][0])
        self.assertNotIn("screenshot_count", preflight["check"]["evidence"])

    def test_report_retention_removes_matching_ui_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            for run_id in ("20260928T010000Z-11111111", "20260928T020000Z-22222222"):
                (state.data_dir / f"{run_id}.json").write_text("{}")
                artifact = ArtifactStore(state.artifact_dir, run_id)
                artifact.reset()
                artifact.screenshot_path("ui-login", 1, "open-login").write_bytes(b"png")
            state.cleanup_reports(1)
            self.assertFalse((state.artifact_dir / "20260928T010000Z-11111111").exists())
            self.assertTrue((state.artifact_dir / "20260928T020000Z-22222222").exists())

    def test_artifact_http_route_serves_evidence_and_rejects_traversal(self):
        run_id = "20260928T010000Z-1234abcd"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            store = ArtifactStore(state.artifact_dir, run_id)
            store.reset()
            target = store.screenshot_path("ui-login", 1, "open-login")
            target.write_bytes(b"png-evidence")
            try:
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
            except PermissionError:
                self.skipTest("当前沙箱不允许绑定本地测试端口")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            try:
                with urlopen(f"{base}/api/runs/{run_id}/artifacts/ui-login/01-open-login.png") as response:
                    self.assertEqual(response.read(), b"png-evidence")
                    self.assertEqual(response.headers["Content-Type"], "image/png")
                    self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                with self.assertRaises(HTTPError) as raised:
                    urlopen(f"{base}/api/runs/{run_id}/artifacts/%2E%2E%2Fsecrets.json")
                self.assertEqual(raised.exception.code, 400)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)

    def test_login_redirect_preserves_report_deep_link(self):
        run_id = "20260929T051607Z-12c97008"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            auth = AuthManager(root / "auth.db", root / "admin.json")
            try:
                server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state, auth))
            except PermissionError:
                self.skipTest("当前沙箱不允许绑定本地测试端口")
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            target = f"/?view=reports&system=overseas-srm&kind=ui&run={run_id}"
            opener = build_opener(NoRedirect())
            try:
                with self.assertRaises(HTTPError) as raised:
                    opener.open(f"http://127.0.0.1:{server.server_port}{target}")
                self.assertEqual(raised.exception.code, 303)
                location = urlparse(raised.exception.headers["Location"])
                self.assertEqual(location.path, "/login")
                self.assertEqual(parse_qs(location.query)["next"], [target])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
