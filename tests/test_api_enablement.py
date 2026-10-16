import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import (AllowedOriginRedirect, ConfigRepository, InspectionState,
                 api_enablement_issues, build_system_openers, import_metersphere, validate_enabled_check)
from urllib.request import Request


class ApiEnablementTests(unittest.TestCase):
    def config(self):
        return {
            "system_id": "demo-system", "environment": "test", "adapter": "cas-session-v1",
            "base_url": "https://portal.example.test",
            "allowed_origins": ["https://portal.example.test", "https://app.example.test"],
            "checks": [
                {"id": "login", "name": "CAS 登录", "enabled": False, "method": "GET",
                 "path": "/login?service=http%3A%2F%2Fapp.example.test%3A80%2Fcallback",
                 "session_setup": True, "response_type": "text", "assertions": [],
                 "extract": [{"variable": "lt", "source": "body", "pattern": "value=(.+)"}],
                 "pending_arguments": [{"name": "insecure_callback"}]},
                {"id": "query", "name": "查询", "enabled": False, "method": "GET",
                 "path": "/query", "assertions": [],
                 "pending_arguments": [{"name": "business_assertion"}]},
            ],
        }

    def state(self, root):
        path = root / "demo-system.json"
        path.write_text(json.dumps(self.config()))
        ConfigRepository(path).migrate()
        return InspectionState(path, root / "runs", use_environment_fallback=False)

    def test_readiness_reports_precise_reasons_without_changing_drafts(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            before = state.repository.load()
            document = state.api_checks_document()
            self.assertIn("HTTP", document["enablement"]["login"]["reasons"][0])
            self.assertIn("业务断言", document["enablement"]["query"]["reasons"][0])
            self.assertFalse(document["enablement"]["login"]["can_enable"])
            self.assertEqual(state.repository.load(), before)

    def test_batch_reports_all_blockers_and_leaves_collection_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            before = state.api_checks_document()
            payload = copy.deepcopy(before)
            for check in payload["items"]:
                check["enabled"] = True
            with self.assertRaises(ValueError) as caught:
                state.update_api_checks(payload)
            self.assertIn("CAS 登录（login）", str(caught.exception))
            self.assertIn("查询（query）", str(caught.exception))
            self.assertEqual(state.api_checks_document(), before)

    def test_repaired_drafts_clear_only_resolved_markers_then_enable(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            payload = state.api_checks_document()
            payload["items"][0]["path"] = "/login?service=https%3A%2F%2Fapp.example.test%2Fcallback"
            payload["items"][1]["assertions"] = [{"path": "$.success", "op": "equals", "value": True}]
            drafts = state.update_api_checks(payload)
            self.assertTrue(all("pending_arguments" not in item for item in drafts["items"]))
            self.assertTrue(all(info["can_enable"] for info in drafts["enablement"].values()))
            self.assertTrue(all(not item["enabled"] for item in drafts["items"]))
            for item in drafts["items"]:
                item["enabled"] = True
            saved = state.update_api_checks(drafts)
            self.assertTrue(all(item["enabled"] for item in saved["items"]))

    def test_http_callback_cannot_be_enabled_by_deleting_the_marker(self):
        config = self.config()
        check = config["checks"][0]
        check.pop("pending_arguments")
        with self.assertRaisesRegex(ValueError, "CAS 回调地址使用 HTTP"):
            validate_enabled_check(check, config)
        check["path"] = "/login?service=http://app.example.test/callback"
        with self.assertRaisesRegex(ValueError, "CAS 回调地址使用 HTTP"):
            validate_enabled_check(check, config)

    def test_confirmed_http_callback_can_be_saved_tested_and_enabled(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            document = state.api_checks_document()
            check = document["items"][0]
            callback = "http://app.example.test:80/callback"
            original_path = check["path"]
            check["confirmed_callback_urls"] = [callback]
            saved = state.update_api_checks(document)
            self.assertNotIn("pending_arguments", saved["items"][0])
            self.assertEqual(saved["items"][0]["path"], original_path)
            self.assertTrue(saved["enablement"]["login"]["can_enable"])
            with patch("app.execute_check", return_value={"id": "login", "status": "passed"}):
                self.assertEqual(state.test_check({"check": saved["items"][0]})["status"], "passed")
            saved["items"][0]["enabled"] = True
            enabled = state.update_api_checks(saved)
            self.assertTrue(enabled["items"][0]["enabled"])
            self.assertFalse(enabled["items"][1]["enabled"])
            self.assertIn("pending_arguments", enabled["items"][1])

    def test_confirmation_does_not_allow_a_different_callback(self):
        config = self.config()
        check = config["checks"][0]
        check.pop("pending_arguments")
        check["confirmed_callback_urls"] = ["http://app.example.test:80/callback"]
        for callback in ("http://app.example.test:80/other", "http://other.example.test:80/callback"):
            with self.subTest(callback=callback):
                check["path"] = "/login?service=" + callback
                with self.assertRaisesRegex(ValueError, "需确认实际回调地址"):
                    validate_enabled_check(check, config)

    def test_invalid_confirmation_is_rejected(self):
        config = self.config()
        check = config["checks"][0]
        check.pop("pending_arguments")
        for value in ("http://app.example.test:bad/callback", "http://user:password@app.example.test/callback",
                      "http://app.example.test/callback#fragment", 123):
            with self.subTest(value=value):
                check["confirmed_callback_urls"] = [value]
                with self.assertRaisesRegex(ValueError, "confirmed_callback_urls"):
                    validate_enabled_check(check, config)

    def test_redirect_allows_only_confirmed_callback_and_cas_ticket(self):
        config = self.config()
        config["checks"][0]["confirmed_callback_urls"] = ["http://app.example.test:80/callback"]
        opener, _ = build_system_openers(config)
        handler = next(item for item in opener.handlers if isinstance(item, AllowedOriginRedirect))
        request = Request("https://portal.example.test/login")
        for target in ("http://app.example.test:80/callback", "http://app.example.test/callback?ticket=TEST"):
            with self.subTest(target=target):
                result = handler.redirect_request(request, None, 302, "Found", {}, target)
                self.assertIsNotNone(result)
                self.assertEqual(result.full_url, target)
        for target in ("http://app.example.test/other?ticket=TEST", "http://other.example.test/callback",
                       "http://app.example.test:81/callback", "http://app.example.test/callback?next=/other",
                       "http://user:password@app.example.test/callback"):
            with self.subTest(target=target):
                self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, target))

    def test_reimport_preserves_confirmation_only_for_matching_callback(self):
        config = self.config()
        config["checks"][0]["confirmed_callback_urls"] = ["http://app.example.test:80/callback"]
        step = {"name": "CAS 登录", "method": "GET", "type": "HTTPSamplerProxy",
                "url": "https://portal.example.test/login?service=http%3A%2F%2Fapp.example.test%3A80%2Fcallback"}
        def reimport():
            return import_metersphere(json.dumps({"data": [{"scenarioDefinition": {"hashTree": [step]}}]}), config)
        imported = reimport()
        self.assertNotIn("pending_arguments", imported["checks"][0])
        self.assertFalse(imported["checks"][0]["enabled"])
        step["url"] = "https://portal.example.test/login?service=http://app.example.test/other"
        imported = reimport()
        self.assertEqual(imported["checks"][0]["pending_arguments"][0]["name"], "insecure_callback")

    def test_missing_or_unapproved_callback_does_not_clear_the_marker(self):
        for path in ("/login", "/login?service=${callback}", "/login?service=https://unknown.example.test/callback"):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temp:
                state = self.state(Path(temp))
                payload = state.api_checks_document()
                payload["items"][0]["path"] = path
                saved = state.update_api_checks(payload)
                self.assertIn("pending_arguments", saved["items"][0])
                self.assertFalse(saved["enablement"]["login"]["can_enable"])

    def test_unknown_pending_arguments_remain_after_assertion_repair(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            payload = state.api_checks_document()
            check = payload["items"][1]
            check["assertions"] = [{"path": "$.success", "op": "equals", "value": True}]
            check["pending_arguments"].append({"name": "reconCode", "value": "TEST-001"})
            saved = state.update_api_checks(payload)
            self.assertEqual(saved["items"][1]["pending_arguments"], [{"name": "reconCode", "value": "TEST-001"}])
            self.assertFalse(saved["enablement"]["query"]["can_enable"])

    def test_invalid_assertion_remains_blocked_after_marker_refresh(self):
        config = self.config()
        check = config["checks"][1]
        check["assertions"] = [{"path": "$.success", "op": "unknown"}]
        self.assertIn("断言格式无效", api_enablement_issues(check, config))

    def test_test_interface_accepts_repaired_draft_without_persisting_it(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            before = state.api_checks_document()
            check = copy.deepcopy(before["items"][1])
            check["assertions"] = [{"path": "$.success", "op": "equals", "value": True}]
            with patch("app.execute_check", return_value={"id": "query", "status": "passed"}):
                result = state.test_check({"check": check})
            self.assertEqual(result["status"], "passed")
            self.assertEqual(state.api_checks_document(), before)


if __name__ == "__main__":
    unittest.main()
