import json
import base64
import os
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from sys import path as sys_path
from unittest.mock import patch

sys_path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import InspectionManager, InspectionState, build_overview_analytics, evaluate, execute_check, import_metersphere, inspection_public_url, load_config, resolve_env, run_inspection, run_inspection_with_retry, validate_config


class FakeResponse:
    status = 200
    headers = {"Content-Type": "application/json", "X-Request-Id": "mock-request-1"}

    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def read(self, limit):
        return self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class ErrorResponse(FakeResponse):
    status = 400

    def __init__(self, body):
        self.body = json.dumps(body, separators=(",", ":")).encode()


class FakeOpener:
    def open(self, request, timeout):
        if request.full_url.endswith("/login"):
            return FakeResponse({"success": True})
        if request.full_url.endswith("/list"):
            return FakeResponse({"success": True, "data": {"items": [{"id": "TEST-001", "status": "待报价"}]}})
        raise AssertionError("意外的模拟请求")


class TicketOpener:
    def open(self, request, timeout):
        if request.full_url.endswith("/login"):
            return FakeResponse({"ticket": "mock-secret-ticket"})
        self_authorization = request.get_header("Authorization")
        if request.full_url.endswith("/list") and self_authorization == "Bearer mock-secret-ticket":
            return FakeResponse({"success": True})
        raise AssertionError("未携带登录响应中的票据")


class InspectionTests(unittest.TestCase):
    def config(self):
        return {
            "system_id": "overseas-srm", "environment": "mock",
            "base_url": "http://mock-srm.local",
            "checks": [
                {"id": "login", "name": "登录", "method": "POST", "path": "/login", "body": {},
                 "read_only": True, "enabled": True, "login_precheck": True,
                 "assertions": [{"path": "$.success", "op": "equals", "value": True}]},
                {"id": "list", "name": "询价列表", "method": "POST", "path": "/list", "body": {},
                 "read_only": True, "enabled": True,
                 "assertions": [{"path": "$.success", "op": "equals", "value": True},
                                {"path": "$.data.items[0].status", "op": "equals", "value": "待报价"}]},
            ],
        }

    def test_public_report_url_is_explicitly_validated(self):
        with patch.dict("os.environ", {"INSPECTION_PUBLIC_URL": "https://inspection.example.test/console"}):
            self.assertEqual(inspection_public_url(), "https://inspection.example.test/console")
        with patch.dict("os.environ", {"INSPECTION_PUBLIC_URL": "https://user:secret@example.test/#bad"}):
            with self.assertRaisesRegex(ValueError, "INSPECTION_PUBLIC_URL"):
                inspection_public_url()

    def test_success_report_contains_business_evidence(self):
        config = self.config()
        with patch("app.build_opener", return_value=FakeOpener()):
            report = run_inspection(config, "test-version")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["counts"]["passed"], 2)
        self.assertEqual(report["checks"][1]["evidence"]["request_id"], "mock-request-1")
        self.assertEqual(len(report["checks"][1]["evidence"]["response_sha256"]), 64)

    def test_scheduled_report_keeps_trigger_metadata(self):
        config = self.config()
        with patch("app.build_opener", return_value=FakeOpener()):
            report = run_inspection(
                config, "test-version", run_id="scheduled-test",
                trigger="scheduled", scheduled_for="2026-09-23T01:00:00+00:00",
            )
        self.assertEqual(report["run_id"], "scheduled-test")
        self.assertEqual(report["trigger"], "scheduled")
        self.assertEqual(report["scheduled_for"], "2026-09-23T01:00:00+00:00")

    def test_business_assertion_failure_is_not_reported_as_success(self):
        config = self.config()
        config["checks"][1]["assertions"][1]["value"] = "已完成"
        with patch("app.build_opener", return_value=FakeOpener()):
            report = run_inspection(config, "test-version")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["checks"][1]["classification"], "assertion_failed")
        self.assertFalse(report["checks"][1]["assertions"][1]["passed"])

    def test_failed_inspection_retries_and_keeps_only_final_result(self):
        config = self.config()
        config["run_retry"] = {"enabled": True, "max_retries": 2, "delay_seconds": 30}
        outcomes = iter(("failed", "passed"))
        sleeps = []

        def run_once(_config, _version, _variables, **kwargs):
            status = next(outcomes)
            return {
                "run_id": kwargs["run_id"], "system_id": _config["system_id"],
                "environment": _config["environment"], "config_version": _version,
                "status": status, "started_at": f"attempt-{status}",
                "finished_at": f"finished-{status}", "trigger": kwargs["trigger"],
                "scheduled_for": kwargs["scheduled_for"],
                "counts": {"passed": int(status == "passed"), "failed": int(status == "failed"), "skipped": 0},
                "checks": [{"id": "list", "status": status, "classification": "timeout" if status == "failed" else None}],
            }

        report = run_inspection_with_retry(
            config, "test-version", run_id="retry-run",
            sleep_fn=sleeps.append, run_once=run_once,
        )

        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["started_at"], "attempt-failed")
        self.assertEqual(report["retry"]["attempt_count"], 2)
        self.assertTrue(report["retry"]["recovered"])
        self.assertFalse(report["retry"]["exhausted"])
        self.assertEqual(sleeps, [30])

    def test_run_retry_is_validated(self):
        config = self.config()
        config["run_retry"] = {"enabled": True, "max_retries": 6, "delay_seconds": 30}
        with self.assertRaisesRegex(ValueError, "max_retries"):
            validate_config(config)
        config["run_retry"] = {"enabled": True, "max_retries": 2, "delay_seconds": 0}
        with self.assertRaisesRegex(ValueError, "delay_seconds"):
            validate_config(config)

    def test_failed_inspection_stops_after_retry_limit(self):
        config = self.config()
        config["run_retry"] = {"enabled": True, "max_retries": 2, "delay_seconds": 30}
        attempts = []
        sleeps = []

        def always_fails(_config, version, _variables, **kwargs):
            attempts.append(kwargs["run_id"])
            number = len(attempts)
            return {
                "run_id": kwargs["run_id"], "system_id": _config["system_id"],
                "environment": _config["environment"], "config_version": version,
                "status": "failed", "started_at": f"attempt-{number}",
                "finished_at": f"finished-{number}", "trigger": kwargs["trigger"],
                "scheduled_for": kwargs["scheduled_for"],
                "counts": {"passed": 0, "failed": 1, "skipped": 0},
                "checks": [{"id": "list", "status": "failed", "classification": "timeout"}],
            }

        report = run_inspection_with_retry(
            config, "test-version", run_id="retry-run",
            sleep_fn=sleeps.append, run_once=always_fails,
        )

        self.assertEqual(report["status"], "failed")
        self.assertEqual(attempts, ["retry-run", "retry-run", "retry-run"])
        self.assertEqual(sleeps, [30, 30])
        self.assertEqual(report["retry"]["attempt_count"], 3)
        self.assertTrue(report["retry"]["exhausted"])

    def test_api_and_ui_phases_retry_independently(self):
        config = self.config()
        config["checks"].append({
            "id": "ui-scene", "name": "UI 场景", "type": "ui", "enabled": True,
        })
        config["run_retry"] = {"enabled": True, "max_retries": 2, "delay_seconds": 5}
        calls = []
        api_outcomes = iter(("failed", "passed"))

        def run_once(_config, version, _variables, **kwargs):
            target = kwargs["targets"][0]
            calls.append(target)
            status = next(api_outcomes) if target == "api" else "passed"
            return {
                "run_id": kwargs["run_id"], "system_id": _config["system_id"],
                "environment": _config["environment"], "config_version": version,
                "status": status, "started_at": f"{target}-start",
                "finished_at": f"{target}-finish", "trigger": kwargs["trigger"],
                "scheduled_for": kwargs["scheduled_for"],
                "counts": {"passed": int(status == "passed"), "failed": int(status == "failed"), "skipped": 0},
                "checks": [{"id": f"{target}-check", "type": target, "status": status}],
            }

        sleeps = []
        report = run_inspection_with_retry(
            config, "test-version", targets=["api", "ui"],
            sleep_fn=sleeps.append, run_once=run_once,
        )

        self.assertEqual(calls, ["api", "api", "ui"])
        self.assertEqual(sleeps, [5])
        self.assertEqual(report["targets"], ["api", "ui"])
        self.assertEqual(report["phase_status"], {"api": "passed", "ui": "passed"})
        self.assertEqual(report["phase_retry"]["api"]["attempt_count"], 2)
        self.assertEqual(report["phase_retry"]["ui"]["attempt_count"], 1)
        self.assertEqual(InspectionState.report_view(report, "api")["retry"]["attempt_count"], 2)
        self.assertEqual(InspectionState.report_view(report, "ui")["retry"]["attempt_count"], 1)

    def test_selected_run_target_must_have_enabled_checks(self):
        config = self.config()
        with self.assertRaisesRegex(ValueError, "所选范围"):
            run_inspection(config, "test-version", targets=["ui"])

    def test_schedule_targets_are_validated(self):
        config = self.config()
        config["schedule"] = {"targets": []}
        with self.assertRaisesRegex(ValueError, "targets"):
            validate_config(config)
        config["schedule"] = {"targets": ["browser"]}
        with self.assertRaisesRegex(ValueError, "api 和 ui"):
            validate_config(config)

    def test_state_alerts_once_after_retry_finishes(self):
        config = self.config()
        config["run_retry"] = {"enabled": True, "max_retries": 2, "delay_seconds": 30}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(config))
            state = InspectionState(config_path, root / "runs")
            finished = threading.Event()
            lease_released = threading.Event()
            release_lease = state.runtime.release_lease
            def release_and_finish(run_id):
                release_lease(run_id)
                lease_released.set()
            attempt = 0

            def run_once(_config, version, _variables, **kwargs):
                nonlocal attempt
                attempt += 1
                status = "failed" if attempt == 1 else "passed"
                return {
                    "run_id": kwargs["run_id"], "system_id": _config["system_id"],
                    "environment": _config["environment"], "config_version": version,
                    "status": status, "started_at": f"attempt-{attempt}",
                    "finished_at": f"finished-{attempt}", "trigger": kwargs["trigger"],
                    "scheduled_for": kwargs["scheduled_for"],
                    "counts": {"passed": int(status == "passed"), "failed": int(status == "failed"), "skipped": 0},
                    "checks": [{"id": "list", "name": "询价列表", "status": status}],
                }

            with patch("app.run_inspection", side_effect=run_once), \
                    patch("app.time.sleep") as sleeper, \
                    patch.object(state.alerts, "process_report", side_effect=lambda *_: finished.set()) as alert, \
                    patch.object(state.runtime, "release_lease", side_effect=release_and_finish):
                run_id = state.start_run()
                self.assertTrue(finished.wait(2), "巡检重跑未在测试时限内结束")
                self.assertTrue(lease_released.wait(2), "后台任务未完成数据库清理")

            sleeper.assert_called_once_with(30)
            alert.assert_called_once()
            final_report = json.loads((root / "runs" / f"{run_id}.json").read_text())
            self.assertEqual(final_report["status"], "passed")
            self.assertEqual(final_report["retry"]["attempt_count"], 2)
            self.assertEqual(len(list((root / "runs").glob("*.json"))), 1)

    def test_checks_can_be_enabled_without_read_only_confirmation(self):
        for legacy_value in (True, False, None):
            with self.subTest(read_only=legacy_value):
                config = self.config()
                check = config["checks"][1]
                if legacy_value is None:
                    check.pop("read_only")
                else:
                    check["read_only"] = legacy_value
                with tempfile.TemporaryDirectory() as temp:
                    path = Path(temp) / "checks.json"
                    path.write_text(json.dumps(config))
                    loaded, _ = load_config(path)
                    self.assertTrue(loaded["checks"][1]["enabled"])

    def test_check_id_errors_distinguish_format_from_duplicate(self):
        config = self.config()
        config["checks"][1]["id"] = "getSourcingItemList"
        with self.assertRaisesRegex(ValueError, "ID 格式无效.*小写字母"):
            validate_config(config)
        config = self.config()
        config["checks"][1]["id"] = "login"
        with self.assertRaisesRegex(ValueError, "ID 已存在"):
            validate_config(config)

    def test_unconfigured_console_refuses_manual_run(self):
        config = self.config()
        for check in config["checks"]:
            check["enabled"] = False
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checks.json"
            path.write_text(json.dumps(config))
            state = InspectionState(path, Path(temp) / "runs")
            with self.assertRaisesRegex(ValueError, "尚无"):
                state.start_run()

    def test_login_ticket_is_reused_without_entering_report(self):
        config = self.config()
        config["checks"][0]["assertions"] = []
        config["checks"][0]["extract"] = [{"variable": "ticket", "path": "$.ticket"}]
        config["checks"][1]["headers"] = {"Authorization": "Bearer ${ticket}"}
        config["checks"][1]["assertions"] = [{"path": "$.success", "op": "equals", "value": True}]
        with patch("app.build_opener", return_value=TicketOpener()):
            report = run_inspection(config, "test-version")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["checks"][0]["assertions"], [])
        self.assertNotIn("mock-secret-ticket", json.dumps(report))

    def test_missing_ticket_skips_business_checks(self):
        config = self.config()
        config["checks"][0]["assertions"] = []
        config["checks"][0]["extract"] = [{"variable": "ticket", "path": "$.ticket"}]
        with patch("app.build_opener", return_value=FakeOpener()):
            report = run_inspection(config, "test-version")
        self.assertEqual([item["status"] for item in report["checks"]], ["failed", "skipped"])

    def test_login_form_applies_runtime_encoding_without_mutating_credentials(self):
        from urllib.parse import parse_qs
        config = self.config()
        check = config["checks"][0]
        check.update(body_encoding="form", body={
            "portal_username": "${SRM_USERNAME}",
            "username": "${SRM_USERNAME|lower}",
            "password": "${SRM_PASSWORD|base64}",
        })
        variables = {"SRM_USERNAME": "FixtureUser", "SRM_PASSWORD": "secret+&="}
        received = {}

        class FormOpener:
            def open(self, request, timeout):
                received.update(parse_qs(request.data.decode()))
                self_content_type = request.get_header("Content-type")
                assert self_content_type == "application/x-www-form-urlencoded"
                return FakeResponse({"success": True})

        result = execute_check(check, config, FormOpener(), variables)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(received, {"portal_username": ["FixtureUser"], "username": ["fixtureuser"],
                                   "password": [base64.b64encode(b"secret+&=").decode()]})
        self.assertEqual(variables["SRM_PASSWORD"], "secret+&=")
        self.assertEqual(check["body"]["password"], "${SRM_PASSWORD|base64}")
        self.assertNotIn(variables["SRM_PASSWORD"], json.dumps(result))
        self.assertNotIn(received["password"][0], json.dumps(result))

    def test_runtime_transform_preserves_plain_variable_types_and_validates_inputs(self):
        self.assertEqual(resolve_env("${count}", {"count": 42}), 42)
        self.assertEqual(resolve_env("Bearer ${name|lower}", {"name": "USER"}), "Bearer user")
        with self.assertRaisesRegex(ValueError, "需要字符串"):
            resolve_env("${count|base64}", {"count": 42})
        with self.assertRaisesRegex(ValueError, "不支持转换"):
            resolve_env("${name|unknown}", {"name": "USER"})
        with self.assertRaisesRegex(ValueError, "缺少运行变量"):
            resolve_env("${missing|base64}", {})

    def test_login_http_error_keeps_safe_server_diagnostic(self):
        config = self.config()
        config["checks"][0]["login_precheck"] = True

        class LoginErrorOpener:
            def open(self, request, timeout):
                return ErrorResponse({
                    "code": 100106211,
                    "message": "Incorrect username or password.",
                    "debug": "must not enter the report",
                })

        result = execute_check(config["checks"][0], config, LoginErrorOpener(), {"SRM_PASSWORD": "secret"})
        self.assertEqual(result["classification"], "authentication_failed")
        self.assertEqual(result["evidence"]["server_code"], 100106211)
        self.assertEqual(result["evidence"]["server_message"], "Incorrect username or password.")
        self.assertNotIn("debug", json.dumps(result))

    def test_business_check_still_requires_assertions(self):
        config = self.config()
        config["checks"][1]["assertions"] = []
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checks.json"
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "至少需要"):
                load_config(path)

    def test_unresolved_export_arguments_block_enablement(self):
        config = self.config()
        config["checks"][1]["pending_arguments"] = [{"name": "reconCode", "value": "TEST-001"}]
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checks.json"
            path.write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "参数的位置"):
                load_config(path)

    def test_imported_assertions_match_all_response_samples(self):
        root = Path(__file__).resolve().parents[1]
        config, _ = load_config(root / "tests" / "fixtures" / "checks.json")
        self.assertEqual(config["checks"][0]["assertions"], [])
        expected_rules = [
            {"path": "$.code", "op": "equals", "value": 100000000},
            {"path": "$.message", "op": "equals", "value": "操作成功"},
        ]
        samples = (root / "tests" / "fixtures" / "responses.json").read_text()
        decoder = json.JSONDecoder()
        position = 0
        for check in config["checks"]:
            position = samples.index("{", position)
            response, position = decoder.raw_decode(samples, position)
            with self.subTest(check=check["id"]):
                if not check.get("login_precheck"):
                    self.assertEqual(check["assertions"], expected_rules)
                self.assertTrue(all(item["passed"] for item in evaluate(response, check["assertions"])))

    def test_payment_detail_bodies_are_enabled_without_recon_code(self):
        root = Path(__file__).resolve().parents[1]
        config, _ = load_config(root / "tests" / "fixtures" / "checks.json")
        checks = {item["id"]: item for item in config["checks"]}
        for check_id, field, value in (
            ("advance-payment-detail", "advancePayReqInfo", 101),
            ("payment-detail", "payRequestInfo", 202),
        ):
            with self.subTest(check=check_id):
                item = checks[check_id]
                self.assertTrue(item["enabled"])
                self.assertNotIn("pending_arguments", item)
                self.assertEqual(item["body"], {
                    "entity": {field: value}, "isTotalSum": False, "paging": False,
                    "pageNo": 1, "pageSize": 20,
                })

    def test_reconciliation_code_is_sent_as_form_body(self):
        root = Path(__file__).resolve().parents[1]
        config, _ = load_config(root / "tests" / "fixtures" / "checks.json")
        check = next(item for item in config["checks"] if item["id"] == "reconciliation-invoice-detail")

        class FormOpener:
            def open(self, request, timeout):
                headers = {key.lower(): value for key, value in request.header_items()}
                self_request_body = request.data
                assert headers["content-type"] == "application/x-www-form-urlencoded"
                assert self_request_body == b"reconCode=TEST-RECON-001"
                return FakeResponse({"code": 100000000, "message": "操作成功"})

        result = execute_check(check, config, FormOpener(), {"ticket": "offline-ticket"})
        self.assertEqual(result["status"], "passed")

    def test_configuration_update_is_versioned_and_credentials_are_masked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            document = state.config_document()
            document["config"]["environment"] = "edited"
            document["config"]["run_retry"] = {"enabled": True, "max_retries": 2, "delay_seconds": 30}
            saved = state.update_config({
                "config_version": document["config_version"], "config": document["config"],
                "credentials": {
                    "username": "inspector", "password": "top-secret", "client_id": "web-client",
                    "ui_username": "ui-inspector", "ui_password": "ui-top-secret",
                    "webhook_url": "https://hooks.example.test/private-token",
                    "dingtalk_secret": "mock-dingtalk-secret",
                },
            })
            self.assertEqual(saved["config"]["environment"], "edited")
            self.assertEqual(saved["credentials"], {
                "account": "", "username": "inspector", "client_id": "web-client",
                "password_configured": True, "ui_username": "ui-inspector",
                "ui_password_configured": True, "webhook_configured": True,
                "dingtalk_secret_configured": True,
            })
            self.assertNotIn("top-secret", json.dumps(saved))
            self.assertNotIn("ui-top-secret", json.dumps(saved))
            self.assertNotIn("private-token", json.dumps(saved))
            self.assertNotIn("mock-dingtalk-secret", json.dumps(saved))
            self.assertEqual(stat.S_IMODE(os.stat(root / "secrets.json").st_mode), 0o600)
            audit = json.loads(next((root / "config-audit").glob("*.json")).read_text())
            self.assertTrue(audit["run_retry_changed"])
            with self.assertRaisesRegex(RuntimeError, "重新加载"):
                state.update_config({"config_version": document["config_version"], "config": document["config"]})

    def test_new_interface_can_be_saved_as_disabled_safe_draft(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            document = state.config_document()
            document["config"]["checks"].append({
                "id": "supplier-detail", "name": "供应商详情", "category": "供应商主数据",
                "method": "POST", "path": "/supplier/detail", "headers": {}, "body": {},
                "expected_status": 200, "assertions": [], "extract": [],
                "timeout_seconds": 10, "read_only": False, "alert_enabled": False,
                "enabled": False, "severity": "P2",
            })
            saved = state.update_config({
                "config_version": document["config_version"], "config": document["config"],
            })
            draft = saved["config"]["checks"][-1]
            self.assertFalse(draft["enabled"])
            self.assertNotIn("read_only", draft)
            self.assertFalse(draft["alert_enabled"])

    def test_single_interface_test_reuses_session_without_writing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.config()
            config["checks"][0]["assertions"] = []
            config["checks"][0]["extract"] = [{"variable": "ticket", "path": "$.ticket"}]
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(config))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            candidate = {
                "id": "supplier-detail", "name": "供应商详情", "category": "供应商主数据",
                "method": "POST", "path": "/list", "headers": {"Authorization": "Bearer ${ticket}"},
                "body": {}, "expected_status": 200,
                "assertions": [{"path": "$.success", "op": "equals", "value": True}],
                "extract": [], "timeout_seconds": 10, "read_only": True,
                "alert_enabled": False, "enabled": True, "severity": "P2",
            }
            opener = TicketOpener()
            with patch("app.build_system_openers", return_value=(opener, opener)):
                result = state.test_check({"check": candidate})
            self.assertEqual(result["status"], "passed")
            self.assertEqual([item["id"] for item in result["session_checks"]], ["login"])
            self.assertEqual(result["check"]["id"], "supplier-detail")
            self.assertEqual(list((root / "runs").glob("*.json")), [])

    def test_single_interface_test_allows_write_methods_without_confirmation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            candidate = {
                "id": "unsafe-check", "name": "未确认接口", "method": "POST", "path": "/list",
                "body": {}, "assertions": [{"path": "$.success", "op": "equals", "value": True}],
                "read_only": False,
            }
            requests = []

            class WriteOpener(FakeOpener):
                def open(self, request, timeout):
                    if request.full_url.endswith("/list"):
                        requests.append(request)
                    return super().open(request, timeout)

            opener = WriteOpener()
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                for encoding in ("json", "form"):
                    with self.subTest(method=method, encoding=encoding):
                        candidate["method"] = method
                        candidate["body_encoding"] = encoding
                        candidate["body"] = {"id": "TEST-001"}
                        with patch("app.build_system_openers", return_value=(opener, opener)):
                            result = state.test_check({"check": candidate})
                        self.assertEqual(result["status"], "passed")
                        self.assertEqual(requests[-1].get_method(), method)
                        if encoding == "form":
                            self.assertEqual(requests[-1].data, b"id=TEST-001")
                        else:
                            self.assertEqual(json.loads(requests[-1].data), candidate["body"])
            self.assertEqual(list((root / "runs").glob("*.json")), [])
            document = state.config_document()
            document["config"]["checks"].append({**candidate, "enabled": True})
            saved = state.update_config({
                "config_version": document["config_version"], "config": document["config"],
            })
            self.assertTrue(saved["config"]["checks"][-1]["enabled"])

    def test_bodyless_write_and_head_responses_check_http_status(self):
        for method, status in (("DELETE", 204), ("PUT", 205), ("HEAD", 200)):
            with self.subTest(method=method, status=status):
                config = self.config()
                check = config["checks"][1]
                check.pop("read_only")
                check.update(method=method, expected_status=status, assertions=[])
                validate_config(config)
                response = FakeResponse({})
                response.status = status
                response.body = b""

                class Opener:
                    def open(self, request, timeout):
                        return response

                result = execute_check(check, config, Opener())
                self.assertEqual(result["status"], "passed")
                self.assertEqual(result["evidence"]["http_status"], status)
                check["assertions"] = [{"path": "$.success", "op": "equals", "value": True}]
                result = execute_check(check, config, Opener())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["classification"], "automation_contract_changed")

    def test_api_documents_hide_legacy_policy_and_collection_allows_write_enablement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs", root / "secrets.json")
            document = state.api_checks_document()
            self.assertTrue(all("read_only" not in item for item in document["items"]))
            document["items"][1]["method"] = "DELETE"
            saved = state.update_api_checks({"version": document["version"], "items": document["items"]})
            self.assertTrue(saved["items"][1]["enabled"])
            self.assertEqual(saved["items"][1]["method"], "DELETE")
            self.assertNotIn("read_only", saved["items"][1])
            self.assertTrue(all("read_only" not in item for item in state.config_document()["config"]["checks"]))

    def test_invalid_schedule_is_rejected(self):
        config = self.config()
        config["schedule"] = {
            "enabled": True, "mode": "daily", "timezone": "Asia/Shanghai",
            "interval_minutes": 15, "daily_times": ["25:00"],
            "misfire_grace_minutes": 30,
        }
        with self.assertRaisesRegex(ValueError, "HH:MM"):
            validate_config(config)

    def test_success_notification_switch_must_be_boolean(self):
        config = self.config()
        config["alerts"] = {"notify_on_success": "yes"}
        with self.assertRaisesRegex(ValueError, "notify_on_success"):
            validate_config(config)

    def test_report_base_url_must_be_a_safe_http_site(self):
        config = self.config()
        config["alerts"] = {"report_base_url": "https://inspection.example.test/console"}
        validate_config(config)
        config["alerts"]["report_base_url"] = "https://user:secret@example.test/?token=bad"
        with self.assertRaisesRegex(ValueError, "巡检平台访问地址"):
            validate_config(config)

    def test_metersphere_import_creates_editable_safe_draft(self):
        root = Path(__file__).resolve().parents[1]
        current, _ = load_config(root / "tests" / "fixtures" / "checks.json")
        steps = [
            {"name": "GSRM登录", "method": "POST", "url": "https://srm.example/login",
             "body": {"raw": json.dumps({"userName": "plain", "password": "plain", "clientId": "plain"})},
             "arguments": [], "headers": []},
            {"name": "对账开票详情", "method": "POST", "url": "https://srm.example/invoice",
             "body": {"raw": ""}, "arguments": [{"name": "reconCode", "value": "TEST", "enable": True, "valid": True}],
             "headers": []},
            {"name": "预付款单详情", "method": "POST", "url": "https://srm.example/advance",
             "body": {"raw": json.dumps({"entity": {"id": 1}})}, "arguments": [], "headers": []},
        ]
        exported = {"data": [{"scenarioDefinition": json.dumps({"hashTree": steps})}]}
        imported = import_metersphere(json.dumps(exported), current)
        self.assertEqual(len(imported["checks"]), 3)
        self.assertEqual(imported["checks"][0]["body"]["password"], "${SRM_PASSWORD}")
        self.assertEqual(imported["checks"][1]["body_encoding"], "form")
        self.assertNotIn("body_encoding", imported["checks"][2])

    def test_nested_cas_import_includes_write_operation_as_disabled_draft(self):
        current = self.config()
        current["system_id"] = "new-srm"
        current["base_url"] = "https://ubd.example.test"
        current["adapter"] = "cas-session-v1"
        current["allowed_origins"] = ["https://portal.example.test", "https://ubd.example.test"]
        nested = {
            "hashTree": [{"type": "scenario", "hashTree": [
                {"name": "CAS 登录", "type": "HTTPSamplerProxy", "method": "GET",
                 "url": "https://portal.example.test/cas/login", "body": {}, "arguments": [], "headers": []},
                {"name": "新建等级模板", "type": "HTTPSamplerProxy", "method": "POST",
                 "url": "https://ubd.example.test/api/level/save", "body": {"raw": "{}"},
                 "arguments": [], "headers": []},
            ]}]
        }
        exported = {"data": [{"scenarioDefinition": json.dumps(nested)}]}
        imported = import_metersphere(json.dumps(exported), current)
        self.assertEqual(len(imported["checks"]), 2)
        self.assertTrue(all(not item["enabled"] for item in imported["checks"]))
        self.assertEqual(imported["checks"][1]["path"], "/api/level/save")
        self.assertEqual(imported["base_url"], "https://ubd.example.test")
        self.assertEqual(imported["onboarding"]["excluded_steps"], [])

    def test_reference_metersphere_files_generate_safe_system_drafts(self):
        root = Path(__file__).resolve().parents[1]
        cases = (
            ("srm", "Metersphere_Scenario_业务线：数科-SRM (1).json", 10),
            ("new-srm", "Metersphere_Scenario_业务线：数科-SRM (2).json", 21),
        )
        missing = [source_name for _, source_name, _ in cases if not (root / source_name).exists()]
        if missing:
            self.skipTest(f"未提供外部 MeterSphere 验收资料: {', '.join(missing)}")
        for system_id, source_name, expected_count in cases:
            with self.subTest(system=system_id):
                current, _ = load_config(root / "config" / "systems" / f"{system_id}.json")
                imported = import_metersphere((root / source_name).read_text(), current)
                self.assertEqual(len(imported["checks"]), expected_count)
                self.assertFalse(any(item.get("enabled") for item in imported["checks"]))
                raw = json.dumps(imported, ensure_ascii=False)
                self.assertNotIn('"Authorization": "Bearer ey', raw)
                self.assertNotRegex(raw, r'"Cookie"\s*:\s*"[^$]')

        old_srm = import_metersphere(
            (root / cases[0][1]).read_text(),
            load_config(root / "config" / "systems" / "srm.json")[0],
        )
        login = old_srm["checks"][0]
        self.assertEqual(login["body"]["elsAccount"], "${SRM_ACCOUNT}")
        self.assertEqual(login["body"]["elsSubAccount"], "${SRM_USERNAME}")
        self.assertEqual(login["body"]["elsSubAccountPassword"], "${SRM_PASSWORD}")
        self.assertEqual(login["extract"], [{"variable": "token", "path": "$.data.token"}])

        new_srm = import_metersphere(
            (root / cases[1][1]).read_text(),
            load_config(root / "config" / "systems" / "new-srm.json")[0],
        )
        excluded = {item["name"]: item["reason"] for item in new_srm["onboarding"]["excluded_steps"]}
        self.assertNotIn("新建等级模版", excluded)
        self.assertEqual(excluded["生产-退出登录"], "cleanup")
        self.assertIn("新建等级模版", {item["name"] for item in new_srm["checks"]})
        self.assertTrue(any(item.get("session_setup") for item in new_srm["checks"]))
        self.assertTrue(any(item.get("body") for item in new_srm["checks"] if not item.get("session_setup")))

    def test_extended_meter_assertion_operators(self):
        data = {"count": 3, "items": ["ready"], "code": "ABC-123"}
        rules = [
            {"path": "$.count", "op": "greater_than", "value": 2},
            {"path": "$.items", "op": "contains", "value": "ready"},
            {"path": "$.code", "op": "matches", "value": r"ABC-\d+"},
        ]
        self.assertTrue(all(item["passed"] for item in evaluate(data, rules)))

    def test_manager_isolates_system_state_and_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_root = root / "config"
            (config_root / "systems").mkdir(parents=True)
            systems = []
            for system_id in ("alpha-srm", "beta-srm"):
                config = self.config()
                config["system_id"] = system_id
                config["environment"] = "mock"
                path = config_root / "systems" / f"{system_id}.json"
                path.write_text(json.dumps(config))
                systems.append({"system_id": system_id, "config": f"systems/{system_id}.json"})
            registry = config_root / "systems.json"
            registry.write_text(json.dumps({
                "default_system_id": "alpha-srm", "max_parallel_runs": 1, "systems": systems,
            }))
            manager = InspectionManager(registry, root / "data")
            alpha = manager.get_state("alpha-srm")
            beta = manager.get_state("beta-srm")
            alpha.credentials.update({"username": "alpha-user", "password": "alpha-secret"})
            self.assertEqual(alpha.credentials.public_status()["username"], "alpha-user")
            self.assertEqual(beta.credentials.public_status()["username"], "")
            self.assertNotEqual(alpha.runtime.path, beta.runtime.path)
            self.assertEqual([item["system_id"] for item in manager.list_systems()], ["alpha-srm", "beta-srm"])

    def test_report_retention_keeps_newest_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_path = root / "checks.json"
            config_path.write_text(json.dumps(self.config()))
            state = InspectionState(config_path, root / "runs")
            for name in ("20260101.json", "20260102.json", "20260103.json"):
                (root / "runs" / name).write_text("{}")
            state.cleanup_reports(2)
            self.assertEqual(sorted(path.name for path in (root / "runs").glob("*.json")), ["20260102.json", "20260103.json"])

    def test_report_views_separate_api_and_ui_evidence(self):
        report = {
            "run_id": "20260928T100806Z-87cb6cdb", "status": "failed",
            "checks": [
                {"id": "api-ok", "type": "api", "status": "passed", "duration_ms": 100},
                {"id": "api-fail", "type": "api", "status": "failed", "duration_ms": 500},
                {
                    "id": "ui-scene", "type": "ui", "status": "passed", "duration_ms": 900,
                    "evidence": {"screenshot_count": 2},
                    "steps": [{"status": "passed"}, {"status": "failed"}],
                },
            ],
        }

        api_report = InspectionState.report_view(report, "api")
        ui_report = InspectionState.report_view(report, "ui")

        self.assertEqual([item["id"] for item in api_report["checks"]], ["api-ok", "api-fail"])
        self.assertEqual(api_report["counts"], {"passed": 1, "failed": 1, "skipped": 0})
        self.assertEqual((api_report["average_duration_ms"], api_report["p95_duration_ms"]), (300, 500))
        self.assertEqual([item["id"] for item in ui_report["checks"]], ["ui-scene"])
        self.assertEqual(ui_report["status"], "passed")
        self.assertEqual((ui_report["screenshot_count"], ui_report["step_count"], ui_report["failed_step_count"]), (2, 2, 1))

    def test_overview_analytics_aggregates_runs_categories_and_latency(self):
        config = self.config()
        config["checks"][0]["category"] = "访问与会话"
        config["checks"][1]["category"] = "询价管理"
        reports = [
            {
                "run_id": "run-2", "status": "failed", "trigger": "scheduled",
                "started_at": "2026-09-23T02:00:00+00:00", "finished_at": "2026-09-23T02:00:03+00:00",
                "counts": {"passed": 1, "failed": 1, "skipped": 0},
                "checks": [
                    {"id": "login", "name": "登录", "status": "passed", "duration_ms": 200},
                    {"id": "list", "name": "询价列表", "status": "failed", "duration_ms": 800},
                ],
            },
            {
                "run_id": "run-1", "status": "passed", "trigger": "manual",
                "started_at": "2026-09-23T01:00:00Z", "finished_at": "2026-09-23T01:00:02Z",
                "counts": {"passed": 2, "failed": 0, "skipped": 0},
                "checks": [
                    {"id": "login", "name": "登录", "status": "passed", "duration_ms": 100},
                    {"id": "list", "name": "询价列表", "status": "passed", "duration_ms": 500},
                ],
            },
        ]

        analytics = build_overview_analytics(config, reports)

        self.assertEqual([item["run_id"] for item in analytics["runs"]], ["run-1", "run-2"])
        self.assertEqual([item["pass_rate"] for item in analytics["runs"]], [100.0, 50.0])
        self.assertEqual([item["duration_ms"] for item in analytics["runs"]], [600, 1000])
        inquiry = next(item for item in analytics["categories"] if item["name"] == "询价管理")
        self.assertEqual((inquiry["passed"], inquiry["failed"], inquiry["pass_rate"]), (1, 1, 50.0))
        self.assertEqual(analytics["slow_checks"][0]["id"], "list")
        self.assertEqual(analytics["slow_checks"][0]["average_ms"], 650)
        self.assertEqual(analytics["slow_checks"][0]["failures"], 1)

    def test_overview_analytics_handles_empty_and_incomplete_reports(self):
        self.assertEqual(build_overview_analytics(self.config(), []), {
            "runs": [], "categories": [], "slow_checks": [],
        })
        analytics = build_overview_analytics(self.config(), [{
            "run_id": "incomplete", "status": "failed", "started_at": "not-a-date",
            "counts": {"failed": "1"}, "checks": [{"id": "list", "status": "failed", "duration_ms": "40"}],
        }])
        self.assertEqual(analytics["runs"][0]["duration_ms"], 40)
        self.assertEqual(analytics["runs"][0]["pass_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
