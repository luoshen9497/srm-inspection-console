import base64
import hashlib
import hmac
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from operations import AlertEngine, RuntimeStore, ScheduleEngine, WebhookNotifier, next_schedule_time


class WebhookResponse:
    status = 200

    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def read(self, _limit):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = RuntimeStore(Path(self.temp.name) / "runtime.db")
        self.engine = AlertEngine(self.store)
        self.config = {
            "system_id": "overseas-srm", "display_name": "GSRM",
            "environment": "test",
            "alerts": {
                "enabled": True,
                "failure_threshold": 2,
                "recovery_threshold": 1,
                "repeat_interval_minutes": 60,
                "default_severity": "P2",
            },
        }

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def report(status, run_id, check_status="failed", classification="timeout"):
        return {
            "run_id": run_id,
            "status": status,
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "checks": [{
                "id": "purchase-list", "name": "采购申请列表", "status": check_status,
                "classification": classification,
                "reason": "mock failure" if check_status == "failed" else None,
            }],
        }

    def test_incident_opens_after_threshold_and_recovers_once(self):
        self.engine.process_report(self.report("failed", "run-1"), self.config)
        self.assertEqual(self.store.list_incidents(), [])
        self.assertEqual(self.store.list_notifications(), [])

        self.engine.process_report(self.report("failed", "run-2"), self.config)
        incidents = self.store.list_incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "open")
        self.assertEqual([item["event_type"] for item in self.store.list_notifications()], ["alert"])

        self.engine.process_report(self.report("passed", "run-3", "passed", None), self.config)
        incidents = self.store.list_incidents()
        self.assertEqual(incidents[0]["status"], "resolved")
        self.assertEqual(
            sorted(item["event_type"] for item in self.store.list_notifications()),
            ["alert", "recovery"],
        )
        self.engine.process_report(self.report("passed", "run-4", "passed", None), self.config)
        self.assertEqual(len(self.store.list_notifications()), 2)

    def test_success_notification_is_configurable(self):
        self.config["alerts"]["notify_on_success"] = True
        scheduled = self.report("passed", "scheduled-1", "passed", None)
        scheduled["trigger"] = "scheduled"
        scheduled["counts"] = {"passed": 1, "failed": 0, "skipped": 0}
        self.engine.process_report(scheduled, self.config)
        notifications = self.store.list_notifications()
        self.assertEqual([item["event_type"] for item in notifications], ["success"])
        payload = self.store.due_notifications()[0]["payload"]
        self.assertEqual(payload["run_id"], "scheduled-1")
        self.assertEqual(payload["counts"]["passed"], 1)

    def test_manual_success_notification_is_sent(self):
        self.config["alerts"]["notify_on_success"] = True
        manual = self.report("passed", "manual-1", "passed", None)
        manual["trigger"] = "manual"
        manual["counts"] = {"passed": 1, "failed": 0, "skipped": 0}
        self.engine.process_report(manual, self.config)
        notifications = self.store.list_notifications()
        self.assertEqual([item["event_type"] for item in notifications], ["success"])
        payload = self.store.due_notifications()[0]["payload"]
        self.assertEqual(payload["run_id"], "manual-1")
        self.assertEqual(payload["title"], "[成功] SRM 巡检通过")

    def test_notification_payload_has_report_deep_link_and_summary(self):
        self.config["alerts"]["notify_on_success"] = True
        self.config["alerts"]["report_base_url"] = "https://configured.example.test/console"
        engine = AlertEngine(self.store, lambda: "https://fallback.example.test")
        report = self.report("passed", "20260929T051607Z-12c97008", "passed", None)
        report.update({
            "trigger": "manual", "targets": ["ui"],
            "started_at": "2026-09-29T05:16:07+00:00",
            "finished_at": "2026-09-29T05:16:27+00:00",
            "counts": {"passed": 2, "failed": 0, "skipped": 0},
            "retry": {"attempt_count": 1},
        })
        report["checks"][0].update({
            "type": "ui", "duration_ms": 18700,
            "evidence": {"screenshot_count": 7},
        })
        engine.process_report(report, self.config)
        payload = self.store.due_notifications()[0]["payload"]
        link = urlparse(payload["report_url"])
        self.assertEqual(link.netloc, "configured.example.test")
        self.assertEqual(link.path, "/console/")
        self.assertEqual(parse_qs(link.query), {
            "view": ["reports"], "system": ["overseas-srm"],
            "kind": ["ui"], "run": ["20260929T051607Z-12c97008"],
        })
        self.assertEqual(payload["display_name"], "GSRM")
        self.assertEqual(payload["duration_ms"], 18700)
        self.assertEqual(payload["screenshot_count"], 7)

    def test_failure_notification_includes_failed_step_and_retry_count(self):
        self.config["alerts"]["failure_threshold"] = 1
        engine = AlertEngine(self.store, lambda: "https://inspection.example.test")
        report = self.report("failed", "20260929T051607Z-12c97008")
        report.update({
            "trigger": "scheduled", "targets": ["ui"],
            "counts": {"passed": 1, "failed": 1, "skipped": 0},
            "retry": {"attempt_count": 3}, "phase_status": {"ui": "failed"},
        })
        report["checks"][0].update({
            "type": "ui", "steps": [
                {"id": "open-list", "description": "打开采购申请列表", "status": "passed"},
                {"id": "wait-table", "description": "等待列表加载", "status": "failed"},
            ],
        })
        engine.process_report(report, self.config)
        payload = self.store.due_notifications()[0]["payload"]
        self.assertEqual(payload["failed_step"], "等待列表加载")
        self.assertEqual(payload["attempt_count"], 3)
        _, body = WebhookNotifier._dingtalk_request(
            "https://oapi.dingtalk.com/robot/send?access_token=redacted", payload, ""
        )
        self.assertEqual(body["msgtype"], "actionCard")
        self.assertEqual(body["actionCard"]["singleTitle"], "在浏览器查看失败证据")
        self.assertIn("失败步骤：等待列表加载", body["actionCard"]["text"])
        self.assertIn("自动重试：2 次", body["actionCard"]["text"])

    def test_success_is_silent_when_option_is_off(self):
        self.config["alerts"]["notify_on_success"] = False
        scheduled = self.report("passed", "scheduled-1", "passed", None)
        scheduled["trigger"] = "scheduled"
        scheduled["counts"] = {"passed": 1, "failed": 0, "skipped": 0}
        self.engine.process_report(scheduled, self.config)
        self.assertEqual(self.store.list_notifications(), [])

    def test_skipped_checks_do_not_create_cascade_incidents(self):
        report = self.report("failed", "run-1")
        report["checks"] = [
            {"id": "login", "name": "登录", "status": "failed", "classification": "authentication_failed", "reason": "bad credentials"},
            {"id": "purchase-list", "name": "采购申请列表", "status": "skipped", "classification": "authentication_failed"},
        ]
        self.config["alerts"]["failure_threshold"] = 1
        self.engine.process_report(report, self.config)
        self.assertEqual([item["check_id"] for item in self.store.list_incidents()], ["login"])

    def test_check_can_disable_alerting(self):
        self.config["alerts"]["failure_threshold"] = 1
        report = self.report("failed", "run-1")
        report["checks"][0]["alert_enabled"] = False
        self.engine.process_report(report, self.config)
        self.assertEqual(self.store.list_incidents(), [])

    def test_runner_exception_has_independent_incident(self):
        self.config["alerts"]["failure_threshold"] = 1
        report = {"run_id": "run-error", "status": "failed", "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "checks": [], "error": "巡检执行异常"}
        self.engine.process_report(report, self.config)
        incident = self.store.list_incidents()[0]
        self.assertEqual(incident["check_id"], "__runner__")
        self.assertEqual(incident["severity"], "P1")

    def test_interval_and_daily_next_schedule(self):
        start = datetime(2026, 9, 23, 1, 0, tzinfo=timezone.utc)
        self.assertEqual(
            next_schedule_time(start, {"mode": "interval", "interval_minutes": 15}),
            start + timedelta(minutes=15),
        )
        daily = next_schedule_time(start, {
            "mode": "daily", "timezone": "Asia/Shanghai", "daily_times": ["09:30"]
        })
        self.assertEqual(daily, datetime(2026, 9, 23, 1, 30, tzinfo=timezone.utc))

    def test_execution_lease_prevents_overlapping_processes(self):
        self.assertTrue(self.store.claim_lease("run-1", "manual", 300))
        second_store = RuntimeStore(Path(self.temp.name) / "runtime.db")
        self.assertFalse(second_store.claim_lease("run-2", "scheduled", 300))
        self.store.release_lease("run-1")
        self.assertTrue(second_store.claim_lease("run-2", "scheduled", 300))

    def test_due_schedule_starts_one_scheduled_run(self):
        now = datetime(2026, 9, 23, 1, 0, tzinfo=timezone.utc)
        config = {
            **self.config,
            "schedule": {"enabled": True, "mode": "interval", "timezone": "Asia/Shanghai", "interval_minutes": 15, "misfire_grace_minutes": 30},
        }
        calls = []
        notifier = WebhookNotifier(self.store, lambda: "")
        scheduler = ScheduleEngine(lambda: (config, "v1"), self.store,
                                   lambda **kwargs: calls.append(kwargs) or "scheduled-run",
                                   self.engine, notifier)
        scheduler.tick(now)
        status = self.store.schedule_status()
        due = datetime.fromisoformat(status["next_run_at"])
        scheduler.tick(due)
        self.assertEqual(calls, [{"trigger": "scheduled", "scheduled_for": due.isoformat(timespec="seconds")}])
        self.assertEqual(self.store.schedule_status()["last_outcome"], "started")

    def test_schedule_forwards_configured_run_targets(self):
        now = datetime(2026, 9, 23, 1, 0, tzinfo=timezone.utc)
        config = {
            **self.config,
            "schedule": {
                "enabled": True, "mode": "interval", "timezone": "Asia/Shanghai",
                "interval_minutes": 15, "misfire_grace_minutes": 30,
                "targets": ["ui"],
            },
        }
        calls = []
        scheduler = ScheduleEngine(
            lambda: (config, "v1"), self.store,
            lambda **kwargs: calls.append(kwargs) or "scheduled-run",
            self.engine, WebhookNotifier(self.store, lambda: ""),
        )
        scheduler.tick(now)
        due = datetime.fromisoformat(self.store.schedule_status()["next_run_at"])
        scheduler.tick(due)
        self.assertEqual(calls[0]["targets"], ["ui"])

    def test_schedule_outside_grace_is_recorded_as_missed(self):
        now = datetime(2026, 9, 23, 2, 0, tzinfo=timezone.utc)
        config = {
            **self.config,
            "alerts": {**self.config["alerts"], "failure_threshold": 1},
            "schedule": {"enabled": True, "mode": "interval", "timezone": "Asia/Shanghai", "interval_minutes": 15, "misfire_grace_minutes": 30},
        }
        calls = []
        scheduler = ScheduleEngine(
            lambda: (config, "v1"), self.store,
            lambda **kwargs: calls.append(kwargs) or "unexpected",
            self.engine, WebhookNotifier(self.store, lambda: ""),
        )
        scheduler.tick(now - timedelta(minutes=60))
        scheduler.tick(now)
        self.assertEqual(calls, [])
        self.assertEqual(self.store.schedule_status()["last_outcome"], "misfire_skipped")
        self.assertEqual(self.store.list_incidents()[0]["check_id"], "__scheduler__")

    def test_webhook_delivery_marks_notification_sent(self):
        self.config["alerts"]["failure_threshold"] = 1
        self.engine.process_report(self.report("failed", "run-1"), self.config)
        notifier = WebhookNotifier(self.store, lambda: "https://hooks.example.test/token")
        with patch.object(WebhookNotifier, "_send") as send:
            notifier.drain()
        send.assert_called_once()
        self.assertEqual(self.store.list_notifications()[0]["status"], "sent")

    def test_webhook_failure_does_not_persist_secret_url(self):
        self.config["alerts"]["failure_threshold"] = 1
        self.engine.process_report(self.report("failed", "run-1"), self.config)
        notifier = WebhookNotifier(self.store, lambda: "https://hooks.example.test/private-token")
        with patch.object(WebhookNotifier, "_send", side_effect=RuntimeError("https://hooks.example.test/private-token")):
            notifier.drain()
        notification = self.store.list_notifications()[0]
        self.assertEqual(notification["status"], "retry")
        self.assertEqual(notification["last_error"], "RuntimeError")
        self.assertNotIn("private-token", str(notification))

    def test_dingtalk_webhook_uses_markdown_and_signature(self):
        url = "https://oapi.dingtalk.com/robot/send?access_token=mock-token"
        secret = "mock-signing-secret"
        payload = {
            "title": "巡检成功", "message": "通过 10 项", "system_id": "overseas-srm",
            "environment": "test", "run_id": "run-1", "occurred_at": "2026-09-23T02:00:00+00:00",
        }
        timestamp = 1700000000123
        with patch("operations.time.time", return_value=timestamp / 1000), \
                patch("operations.urlopen", return_value=WebhookResponse({"errcode": 0, "errmsg": "ok"})) as opened:
            WebhookNotifier._send(url, payload, secret)
        request = opened.call_args.args[0]
        query = parse_qs(urlparse(request.full_url).query)
        expected = base64.b64encode(hmac.new(
            secret.encode(), f"{timestamp}\n{secret}".encode(), hashlib.sha256
        ).digest()).decode()
        self.assertEqual(query["access_token"], ["mock-token"])
        self.assertEqual(query["timestamp"], [str(timestamp)])
        self.assertEqual(query["sign"], [expected])
        body = json.loads(request.data)
        self.assertEqual(body["msgtype"], "markdown")
        self.assertIn("巡检成功", body["markdown"]["title"])
        self.assertIn("run-1", body["markdown"]["text"])

    def test_dingtalk_report_link_uses_action_card_with_local_time(self):
        url = "https://oapi.dingtalk.com/robot/send?access_token=mock-token"
        report_url = (
            "https://inspection.example.test/?view=reports&system=overseas-srm"
            "&kind=ui&run=20260929T051607Z-12c97008"
        )
        payload = {
            "event": "success", "display_name": "GSRM", "system_id": "overseas-srm",
            "environment": "production", "trigger": "manual", "targets": ["ui"],
            "counts": {"passed": 2, "failed": 0, "skipped": 0},
            "duration_ms": 18700, "screenshot_count": 7,
            "run_id": "20260929T051607Z-12c97008",
            "occurred_at": "2026-09-29T05:16:27+00:00", "timezone": "Asia/Shanghai",
            "report_kind": "ui", "report_url": report_url, "report_urls": {"ui": report_url},
        }
        with patch("operations.urlopen", return_value=WebhookResponse({"errcode": 0, "errmsg": "ok"})) as opened:
            WebhookNotifier._send(url, payload)
        body = json.loads(opened.call_args.args[0].data)
        self.assertEqual(body["msgtype"], "actionCard")
        card = body["actionCard"]
        browser_link = urlparse(card["singleURL"])
        self.assertEqual(
            (browser_link.scheme, browser_link.netloc, browser_link.path),
            ("dingtalk", "dingtalkclient", "/page/link"),
        )
        self.assertEqual(parse_qs(browser_link.query), {
            "url": [report_url], "pc_slide": ["false"],
        })
        self.assertEqual(card["singleTitle"], "在浏览器查看完整报告")
        self.assertIn("✅ GSRM · UI 巡检通过", card["title"])
        self.assertIn("2 / 2 场景通过，通过率 100%", card["text"])
        self.assertIn("正式环境 · 手动执行 · 耗时 18.7 秒", card["text"])
        self.assertIn("2026-09-29 13:16:27", card["text"])

    def test_dingtalk_business_error_is_not_marked_sent(self):
        self.config["alerts"]["failure_threshold"] = 1
        self.engine.process_report(self.report("failed", "run-1"), self.config)
        notifier = WebhookNotifier(
            self.store,
            lambda: "https://oapi.dingtalk.com/robot/send?access_token=mock-token",
            lambda: "mock-signing-secret",
        )
        with patch("operations.urlopen", return_value=WebhookResponse({"errcode": 310000, "errmsg": "sign not match"})):
            notifier.drain()
        notification = self.store.list_notifications()[0]
        self.assertEqual(notification["status"], "retry")
        self.assertIn("errcode=310000", notification["last_error"])


if __name__ == "__main__":
    unittest.main()
