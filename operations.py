"""Durable scheduling, incident lifecycle, and webhook delivery support."""

from __future__ import annotations

import hashlib
import hmac
import base64
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _safe_count(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _report_duration_ms(report: dict) -> int:
    durations = [
        _safe_count(item.get("duration_ms"))
        for item in report.get("checks", []) if isinstance(item, dict)
    ]
    if any(durations):
        return sum(durations)
    started = parse_time(report.get("started_at"))
    finished = parse_time(report.get("finished_at"))
    return max(0, round((finished - started).total_seconds() * 1000)) \
        if started and finished else 0


def _report_targets(report: dict) -> list[str]:
    targets = report.get("targets")
    if isinstance(targets, list):
        normalized = [value for value in ("api", "ui") if value in targets]
        if normalized:
            return normalized
    discovered = {
        item.get("type", "api") for item in report.get("checks", [])
        if isinstance(item, dict) and item.get("type", "api") in ("api", "ui")
    }
    return [value for value in ("api", "ui") if value in discovered] or ["api"]


def _report_urls(public_url: str, config: dict, report: dict) -> dict[str, str]:
    if not public_url:
        return {}
    parsed = urlparse(public_url.strip())
    if (parsed.scheme not in ("http", "https") or not parsed.netloc
            or parsed.username or parsed.password or parsed.fragment):
        return {}
    base_query = [
        (key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key not in ("view", "system", "kind", "run")
    ]
    path = parsed.path.rstrip("/") + "/"
    urls = {}
    for kind in _report_targets(report):
        query = [*base_query, ("view", "reports"), ("system", config["system_id"]),
                 ("kind", kind), ("run", report["run_id"])]
        urls[kind] = urlunparse(parsed._replace(path=path, query=urlencode(query), fragment=""))
    return urls


def _notification_context(public_url: str, config: dict, report: dict) -> dict:
    targets = _report_targets(report)
    urls = _report_urls(public_url, config, report)
    phase_status = report.get("phase_status") if isinstance(report.get("phase_status"), dict) else {}
    failed_target = next((kind for kind in targets if phase_status.get(kind) == "failed"), None)
    primary_kind = failed_target or targets[0]
    screenshots = sum(
        _safe_count((item.get("evidence") or {}).get("screenshot_count"))
        for item in report.get("checks", []) if isinstance(item, dict)
    )
    retry = report.get("retry") if isinstance(report.get("retry"), dict) else {}
    return {
        "display_name": config.get("display_name") or config["system_id"],
        "trigger": report.get("trigger") or "manual",
        "targets": targets,
        "report_kind": primary_kind,
        "duration_ms": _report_duration_ms(report),
        "screenshot_count": screenshots,
        "attempt_count": _safe_count(retry.get("attempt_count")) or 1,
        "timezone": (config.get("schedule") or {}).get("timezone") or "Asia/Shanghai",
        "report_url": urls.get(primary_kind),
        "report_urls": urls,
    }


class RuntimeStore:
    """SQLite-backed operational state; reports remain JSON files."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS execution_lease (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    run_id TEXT NOT NULL,
                    trigger_name TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS check_states (
                    incident_key TEXT PRIMARY KEY,
                    system_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    consecutive_successes INTEGER NOT NULL DEFAULT 0,
                    first_failed_at TEXT,
                    last_failed_at TEXT,
                    current_incident_id TEXT,
                    last_notification_at TEXT,
                    last_classification TEXT,
                    last_reason TEXT,
                    last_run_id TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    incident_key TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    classification TEXT,
                    reason TEXT,
                    first_failed_at TEXT NOT NULL,
                    last_failed_at TEXT NOT NULL,
                    opened_at TEXT NOT NULL,
                    resolved_at TEXT,
                    failure_count INTEGER NOT NULL,
                    last_run_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS incidents_status_idx
                    ON incidents(status, opened_at DESC);
                CREATE TABLE IF NOT EXISTS notifications (
                    notification_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    next_attempt_at TEXT NOT NULL,
                    sent_at TEXT,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS notifications_due_idx
                    ON notifications(status, next_attempt_at);
                """
            )

    def claim_lease(self, run_id: str, trigger: str, ttl_seconds: int = 3600) -> bool:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT expires_at FROM execution_lease WHERE singleton = 1"
            ).fetchone()
            if row and (parse_time(row["expires_at"]) or now) > now:
                return False
            connection.execute("DELETE FROM execution_lease WHERE singleton = 1")
            connection.execute(
                "INSERT INTO execution_lease VALUES (1, ?, ?, ?, ?)",
                (run_id, trigger, now.isoformat(timespec="seconds"),
                 (now + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")),
            )
            return True

    def release_lease(self, run_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM execution_lease WHERE singleton = 1 AND run_id = ?", (run_id,)
            )

    def active_lease(self) -> dict | None:
        now = datetime.now(timezone.utc)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT run_id, trigger_name, acquired_at, expires_at FROM execution_lease WHERE singleton = 1"
            ).fetchone()
            if not row:
                return None
            if (parse_time(row["expires_at"]) or now) <= now:
                connection.execute("DELETE FROM execution_lease WHERE singleton = 1")
                return None
            return dict(row)

    def get_metadata(self, key: str, default=None):
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def set_metadata(self, key: str, value) -> None:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO metadata(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, raw),
            )

    def schedule_status(self) -> dict:
        return self.get_metadata("schedule_status", {
            "enabled": False, "next_run_at": None, "last_scheduled_for": None,
            "last_outcome": None, "last_run_id": None,
        })

    def set_schedule_status(self, value: dict) -> None:
        self.set_metadata("schedule_status", value)

    @staticmethod
    def _queue_notification(connection, incident_id: str | None, event_type: str, payload: dict) -> str:
        notification_id = uuid.uuid4().hex
        now = utc_now()
        connection.execute(
            "INSERT INTO notifications(notification_id, incident_id, event_type, payload_json, status, "
            "created_at, next_attempt_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
            (notification_id, incident_id, event_type,
             json.dumps(payload, ensure_ascii=False, separators=(",", ":")), now, now),
        )
        return notification_id

    def queue_notification(self, event_type: str, payload: dict, incident_id: str | None = None) -> str:
        with self._connect() as connection:
            return self._queue_notification(connection, incident_id, event_type, payload)

    def record_failure(self, config: dict, item: dict, run_id: str, occurred_at: str,
                       failure_threshold: int, repeat_minutes: int,
                       notification_context: dict | None = None) -> list[str]:
        system_id = config["system_id"]
        environment = config["environment"]
        check_id = item["id"]
        incident_key = f"{system_id}:{environment}:{check_id}"
        severity = item.get("severity") or config.get("alerts", {}).get("default_severity", "P2")
        now = parse_time(occurred_at) or datetime.now(timezone.utc)
        queued = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM check_states WHERE incident_key = ?", (incident_key,)
            ).fetchone()
            if row:
                state = dict(row)
            else:
                state = {
                    "status": "normal", "consecutive_failures": 0,
                    "consecutive_successes": 0, "first_failed_at": None,
                    "current_incident_id": None, "last_notification_at": None,
                }
            failures = int(state["consecutive_failures"]) + 1
            first_failed = state["first_failed_at"] or occurred_at
            incident_id = state["current_incident_id"]
            state_status = state["status"]
            should_notify = False
            event_type = None

            if state_status != "open" and failures >= failure_threshold:
                incident_id = uuid.uuid4().hex
                state_status = "open"
                event_type = "alert"
                should_notify = True
                connection.execute(
                    "INSERT INTO incidents VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, NULL, ?, ?)",
                    (incident_id, incident_key, system_id, environment, check_id,
                     item.get("name", check_id), severity, item.get("classification"),
                     item.get("reason"), first_failed, occurred_at, occurred_at, failures, run_id),
                )
            elif state_status == "open" and incident_id:
                connection.execute(
                    "UPDATE incidents SET last_failed_at = ?, failure_count = failure_count + 1, "
                    "classification = ?, reason = ?, last_run_id = ? WHERE incident_id = ?",
                    (occurred_at, item.get("classification"), item.get("reason"), run_id, incident_id),
                )
                last_notice = parse_time(state.get("last_notification_at"))
                if repeat_minutes > 0 and (not last_notice or now - last_notice >= timedelta(minutes=repeat_minutes)):
                    event_type = "reminder"
                    should_notify = True

            last_notification_at = occurred_at if should_notify else state.get("last_notification_at")
            connection.execute(
                """
                INSERT INTO check_states(
                    incident_key, system_id, environment, check_id, check_name, severity, status,
                    consecutive_failures, consecutive_successes, first_failed_at, last_failed_at,
                    current_incident_id, last_notification_at, last_classification, last_reason,
                    last_run_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_key) DO UPDATE SET
                    check_name=excluded.check_name, severity=excluded.severity, status=excluded.status,
                    consecutive_failures=excluded.consecutive_failures, consecutive_successes=0,
                    first_failed_at=excluded.first_failed_at, last_failed_at=excluded.last_failed_at,
                    current_incident_id=excluded.current_incident_id,
                    last_notification_at=excluded.last_notification_at,
                    last_classification=excluded.last_classification, last_reason=excluded.last_reason,
                    last_run_id=excluded.last_run_id, updated_at=excluded.updated_at
                """,
                (incident_key, system_id, environment, check_id, item.get("name", check_id), severity,
                 state_status, failures, first_failed, occurred_at, incident_id,
                 last_notification_at, item.get("classification"), item.get("reason"), run_id, occurred_at),
            )
            if should_notify:
                failed_step = next((
                    step for step in item.get("steps", [])
                    if isinstance(step, dict) and step.get("status") == "failed"
                ), None)
                payload = {
                    "event": event_type, "incident_id": incident_id, "severity": severity,
                    "title": f"[{severity}] {item.get('name', check_id)}巡检异常",
                    "message": item.get("reason") or item.get("classification") or "检查未通过",
                    "system_id": system_id, "environment": environment,
                    "check_id": check_id, "check_name": item.get("name", check_id),
                    "classification": item.get("classification"), "reason": item.get("reason"),
                    "first_failed_at": first_failed, "occurred_at": occurred_at,
                    "failure_count": failures, "run_id": run_id,
                    "failed_step": (failed_step or {}).get("description")
                        or (failed_step or {}).get("id"),
                    **(notification_context or {}),
                }
                queued.append(self._queue_notification(connection, incident_id, event_type, payload))
        return queued

    def record_success(self, config: dict, item: dict, run_id: str, occurred_at: str,
                       recovery_threshold: int,
                       notification_context: dict | None = None) -> list[str]:
        incident_key = f"{config['system_id']}:{config['environment']}:{item['id']}"
        queued = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM check_states WHERE incident_key = ?", (incident_key,)
            ).fetchone()
            if not row:
                return queued
            state = dict(row)
            if state["status"] != "open" or not state["current_incident_id"]:
                connection.execute(
                    "UPDATE check_states SET consecutive_failures=0, consecutive_successes=0, "
                    "first_failed_at=NULL, last_failed_at=NULL, updated_at=?, last_run_id=? "
                    "WHERE incident_key=?",
                    (occurred_at, run_id, incident_key),
                )
                return queued
            successes = int(state["consecutive_successes"]) + 1
            if successes < recovery_threshold:
                connection.execute(
                    "UPDATE check_states SET consecutive_successes=?, updated_at=?, last_run_id=? "
                    "WHERE incident_key=?",
                    (successes, occurred_at, run_id, incident_key),
                )
                return queued

            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (state["current_incident_id"],)
            ).fetchone()
            connection.execute(
                "UPDATE incidents SET status='resolved', resolved_at=?, last_run_id=? WHERE incident_id=?",
                (occurred_at, run_id, state["current_incident_id"]),
            )
            connection.execute(
                "UPDATE check_states SET status='normal', consecutive_failures=0, consecutive_successes=0, "
                "first_failed_at=NULL, last_failed_at=NULL, current_incident_id=NULL, "
                "last_notification_at=NULL, last_classification=NULL, last_reason=NULL, "
                "last_run_id=?, updated_at=? WHERE incident_key=?",
                (run_id, occurred_at, incident_key),
            )
            if incident:
                first = parse_time(incident["first_failed_at"])
                recovered = parse_time(occurred_at)
                duration = max(0, int((recovered - first).total_seconds())) if first and recovered else None
                payload = {
                    "event": "recovery", "incident_id": incident["incident_id"],
                    "title": f"[恢复] {incident['check_name']}巡检恢复",
                    "message": "检查已重新通过",
                    "severity": incident["severity"], "system_id": incident["system_id"],
                    "environment": incident["environment"], "check_id": incident["check_id"],
                    "check_name": incident["check_name"], "first_failed_at": incident["first_failed_at"],
                    "recovered_at": occurred_at, "duration_seconds": duration,
                    "failure_count": incident["failure_count"], "run_id": run_id,
                    **(notification_context or {}),
                }
                queued.append(self._queue_notification(
                    connection, incident["incident_id"], "recovery", payload
                ))
        return queued

    def list_incidents(self, limit: int = 100) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, "
                "opened_at DESC LIMIT ?", (max(1, min(limit, 500)),)
            ).fetchall()
        return [dict(row) for row in rows]

    def incident_counts(self) -> dict:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM incidents GROUP BY status"
            ).fetchall()
        result = {"open": 0, "resolved": 0}
        result.update({row["status"]: row["count"] for row in rows})
        return result

    def list_notifications(self, limit: int = 100) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT notification_id, incident_id, event_type, status, attempt_count, created_at, "
                "next_attempt_at, sent_at, last_error FROM notifications ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def due_notifications(self, limit: int = 20) -> list[dict]:
        now = utc_now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM notifications WHERE status IN ('pending','retry') AND next_attempt_at <= ? "
                "ORDER BY created_at LIMIT ?", (now, limit)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["payload"] = json.loads(item.pop("payload_json"))
            except json.JSONDecodeError:
                item["payload"] = {}
            result.append(item)
        return result

    def mark_notification_sent(self, notification_id: str) -> None:
        now = utc_now()
        with self._connect() as connection:
            connection.execute(
                "UPDATE notifications SET status='sent', attempt_count=attempt_count+1, sent_at=?, "
                "last_error=NULL WHERE notification_id=?", (now, notification_id)
            )

    def mark_notification_failed(self, notification_id: str, attempt_count: int, error: str) -> None:
        attempts = attempt_count + 1
        terminal = attempts >= 5
        delay = min(15 * (2 ** max(0, attempts - 1)), 900)
        next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
        with self._connect() as connection:
            connection.execute(
                "UPDATE notifications SET status=?, attempt_count=?, next_attempt_at=?, last_error=? "
                "WHERE notification_id=?",
                ("failed" if terminal else "retry", attempts,
                 next_attempt.isoformat(timespec="seconds"), error[:300], notification_id),
            )


class AlertEngine:
    def __init__(self, store: RuntimeStore, public_url_getter=lambda: ""):
        self.store = store
        self.public_url_getter = public_url_getter

    def process_report(self, report: dict, config: dict) -> None:
        alerts = config.get("alerts", {})
        if not alerts.get("enabled", False):
            return
        failure_threshold = int(alerts.get("failure_threshold", 2))
        recovery_threshold = int(alerts.get("recovery_threshold", 1))
        repeat_minutes = int(alerts.get("repeat_interval_minutes", 60))
        occurred_at = report.get("finished_at") or utc_now()
        report_base_url = str(alerts.get("report_base_url") or "").strip()
        context = _notification_context(report_base_url or self.public_url_getter(), config, report)
        items = list(report.get("checks") or [])
        targets = report.get("targets") or []
        if targets:
            phase_errors = report.get("phase_errors") or {}
            for target in targets:
                error = phase_errors.get(target) or (
                    report.get("error") if len(targets) == 1 else None
                )
                items.append({
                    "id": f"__runner__:{target}",
                    "name": f"{target.upper()} 巡检执行器", "severity": "P1",
                    "status": "failed" if error else "passed",
                    "classification": "execution_failed" if error else None,
                    "reason": error,
                })
        else:
            items.append({
                "id": "__runner__", "name": "巡检执行器", "severity": "P1",
                "status": "failed" if report.get("error") else "passed",
                "classification": "execution_failed" if report.get("error") else None,
                "reason": report.get("error"),
            })
        for item in items:
            if item.get("alert_enabled", True) is False:
                continue
            if item.get("status") == "failed":
                self.store.record_failure(
                    config, item, report["run_id"], occurred_at,
                    failure_threshold, repeat_minutes, context,
                )
            elif item.get("status") == "passed":
                self.store.record_success(
                    config, item, report["run_id"], occurred_at, recovery_threshold, context
                )
        if (alerts.get("notify_on_success", False)
                and report.get("status") == "passed"):
            counts = report.get("counts") or {}
            self.store.queue_notification("success", {
                "event": "success", "severity": "INFO",
                "title": "[成功] SRM 巡检通过",
                "message": f"通过 {counts.get('passed', 0)} 项，失败 {counts.get('failed', 0)} 项，跳过 {counts.get('skipped', 0)} 项",
                "system_id": config["system_id"], "environment": config["environment"],
                "occurred_at": occurred_at, "run_id": report["run_id"], "counts": counts,
                **context,
            })

    def process_scheduler_signal(self, config: dict, failed: bool, reason: str, run_id: str = "") -> None:
        alerts = config.get("alerts", {})
        if not alerts.get("enabled", False):
            return
        item = {
            "id": "__scheduler__", "name": "巡检调度器", "severity": "P1",
            "status": "failed" if failed else "passed",
            "classification": "schedule_missed" if failed else None,
            "reason": reason if failed else None,
        }
        now = utc_now()
        if failed:
            self.store.record_failure(
                config, item, run_id or "scheduler", now,
                int(alerts.get("failure_threshold", 2)),
                int(alerts.get("repeat_interval_minutes", 60)),
            )
        else:
            self.store.record_success(
                config, item, run_id or "scheduler", now,
                int(alerts.get("recovery_threshold", 1)),
            )


class WebhookNotifier:
    def __init__(self, store: RuntimeStore, webhook_getter, dingtalk_secret_getter=lambda: ""):
        self.store = store
        self.webhook_getter = webhook_getter
        self.dingtalk_secret_getter = dingtalk_secret_getter
        self._drain_lock = threading.Lock()

    @staticmethod
    def _display_time(value, timezone_name: str) -> str:
        parsed = parse_time(str(value or ""))
        if not parsed:
            return str(value or "—")
        try:
            parsed = parsed.astimezone(ZoneInfo(timezone_name or "Asia/Shanghai"))
        except Exception:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _display_duration(value) -> str:
        milliseconds = _safe_count(value)
        if milliseconds < 1000:
            return f"{milliseconds} ms"
        seconds = milliseconds / 1000
        if seconds < 60:
            return f"{seconds:.0f} 秒" if seconds.is_integer() else f"{seconds:.1f} 秒"
        return f"{int(seconds // 60)} 分 {round(seconds % 60)} 秒"

    @staticmethod
    def _safe_text(value, limit: int = 240) -> str:
        return " ".join(str(value or "").split())[:limit]

    @staticmethod
    def _report_links(payload: dict) -> dict[str, str]:
        candidates = payload.get("report_urls") if isinstance(payload.get("report_urls"), dict) else {}
        if payload.get("report_url") and payload.get("report_kind") not in candidates:
            candidates = {**candidates, str(payload.get("report_kind") or "report"): payload["report_url"]}
        result = {}
        for kind, value in candidates.items():
            parsed = urlparse(str(value or ""))
            if (kind in ("api", "ui", "report") and parsed.scheme in ("http", "https")
                    and parsed.netloc and not parsed.username and not parsed.password):
                result[kind] = str(value)
        return result

    @staticmethod
    def _dingtalk_browser_url(url: str) -> str:
        """Ask DingTalk desktop to hand the report URL to the system browser."""
        return "dingtalk://dingtalkclient/page/link?" + urlencode({
            "url": url,
            "pc_slide": "false",
        })

    @staticmethod
    def _dingtalk_content(payload: dict) -> tuple[str, str]:
        event = str(payload.get("event") or "")
        system_name = WebhookNotifier._safe_text(
            payload.get("display_name") or payload.get("system_id") or "SRM", 48
        )
        targets = payload.get("targets") if isinstance(payload.get("targets"), list) else []
        scope = " + ".join(value.upper() for value in targets if value in ("api", "ui")) or "巡检"
        titles = {
            "success": f"✅ {system_name} · {scope} 巡检通过",
            "alert": f"❌ {system_name} · {WebhookNotifier._safe_text(payload.get('check_name') or '检查项')}巡检异常",
            "reminder": f"⚠️ {system_name} · 巡检异常持续",
            "recovery": f"✅ {system_name} · {WebhookNotifier._safe_text(payload.get('check_name') or '检查项')}巡检已恢复",
            "test": f"🧪 {system_name} · 通知测试",
        }
        title = titles.get(event) or WebhookNotifier._safe_text(payload.get("title") or "SRM 巡检通知", 80)
        lines = [f"### {title}"]
        counts = payload.get("counts") if isinstance(payload.get("counts"), dict) else {}
        if event == "success":
            passed = _safe_count(counts.get("passed"))
            failed = _safe_count(counts.get("failed"))
            skipped = _safe_count(counts.get("skipped"))
            total = passed + failed + skipped
            rate = round(passed / total * 100, 1) if total else 0
            rate_text = f"{rate:.0f}%" if rate.is_integer() else f"{rate:.1f}%"
            unit = "场景" if targets == ["ui"] else "接口" if targets == ["api"] else "检查项"
            lines.append(f"**{passed} / {total} {unit}通过，通过率 {rate_text}**")
        elif event in ("alert", "reminder"):
            lines.append(f"**{WebhookNotifier._safe_text(payload.get('message') or '检查未通过')}**")
        elif event == "recovery":
            lines.append("**检查已重新通过，异常已恢复。**")
        elif payload.get("message"):
            lines.append(WebhookNotifier._safe_text(payload["message"]))

        environment = {"production": "正式环境", "test": "测试环境"}.get(
            payload.get("environment"), WebhookNotifier._safe_text(payload.get("environment") or "环境未知", 40)
        )
        trigger = {"manual": "手动执行", "scheduled": "定时执行"}.get(
            payload.get("trigger"), WebhookNotifier._safe_text(payload.get("trigger") or "", 24)
        )
        summary = [environment]
        if trigger:
            summary.append(trigger)
        if payload.get("duration_ms") is not None:
            summary.append(f"耗时 {WebhookNotifier._display_duration(payload['duration_ms'])}")
        lines.append("> " + " · ".join(summary))

        if payload.get("failed_step"):
            lines.append(f"- 失败步骤：{WebhookNotifier._safe_text(payload['failed_step'], 100)}")
        if payload.get("classification"):
            lines.append(f"- 失败分类：{WebhookNotifier._safe_text(payload['classification'], 80)}")
        if event in ("alert", "reminder") and _safe_count(payload.get("attempt_count")) > 1:
            lines.append(f"- 自动重试：{_safe_count(payload['attempt_count']) - 1} 次")
        if _safe_count(payload.get("screenshot_count")):
            lines.append(f"- 截图证据：{_safe_count(payload['screenshot_count'])} 张")
        if payload.get("run_id"):
            lines.append(f"- 运行标识：`{WebhookNotifier._safe_text(payload['run_id'], 80)}`")
        occurred_at = payload.get("occurred_at") or payload.get("recovered_at")
        if occurred_at:
            lines.append(
                f"- 完成时间：{WebhookNotifier._display_time(occurred_at, str(payload.get('timezone') or 'Asia/Shanghai'))}"
            )
        return title[:80], "\n\n".join(lines)

    @staticmethod
    def _dingtalk_request(url: str, payload: dict, secret: str) -> tuple[str, dict]:
        parsed = urlparse(url)
        if secret:
            timestamp = str(int(time.time() * 1000))
            string_to_sign = f"{timestamp}\n{secret}".encode()
            signature = base64.b64encode(
                hmac.new(secret.encode(), string_to_sign, digestmod=hashlib.sha256).digest()
            ).decode()
            query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                     if key not in ("timestamp", "sign")]
            query.extend((("timestamp", timestamp), ("sign", signature)))
            url = urlunparse(parsed._replace(query=urlencode(query)))

        title, text = WebhookNotifier._dingtalk_content(payload)
        links = WebhookNotifier._report_links(payload)
        if links:
            card = {"title": title, "text": text, "btnOrientation": "0"}
            if len(links) == 1:
                card.update({
                    "singleTitle": "在浏览器查看失败证据" if payload.get("event") in ("alert", "reminder")
                        else "在浏览器查看完整报告",
                    "singleURL": WebhookNotifier._dingtalk_browser_url(next(iter(links.values()))),
                })
            else:
                card["btns"] = [
                    {
                        "title": f"在浏览器查看 {kind.upper()} 报告",
                        "actionURL": WebhookNotifier._dingtalk_browser_url(report_url),
                    }
                    for kind, report_url in links.items()
                ]
            return url, {"msgtype": "actionCard", "actionCard": card}
        return url, {
            "msgtype": "markdown", "markdown": {"title": title, "text": text},
            "at": {"isAtAll": False},
        }

    @staticmethod
    def _send(url: str, payload: dict, dingtalk_secret: str = "") -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("Webhook 地址无效")
        is_dingtalk = parsed.hostname == "dingtalk.com" or (parsed.hostname or "").endswith(".dingtalk.com")
        if is_dingtalk:
            url, payload = WebhookNotifier._dingtalk_request(url, payload, dingtalk_secret)
        body = json.dumps(payload, ensure_ascii=False).encode()
        request = Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "overseas-srm-inspection/1.0",
        })
        with urlopen(request, timeout=10) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Webhook 返回 HTTP {response.status}")
            raw = response.read(64 * 1024)
            if is_dingtalk:
                try:
                    result = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise RuntimeError("钉钉响应不是有效 JSON") from error
                if result.get("errcode") != 0:
                    code = result.get("errcode", "unknown")
                    message = str(result.get("errmsg") or "业务拒绝")[:120]
                    raise RuntimeError(f"钉钉 errcode={code}: {message}")

    def drain(self) -> None:
        if not self._drain_lock.acquire(blocking=False):
            return
        try:
            webhook_url = self.webhook_getter()
            dingtalk_secret = self.dingtalk_secret_getter()
            for item in self.store.due_notifications():
                if not webhook_url:
                    self.store.mark_notification_failed(
                        item["notification_id"], item["attempt_count"], "未配置 Webhook 地址"
                    )
                    continue
                try:
                    self._send(webhook_url, item["payload"], dingtalk_secret)
                except Exception as error:
                    code = getattr(error, "code", None)
                    if isinstance(code, int):
                        safe_error = f"HTTP {code}"
                    elif isinstance(error, RuntimeError) and str(error).startswith("钉钉 "):
                        safe_error = str(error)
                    else:
                        safe_error = type(error).__name__
                    self.store.mark_notification_failed(
                        item["notification_id"], item["attempt_count"],
                        safe_error,
                    )
                else:
                    self.store.mark_notification_sent(item["notification_id"])
        finally:
            self._drain_lock.release()

    def send_test(self, config: dict) -> None:
        url = self.webhook_getter()
        if not url:
            raise ValueError("尚未配置 Webhook 地址")
        self._send(url, {
            "event": "test", "severity": "INFO", "system_id": config["system_id"],
            "environment": config["environment"], "title": "SRM 巡检通知测试",
            "message": "Webhook 与消息格式验证成功",
            "occurred_at": utc_now(),
        }, self.dingtalk_secret_getter())


def next_schedule_time(after: datetime, schedule: dict) -> datetime:
    mode = schedule.get("mode", "interval")
    if mode == "interval":
        return after.astimezone(timezone.utc) + timedelta(minutes=int(schedule.get("interval_minutes", 15)))
    zone = ZoneInfo(schedule.get("timezone", "Asia/Shanghai"))
    local_after = after.astimezone(zone)
    times = sorted(schedule.get("daily_times") or ["09:00"])
    for day_offset in (0, 1, 2):
        day = local_after.date() + timedelta(days=day_offset)
        for value in times:
            hour, minute = (int(part) for part in value.split(":"))
            candidate = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone)
            if candidate > local_after:
                return candidate.astimezone(timezone.utc)
    raise ValueError("无法计算下次调度时间")


class ScheduleEngine:
    def __init__(self, load_config, store: RuntimeStore, start_run, alert_engine: AlertEngine,
                 notifier: WebhookNotifier):
        self.load_config = load_config
        self.store = store
        self.start_run = start_run
        self.alert_engine = alert_engine
        self.notifier = notifier
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._loop, name="srm-scheduler", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.tick()
                config, _ = self.load_config()
                if config.get("alerts", {}).get("enabled", False):
                    self.notifier.drain()
            except Exception as error:
                status = self.store.schedule_status()
                status.update({"last_outcome": "scheduler_error", "last_error": f"{type(error).__name__}: {error}"})
                self.store.set_schedule_status(status)
            self.stop_event.wait(2)

    def tick(self, now: datetime | None = None) -> None:
        config, _ = self.load_config()
        schedule = config.get("schedule", {})
        status = self.store.schedule_status()
        if not schedule.get("enabled", False):
            if status.get("enabled") or status.get("next_run_at"):
                self.store.set_schedule_status({
                    "enabled": False, "next_run_at": None,
                    "last_scheduled_for": status.get("last_scheduled_for"),
                    "last_outcome": status.get("last_outcome"),
                    "last_run_id": status.get("last_run_id"),
                })
            return

        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        signature = hashlib.sha256(json.dumps(schedule, sort_keys=True).encode()).hexdigest()[:12]
        next_run = parse_time(status.get("next_run_at"))
        if status.get("signature") != signature or next_run is None:
            next_run = next_schedule_time(now, schedule)
            status = {
                "enabled": True, "signature": signature,
                "next_run_at": next_run.isoformat(timespec="seconds"),
                "last_scheduled_for": status.get("last_scheduled_for"),
                "last_outcome": status.get("last_outcome"),
                "last_run_id": status.get("last_run_id"),
            }
            self.store.set_schedule_status(status)
            return
        if now < next_run:
            return

        following = next_schedule_time(next_run, schedule)
        while following <= now:
            following = next_schedule_time(following, schedule)
        status.update({
            "enabled": True, "signature": signature,
            "next_run_at": following.isoformat(timespec="seconds"),
            "last_scheduled_for": next_run.isoformat(timespec="seconds"),
        })
        delay_minutes = (now - next_run).total_seconds() / 60
        grace = int(schedule.get("misfire_grace_minutes", 30))
        if delay_minutes > grace:
            status.update({"last_outcome": "misfire_skipped", "last_run_id": None})
            self.store.set_schedule_status(status)
            self.alert_engine.process_scheduler_signal(
                config, True, f"计划时间已延迟 {round(delay_minutes)} 分钟，超过 {grace} 分钟宽限期"
            )
            return
        try:
            run_arguments = {
                "trigger": "scheduled",
                "scheduled_for": next_run.isoformat(timespec="seconds"),
            }
            if "targets" in schedule:
                run_arguments["targets"] = schedule["targets"]
            run_id = self.start_run(**run_arguments)
        except RuntimeError:
            status.update({"last_outcome": "overlap_skipped", "last_run_id": None})
        except Exception as error:
            status.update({"last_outcome": "start_failed", "last_run_id": None})
            self.alert_engine.process_scheduler_signal(
                config, True, f"定时巡检启动失败：{type(error).__name__}"
            )
        else:
            status.update({"last_outcome": "started", "last_run_id": run_id})
            self.alert_engine.process_scheduler_signal(config, False, "", run_id)
        self.store.set_schedule_status(status)
