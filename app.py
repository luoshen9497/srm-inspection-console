#!/usr/bin/env python3
"""Local SRM inspection console with API and optional UI checks."""

from __future__ import annotations

import argparse
import base64
import copy
import errno
import hashlib
import hmac
import http.cookiejar
import importlib.util
import json
import math
import os
import re
import secrets
import socket
import sqlite3
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, unquote, urlencode, urlparse
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from api_auth import auth_flow_hash, execute_auth_flow, flow_step_ids, validate_auth_flows, redact_auth_evidence, browser_cookies, validate_browser_entry_url
from artifact_store import ArtifactStore, remove_run_artifacts, resolve_artifact
from browser_executor import run_ui_checks
from operations import AlertEngine, RuntimeStore, ScheduleEngine, WebhookNotifier

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config" / "checks.json"
DEFAULT_DATA = ROOT / "data" / "runs"
DEFAULT_REGISTRY = ROOT / "config" / "systems.json"
DEFAULT_SYSTEM_DATA = ROOT / "data" / "systems"
DEFAULT_AUTH_DB = ROOT / "data" / "auth.db"
DEFAULT_AUTH_CONFIG = ROOT / "data" / "admin.json"
STATIC = ROOT / "static"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 2 * 1024 * 1024
RUN_TARGETS = ("api", "ui")
UI_ACTIONS = {
    "goto", "click", "fill", "select", "wait_visible",
    "assert_visible", "assert_text", "assert_count", "assert_url",
}
UI_LOCATOR_KEYS = {"test_id", "role", "label", "placeholder", "text", "css"}


def validate_inspection_public_url(value: str, label: str = "INSPECTION_PUBLIC_URL") -> str:
    value = value.strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if (parsed.scheme not in ("http", "https") or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or len(value) > 2048):
        raise ValueError(f"{label} 必须是无账号、密码、查询参数和片段的 HTTP(S) 地址")
    return value


def inspection_public_url() -> str:
    return validate_inspection_public_url(os.environ.get("INSPECTION_PUBLIC_URL", ""))


def normalize_run_targets(targets) -> list[str]:
    """Validate and normalize the requested execution targets."""
    if targets is None:
        return list(RUN_TARGETS)
    if not isinstance(targets, list) or not targets:
        raise ValueError("targets 必须是包含 api 或 ui 的非空数组")
    if any(not isinstance(target, str) or target not in RUN_TARGETS for target in targets):
        raise ValueError("targets 仅支持 api 和 ui")
    return [target for target in RUN_TARGETS if target in targets]


def enabled_run_targets(config: dict, targets=None, *, strict: bool = False) -> tuple[list[str], list[dict]]:
    requested = normalize_run_targets(targets)
    enabled = [
        item for item in config.get("checks", [])
        if item.get("enabled") and item.get("type", "api") in requested
    ]
    available = [
        target for target in requested
        if any(item.get("type", "api") == target for item in enabled)
    ]
    if strict and len(available) != len(requested):
        missing = [target.upper() for target in requested if target not in available]
        raise ValueError(f"所选范围没有已启用的巡检项: {', '.join(missing)}")
    if not enabled:
        raise ValueError("所选范围尚无已配置并启用的巡检项")
    return available, enabled


class AuthManager:
    """Local administrator authentication with durable, server-side sessions."""

    SESSION_COOKIE = "srm_session"
    SECURE_SESSION_COOKIE = "__Host-srm_session"
    SESSION_TTL_SECONDS = 30 * 60
    LOGIN_WINDOW_SECONDS = 15 * 60
    LOGIN_LIMIT = 5

    def __init__(self, database_path: Path, config_path: Path,
                 secure_cookie: bool = False, session_ttl_seconds: int = SESSION_TTL_SECONDS):
        self.database_path = Path(database_path)
        self.config_path = Path(config_path)
        self.secure_cookie = bool(secure_cookie)
        self.session_ttl_seconds = max(300, int(session_ttl_seconds))
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.bootstrap_password: str | None = None
        self.username, self.password_hash = self._load_credentials()
        self._initialize()

    @staticmethod
    def hash_password(password: str) -> str:
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError("管理员密码至少需要 12 个字符")
        salt = secrets.token_bytes(16)
        derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return "scrypt$16384$8$1$%s$%s" % (
            base64.urlsafe_b64encode(salt).decode().rstrip("="),
            base64.urlsafe_b64encode(derived).decode().rstrip("="),
        )

    @staticmethod
    def verify_password(password: str, encoded: str) -> bool:
        try:
            algorithm, n, r, p, salt_raw, digest_raw = encoded.split("$", 5)
            if algorithm != "scrypt":
                return False
            decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            expected = decode(digest_raw)
            actual = hashlib.scrypt(
                password.encode(), salt=decode(salt_raw), n=int(n), r=int(r), p=int(p), dklen=len(expected)
            )
            return hmac.compare_digest(actual, expected)
        except (TypeError, ValueError):
            return False

    def _load_credentials(self) -> tuple[str, str]:
        environment_username = os.environ.get("INSPECTION_ADMIN_USERNAME", "").strip()
        environment_hash = os.environ.get("INSPECTION_ADMIN_PASSWORD_HASH", "").strip()
        environment_password = os.environ.get("INSPECTION_ADMIN_PASSWORD", "")
        if environment_hash or environment_password:
            username = environment_username or "admin"
            password_hash = environment_hash or self.hash_password(environment_password)
            if not self.verify_password(environment_password or "invalid-password", password_hash) and not environment_hash:
                raise ValueError("管理员密码配置无效")
            if environment_hash and not environment_hash.startswith("scrypt$"):
                raise ValueError("INSPECTION_ADMIN_PASSWORD_HASH 格式无效")
            return username, password_hash

        if self.config_path.exists():
            document = json.loads(self.config_path.read_text())
            username = str(document.get("username", "")).strip()
            password_hash = str(document.get("password_hash", ""))
            if not username or not password_hash.startswith("scrypt$"):
                raise ValueError("管理员认证配置无效")
            return username, password_hash

        self.bootstrap_password = secrets.token_urlsafe(18)
        document = {
            "username": environment_username or "admin",
            "password_hash": self.hash_password(self.bootstrap_password),
            "created_at": utc_now(),
        }
        self._write_credentials(document)
        return document["username"], document["password_hash"]

    def _write_credentials(self, document: dict) -> None:
        temporary = self.config_path.with_suffix(self.config_path.suffix + ".tmp")
        temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2))
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.config_path)
        os.chmod(self.config_path, 0o600)

    def reset_credentials(self) -> str:
        if os.environ.get("INSPECTION_ADMIN_PASSWORD_HASH") or os.environ.get("INSPECTION_ADMIN_PASSWORD"):
            raise ValueError("当前管理员凭据由环境变量提供，请修改环境变量后重启服务")
        password = secrets.token_urlsafe(18)
        self.password_hash = self.hash_password(password)
        self._write_credentials({
            "username": self.username,
            "password_hash": self.password_hash,
            "updated_at": utc_now(),
        })
        with self._connect() as connection:
            connection.execute("DELETE FROM auth_sessions")
            connection.execute("DELETE FROM auth_attempts")
        return password

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=5)
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
            for path in (
                self.database_path,
                self.database_path.with_name(self.database_path.name + "-wal"),
                self.database_path.with_name(self.database_path.name + "-shm"),
            ):
                if path.exists():
                    os.chmod(path, 0o600)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS auth_sessions (
                    token_hash TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    csrf_token TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    remote_address TEXT,
                    user_agent TEXT
                );
                CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    attempt_key TEXT PRIMARY KEY,
                    failure_count INTEGER NOT NULL,
                    window_started_at INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            # Apply a shorter lifetime to persisted sessions without extending them.
            connection.execute(
                "UPDATE auth_sessions SET expires_at = created_at + ? "
                "WHERE expires_at > created_at + ?",
                (self.session_ttl_seconds, self.session_ttl_seconds),
            )

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _attempt_key(remote_address: str, username: str) -> str:
        raw = f"{remote_address}\0{username.casefold()}".encode()
        return hashlib.sha256(raw).hexdigest()

    def login(self, username: str, password: str, remote_address: str = "",
              user_agent: str = "") -> dict:
        now = int(time.time())
        key = self._attempt_key(remote_address, username)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM auth_sessions WHERE expires_at <= ?", (now,))
            attempt = connection.execute(
                "SELECT failure_count, window_started_at, blocked_until FROM auth_attempts WHERE attempt_key = ?",
                (key,),
            ).fetchone()
            if attempt and int(attempt["blocked_until"]) > now:
                return {"ok": False, "retry_after": int(attempt["blocked_until"]) - now}

            username_valid = hmac.compare_digest(username.encode(), self.username.encode())
            password_valid = self.verify_password(password, self.password_hash)
            valid = username_valid and password_valid
            if not valid:
                window_started = int(attempt["window_started_at"]) if attempt else now
                failures = int(attempt["failure_count"]) if attempt else 0
                if now - window_started >= self.LOGIN_WINDOW_SECONDS:
                    window_started, failures = now, 0
                failures += 1
                blocked_until = now + self.LOGIN_WINDOW_SECONDS if failures >= self.LOGIN_LIMIT else 0
                connection.execute(
                    "INSERT INTO auth_attempts(attempt_key, failure_count, window_started_at, blocked_until) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(attempt_key) DO UPDATE SET "
                    "failure_count=excluded.failure_count, window_started_at=excluded.window_started_at, "
                    "blocked_until=excluded.blocked_until",
                    (key, failures, window_started, blocked_until),
                )
                return {"ok": False, "retry_after": max(0, blocked_until - now)}

            connection.execute("DELETE FROM auth_attempts WHERE attempt_key = ?", (key,))
            token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(24)
            expires_at = now + self.session_ttl_seconds
            connection.execute(
                "INSERT INTO auth_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (self._token_hash(token), self.username, csrf_token, now, expires_at, now,
                 remote_address[:128], user_agent[:512]),
            )
        return {
            "ok": True, "token": token, "username": self.username,
            "csrf_token": csrf_token, "expires_at": expires_at,
        }

    def session(self, token: str | None) -> dict | None:
        if not token:
            return None
        now = int(time.time())
        with self._connect() as connection:
            row = connection.execute(
                "SELECT username, csrf_token, created_at, expires_at, last_seen_at "
                "FROM auth_sessions WHERE token_hash = ?",
                (self._token_hash(token),),
            ).fetchone()
            if not row or int(row["expires_at"]) <= now:
                connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (self._token_hash(token),))
                return None
            if now - int(row["last_seen_at"]) >= 60:
                connection.execute(
                    "UPDATE auth_sessions SET last_seen_at = ? WHERE token_hash = ?",
                    (now, self._token_hash(token)),
                )
            return dict(row)

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._connect() as connection:
            connection.execute("DELETE FROM auth_sessions WHERE token_hash = ?", (self._token_hash(token),))


def ui_check_hash(check: dict) -> str:
    """Hash the executable UI contract, excluding legacy policy metadata."""
    normalized = copy.deepcopy(check)
    normalized.pop("enabled", None)
    normalized.pop("read_only", None)
    raw = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def ui_verification_matches(check: dict, record: dict) -> bool:
    if not isinstance(record, dict):
        return False
    hashes = {ui_check_hash(check)}
    # Existing test records included read_only in their hash. Accept those
    # records for the same executable contract without requiring a new test.
    legacy = copy.deepcopy(check)
    legacy.pop("enabled", None)
    for value in (True, False):
        legacy["read_only"] = value
        raw = json.dumps(legacy, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        hashes.add(hashlib.sha256(raw.encode()).hexdigest())
    return record.get("check_hash") in hashes


def _ui_verification_key(check_id: str) -> str:
    return f"ui_verification:{check_id}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_count(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _report_duration_ms(report: dict) -> int:
    check_durations = [
        _safe_count(item.get("duration_ms"))
        for item in report.get("checks", []) if isinstance(item, dict) and item.get("duration_ms") is not None
    ]
    if check_durations:
        return sum(check_durations)
    try:
        started = datetime.fromisoformat(str(report.get("started_at", "")).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(report.get("finished_at", "")).replace("Z", "+00:00"))
        return max(0, round((finished - started).total_seconds() * 1000))
    except (TypeError, ValueError):
        return 0


def build_overview_analytics(config: dict, reports: list[dict]) -> dict:
    """Return chart-ready, evidence-safe metrics without response bodies or credentials."""
    metadata = {
        item.get("id"): {
            "name": item.get("name") or item.get("id") or "未命名检查项",
            "category": item.get("category") or "未分类",
        }
        for item in config.get("checks", []) if isinstance(item, dict)
    }
    runs = []
    category_totals: dict[str, dict] = {}
    check_totals: dict[str, dict] = {}

    for report in sorted(reports, key=lambda item: str(item.get("started_at", ""))):
        if not isinstance(report, dict):
            continue
        counts = report.get("counts") if isinstance(report.get("counts"), dict) else {}
        normalized_counts = {
            "passed": _safe_count(counts.get("passed")),
            "failed": _safe_count(counts.get("failed")),
            "skipped": _safe_count(counts.get("skipped")),
        }
        run_categories: dict[str, dict] = {}
        run_checks = []
        for item in report.get("checks", []):
            if not isinstance(item, dict):
                continue
            check_id = str(item.get("id") or "unknown")
            check_meta = metadata.get(check_id, {})
            name = str(item.get("name") or check_meta.get("name") or check_id)
            category = str(item.get("category") or check_meta.get("category") or "未分类")
            status = item.get("status") if item.get("status") in ("passed", "failed", "skipped") else "skipped"
            duration_ms = _safe_count(item.get("duration_ms"))
            run_checks.append({
                "id": check_id, "name": name, "category": category,
                "status": status, "duration_ms": duration_ms,
            })
            category_item = run_categories.setdefault(category, {
                "name": category, "passed": 0, "failed": 0, "skipped": 0,
            })
            category_item[status] += 1
            category_total = category_totals.setdefault(category, {
                "name": category, "passed": 0, "failed": 0, "skipped": 0,
            })
            category_total[status] += 1
            check_total = check_totals.setdefault(check_id, {
                "id": check_id, "name": name, "category": category,
                "duration_total_ms": 0, "duration_max_ms": 0, "samples": 0, "failures": 0,
            })
            check_total["duration_total_ms"] += duration_ms
            check_total["duration_max_ms"] = max(check_total["duration_max_ms"], duration_ms)
            check_total["samples"] += 1
            check_total["failures"] += int(status == "failed")

        total = sum(normalized_counts.values())
        runs.append({
            "run_id": report.get("run_id"),
            "status": report.get("status"),
            "started_at": report.get("started_at"),
            "finished_at": report.get("finished_at"),
            "trigger": report.get("trigger"),
            "duration_ms": _report_duration_ms(report),
            "pass_rate": round(normalized_counts["passed"] / total * 100, 1) if total else 0,
            "counts": normalized_counts,
            "categories": list(run_categories.values()),
            "checks": run_checks,
        })

    categories = []
    for item in category_totals.values():
        total = item["passed"] + item["failed"] + item["skipped"]
        categories.append({**item, "total": total, "pass_rate": round(item["passed"] / total * 100, 1) if total else 0})
    categories.sort(key=lambda item: (item["pass_rate"], -item["failed"], item["name"]))

    slow_checks = []
    for item in check_totals.values():
        samples = item["samples"]
        slow_checks.append({
            "id": item["id"], "name": item["name"], "category": item["category"],
            "average_ms": round(item["duration_total_ms"] / samples) if samples else 0,
            "max_ms": item["duration_max_ms"], "samples": samples, "failures": item["failures"],
        })
    slow_checks.sort(key=lambda item: (-item["average_ms"], -item["max_ms"], item["name"]))

    return {"runs": runs, "categories": categories, "slow_checks": slow_checks[:8]}


def validate_config(config: dict) -> None:
    if not isinstance(config, dict):
        raise ValueError("配置必须是 JSON 对象")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", str(config.get("system_id", ""))):
        raise ValueError("system_id 格式无效")
    if not isinstance(config.get("environment"), str) or not config["environment"].strip():
        raise ValueError("环境名称不能为空")
    if not isinstance(config.get("display_name", config["system_id"]), str) or not config.get("display_name", config["system_id"]).strip():
        raise ValueError("系统名称不能为空")
    if config.get("adapter", "http-scenario-v1") not in ("http-scenario-v1", "cas-session-v1"):
        raise ValueError("adapter 仅支持 http-scenario-v1 或 cas-session-v1")
    base = urlparse(config.get("base_url", ""))
    if base.scheme not in ("http", "https") or not base.netloc or base.path not in ("", "/"):
        raise ValueError("base_url 必须是 HTTP(S) 站点根地址")
    timeout = config.get("default_timeout_seconds", 10)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 30:
        raise ValueError("默认请求超时必须在 1 到 30 秒之间")
    report_limit = config.get("report_limit", 30)
    if not isinstance(report_limit, int) or isinstance(report_limit, bool) or not 1 <= report_limit <= 1000:
        raise ValueError("报告保留数量必须在 1 到 1000 之间")
    if not isinstance(config.get("checks"), list):
        raise ValueError("checks 必须是检查项列表")
    variables = config.get("variables", {})
    if not isinstance(variables, dict) or any(
        not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(key)) for key in variables
    ):
        raise ValueError("variables 必须是变量名到值的 JSON 对象")
    validate_schedule_config(config.get("schedule", {}))
    validate_run_retry_config(config.get("run_retry", {}))
    validate_alert_config(config.get("alerts", {}))
    validate_ui_config(config)
    ids = set()
    for check in config["checks"]:
        if not isinstance(check, dict):
            raise ValueError("检查项必须是 JSON 对象")
        check_id = check.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", check_id):
            raise ValueError(
                f"检查项 ID 格式无效: {check_id}；请使用小写字母、数字、- 或 _"
            )
        if check_id in ids:
            raise ValueError(f"检查项 ID 已存在: {check_id}")
        ids.add(check_id)
        if check.get("type", "api") not in ("api", "ui"):
            raise ValueError(f"{check_id}: type 仅支持 api 或 ui")
        if check.get("severity", "P2") not in ("P1", "P2", "P3"):
            raise ValueError(f"{check_id}: 严重级别必须是 P1、P2 或 P3")
        if "alert_enabled" in check and not isinstance(check["alert_enabled"], bool):
            raise ValueError(f"{check_id}: alert_enabled 必须是布尔值")
        if check.get("enabled"):
            validate_enabled_check(check, config)
    _validate_ui_auth_dependencies(config)
    validate_auth_flows(config, validate_enabled_check)


def _validate_ui_auth_dependencies(config: dict) -> None:
    checks = {item.get("id"): item for item in config.get("checks", []) if isinstance(item, dict)}
    flows = {flow.get("id"): flow for flow in config.get("api_auth_flows", []) if isinstance(flow, dict)}
    for check in checks.values():
        dependency = check.get("auth_dependency")
        if dependency is None:
            continue
        check_id = check.get("id", "")
        if check.get("type", "api") != "ui":
            raise ValueError(f"{check_id}: auth_dependency 仅用于 UI 场景")
        if not isinstance(dependency, dict):
            raise ValueError(f"{check_id}: auth_dependency 必须是对象")
        api_flow_id = dependency.get("api_flow_id")
        if api_flow_id is not None:
            if dependency.get("scene_id") is not None:
                raise ValueError(f"{check_id}: 只能选择一个 API 或 UI 登录前置")
            if not isinstance(api_flow_id, str) or api_flow_id not in flows:
                raise ValueError(f"{check_id}: API 登录前置流程不存在")
            if check.get("login_precheck"):
                raise ValueError(f"{check_id}: 登录前置场景不能再依赖其他登录流程")
            if check.get("enabled") and not flows[api_flow_id].get("enabled"):
                raise ValueError(f"{check_id}: 请先启用 API 登录前置流程 {api_flow_id}")
            validate_browser_entry_url(dependency.get("entry_url", ""), config, flows[api_flow_id].get("outputs", {}))
            if dependency.get("share_browser_context", True) is not True:
                raise ValueError(f"{check_id}: 前置登录必须共享浏览器上下文")
            continue
        scene_id = dependency.get("scene_id")
        if not isinstance(scene_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", scene_id):
            raise ValueError(f"{check_id}: 前置登录场景 ID 无效")
        if scene_id == check_id:
            raise ValueError(f"{check_id}: 不能引用自身作为前置登录场景")
        if dependency.get("run_policy", "when-invalid") != "when-invalid":
            raise ValueError(f"{check_id}: 前置登录仅支持 when-invalid 执行策略")
        if dependency.get("share_browser_context", True) is not True:
            raise ValueError(f"{check_id}: 前置登录必须共享浏览器上下文")
        if check.get("login_precheck"):
            raise ValueError(f"{check_id}: 登录前置场景不能再依赖其他登录场景")
        provider = checks.get(scene_id)
        if not provider or provider.get("type", "api") != "ui":
            raise ValueError(f"{check_id}: 前置登录场景不存在: {scene_id}")
        if not provider.get("login_precheck"):
            raise ValueError(f"{check_id}: {scene_id} 未标记为可作为登录前置")
        if check.get("enabled") and not provider.get("enabled"):
            raise ValueError(f"{check_id}: 启用前必须先启用前置登录场景 {scene_id}")


def validate_schedule_config(schedule: dict) -> None:
    if not isinstance(schedule, dict):
        raise ValueError("schedule 必须是 JSON 对象")
    if "enabled" in schedule and not isinstance(schedule["enabled"], bool):
        raise ValueError("schedule.enabled 必须是布尔值")
    normalize_run_targets(schedule.get("targets"))
    mode = schedule.get("mode", "interval")
    if mode not in ("interval", "daily"):
        raise ValueError("调度模式仅支持 interval 或 daily")
    timezone_name = schedule.get("timezone", "Asia/Shanghai")
    if not isinstance(timezone_name, str):
        raise ValueError("调度时区格式无效")
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError("调度时区无效") from error
    interval = schedule.get("interval_minutes", 15)
    if mode == "interval" and (not isinstance(interval, int) or isinstance(interval, bool) or not 1 <= interval <= 10080):
        raise ValueError("调度间隔必须在 1 到 10080 分钟之间")
    daily_times = schedule.get("daily_times", ["09:00"])
    if not isinstance(daily_times, list) or (mode == "daily" and not daily_times):
        raise ValueError("daily_times 至少需要一个时间")
    if mode == "daily" and any(
        not isinstance(value, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", value)
        for value in daily_times
    ):
        raise ValueError("daily_times 必须使用 HH:MM 格式")
    grace = schedule.get("misfire_grace_minutes", 30)
    if not isinstance(grace, int) or isinstance(grace, bool) or not 0 <= grace <= 10080:
        raise ValueError("漏跑宽限必须在 0 到 10080 分钟之间")
    if schedule.get("overlap_policy", "skip") != "skip":
        raise ValueError("当前仅支持 overlap_policy=skip")


def validate_run_retry_config(retry: dict) -> None:
    if not isinstance(retry, dict):
        raise ValueError("run_retry 必须是 JSON 对象")
    if "enabled" in retry and not isinstance(retry["enabled"], bool):
        raise ValueError("run_retry.enabled 必须是布尔值")
    max_retries = retry.get("max_retries", 2)
    if not isinstance(max_retries, int) or isinstance(max_retries, bool) or not 0 <= max_retries <= 5:
        raise ValueError("run_retry.max_retries 必须在 0 到 5 之间")
    delay_seconds = retry.get("delay_seconds", 30)
    if not isinstance(delay_seconds, int) or isinstance(delay_seconds, bool) or not 1 <= delay_seconds <= 3600:
        raise ValueError("run_retry.delay_seconds 必须在 1 到 3600 秒之间")


def validate_alert_config(alerts: dict) -> None:
    if not isinstance(alerts, dict):
        raise ValueError("alerts 必须是 JSON 对象")
    if "enabled" in alerts and not isinstance(alerts["enabled"], bool):
        raise ValueError("alerts.enabled 必须是布尔值")
    if "notify_on_success" in alerts and not isinstance(alerts["notify_on_success"], bool):
        raise ValueError("alerts.notify_on_success 必须是布尔值")
    report_base_url = alerts.get("report_base_url", "")
    if not isinstance(report_base_url, str):
        raise ValueError("alerts.report_base_url 必须是字符串")
    validate_inspection_public_url(report_base_url, "巡检平台访问地址")
    for key, default, maximum in (
        ("failure_threshold", 2, 20), ("recovery_threshold", 1, 20),
        ("repeat_interval_minutes", 60, 10080),
    ):
        value = alerts.get(key, default)
        minimum = 0 if key == "repeat_interval_minutes" else 1
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ValueError(f"alerts.{key} 超出允许范围")
    if alerts.get("default_severity", "P2") not in ("P1", "P2", "P3"):
        raise ValueError("默认严重级别必须是 P1、P2 或 P3")
    channels = alerts.get("channels", ["webhook"])
    if not isinstance(channels, list) or not channels or any(value != "webhook" for value in channels):
        raise ValueError("当前通知渠道仅支持 webhook")


def _validate_ui_locator(locator: dict, label: str) -> None:
    if not isinstance(locator, dict):
        raise ValueError(f"{label}: locator 必须是对象")
    selected = [key for key in UI_LOCATOR_KEYS if key in locator]
    if len(selected) != 1:
        raise ValueError(f"{label}: locator 必须且只能使用一种定位方式")
    key = selected[0]
    if not isinstance(locator[key], str) or not locator[key].strip():
        raise ValueError(f"{label}: locator 值不能为空")
    if key == "css" and (":has-text(" in locator[key] or locator[key].startswith("xpath=")):
        raise ValueError(f"{label}: 不允许使用脆弱的 XPath 或文本 CSS 定位器")
    if "exact" in locator and not isinstance(locator["exact"], bool):
        raise ValueError(f"{label}: locator.exact 必须是布尔值")
    if key != "role" and "name" in locator:
        raise ValueError(f"{label}: locator.name 仅能与 role 一起使用")
    if key == "role" and "name" in locator and not isinstance(locator["name"], str):
        raise ValueError(f"{label}: locator.name 必须是字符串")


def validate_ui_config(config: dict) -> None:
    ui = config.get("ui", {})
    if not isinstance(ui, dict):
        raise ValueError("ui 必须是 JSON 对象")
    if ui.get("browser", "chromium") != "chromium":
        raise ValueError("ui.browser 当前仅支持 chromium")
    for key, default in (("headless", True), ("ignore_https_errors", False), ("trace_on_failure", False)):
        if key in ui and not isinstance(ui.get(key, default), bool):
            raise ValueError(f"ui.{key} 必须是布尔值")
    if config.get("environment") == "production" and ui.get("ignore_https_errors", False):
        raise ValueError("生产环境不允许忽略 HTTPS 证书错误")
    timeout = ui.get("default_timeout_seconds", 15)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
        raise ValueError("ui.default_timeout_seconds 必须在 1 到 60 秒之间")
    viewport = ui.get("viewport", {"width": 1440, "height": 900})
    if not isinstance(viewport, dict) or any(
        not isinstance(viewport.get(key), int) or isinstance(viewport.get(key), bool)
        or not 320 <= viewport[key] <= 3840 for key in ("width", "height")
    ):
        raise ValueError("ui.viewport 宽高必须是 320 到 3840 之间的整数")
    if not isinstance(ui.get("locale", "zh-CN"), str) or not ui.get("locale", "zh-CN").strip():
        raise ValueError("ui.locale 不能为空")
    if ui.get("trace_on_failure") and ui.get("trace_sensitive_data_acknowledged") is not True:
        raise ValueError("启用 UI Trace 前必须确认 trace_sensitive_data_acknowledged=true")
    if "trace_sensitive_data_acknowledged" in ui and not isinstance(ui["trace_sensitive_data_acknowledged"], bool):
        raise ValueError("ui.trace_sensitive_data_acknowledged 必须是布尔值")
    for index, locator in enumerate(ui.get("screenshot_masks", []), 1):
        _validate_ui_locator(locator, f"ui.screenshot_masks[{index}]")
    ui_base = ui.get("base_url")
    if ui_base is not None:
        parsed = urlparse(ui_base)
        normalized = f"{parsed.scheme}://{parsed.netloc}"
        base = urlparse(config["base_url"])
        base_origin = f"{base.scheme}://{base.netloc}"
        allowed = {base_origin, *config.get("allowed_origins", [])}
        if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/"):
            raise ValueError("ui.base_url 必须是 HTTP(S) 站点根地址")
        if normalized not in allowed:
            raise ValueError("ui.base_url 不在 base_url 或 allowed_origins 范围内")


def load_config(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("配置文件超过 2 MiB 上限")
    config = json.loads(raw)
    validate_config(config)
    return config, hashlib.sha256(raw).hexdigest()[:12]


def save_config(path: Path, config: dict, expected_version: str | None = None) -> str:
    if expected_version is not None:
        _, current_version = load_config(path)
        if current_version != expected_version:
            raise RuntimeError("配置已被其他页面更新，请重新加载后再保存")
    validate_config(config)
    raw = (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode()
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("配置内容超过 2 MiB 上限")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(raw)
    os.chmod(temporary, 0o600)
    temporary.replace(path)
    return hashlib.sha256(raw).hexdigest()[:12]


class ConfigRepository:
    """Persist system settings, API checks and UI scenes independently.

    A legacy single JSON file remains readable and writable for standalone tests and
    backwards compatibility. Once all three split files exist, they are the only
    source of truth; the legacy file is retained as a rollback artifact.
    """

    def __init__(self, legacy_path: Path):
        self.legacy_path = legacy_path
        self.root = legacy_path.with_suffix("")
        self.system_path = self.root / "system.json"
        self.api_path = self.root / "api-checks.json"
        self.ui_path = self.root / "ui-scenes.json"

    @property
    def split(self) -> bool:
        return self.system_path.exists() and self.api_path.exists() and self.ui_path.exists()

    @staticmethod
    def _raw_version(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()[:12]

    @staticmethod
    def _read(path: Path) -> tuple[dict, str]:
        raw = path.read_bytes()
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError(f"配置文件超过 2 MiB 上限: {path.name}")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError(f"配置文件必须是 JSON 对象: {path.name}")
        return value, ConfigRepository._raw_version(raw)

    @staticmethod
    def _write(path: Path, value: dict, expected_version: str | None = None) -> str:
        if expected_version is not None:
            _, current_version = ConfigRepository._read(path)
            if current_version != expected_version:
                raise RuntimeError("配置已被其他页面更新，请重新加载后再保存")
        raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("配置内容超过 2 MiB 上限")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(raw)
        os.chmod(temporary, 0o600)
        temporary.replace(path)
        return ConfigRepository._raw_version(raw)

    @staticmethod
    def _without_type(item: dict) -> dict:
        result = copy.deepcopy(item)
        result.pop("type", None)
        return result

    def _split_documents(self) -> tuple[dict, str, dict, str, dict, str]:
        system, system_version = self._read(self.system_path)
        api, api_version = self._read(self.api_path)
        ui, ui_version = self._read(self.ui_path)
        if "checks" in system:
            raise ValueError("system.json 不允许包含 checks")
        if api.get("schema_version") != 1 or not isinstance(api.get("items"), list):
            raise ValueError("api-checks.json 格式无效")
        if ui.get("schema_version") != 1 or not isinstance(ui.get("items"), list):
            raise ValueError("ui-scenes.json 格式无效")
        return system, system_version, api, api_version, ui, ui_version

    def load(self) -> tuple[dict, str]:
        if not self.split:
            return load_config(self.legacy_path)
        system, system_version, api, api_version, ui, ui_version = self._split_documents()
        config = copy.deepcopy(system)
        if "auth_flows" in api:
            config["api_auth_flows"] = copy.deepcopy(api["auth_flows"])
        config["checks"] = [
            {**self._without_type(item), "type": "api"} for item in api["items"]
        ] + [
            {**self._without_type(item), "type": "ui"} for item in ui["items"]
        ]
        validate_config(config)
        combined = hashlib.sha256(
            f"{system_version}:{api_version}:{ui_version}".encode()
        ).hexdigest()[:12]
        return config, combined

    def versions(self) -> dict:
        if not self.split:
            config, version = load_config(self.legacy_path)
            return {
                "config_version": version,
                "settings_version": version,
                "api_version": version,
                "ui_version": version,
                "split": False,
                "config": config,
            }
        system, settings_version, api, api_version, ui, ui_version = self._split_documents()
        config, config_version = self.load()
        return {
            "config_version": config_version,
            "settings_version": settings_version,
            "api_version": api_version,
            "ui_version": ui_version,
            "split": True,
            "config": config,
            "settings": system,
            "api_items": api["items"],
            "ui_items": ui["items"],
        }

    def settings_document(self) -> dict:
        versions = self.versions()
        settings = copy.deepcopy(versions.get("settings") or versions["config"])
        settings.pop("checks", None)
        settings.pop("api_auth_flows", None)
        return {"version": versions["settings_version"], "settings": settings}

    def collection_document(self, kind: str) -> dict:
        if kind not in ("api", "ui"):
            raise ValueError("配置集合类型无效")
        versions = self.versions()
        if versions["split"]:
            items = versions[f"{kind}_items"]
        else:
            items = [
                self._without_type(item) for item in versions["config"].get("checks", [])
                if (item.get("type", "api") == "ui") == (kind == "ui")
            ]
        document = {"version": versions[f"{kind}_version"], "items": copy.deepcopy(items)}
        if kind == "api":
            document["auth_flows"] = copy.deepcopy(versions["config"].get("api_auth_flows", []))
        return document

    def save_settings(self, settings: dict, expected_version: str) -> str:
        if not isinstance(settings, dict) or "checks" in settings or "api_auth_flows" in settings:
            raise ValueError("系统设置必须是且只能是系统级配置")
        current, _ = self.load()
        candidate = copy.deepcopy(settings)
        candidate["checks"] = current["checks"]
        if "api_auth_flows" in current:
            candidate["api_auth_flows"] = current["api_auth_flows"]
        validate_config(candidate)
        if self.split:
            return self._write(self.system_path, settings, expected_version)
        current_version = self.versions()["settings_version"]
        if expected_version != current_version:
            raise RuntimeError("配置已被其他页面更新，请重新加载后再保存")
        return save_config(self.legacy_path, candidate, expected_version)

    def save_collection(self, kind: str, items: list, expected_version: str, auth_flows=None) -> str:
        if kind not in ("api", "ui") or not isinstance(items, list):
            raise ValueError("巡检配置集合格式无效")
        current, _ = self.load()
        normalized = [self._without_type(item) for item in copy.deepcopy(items)]
        typed = [{**item, "type": kind} for item in normalized]
        other = [
            item for item in current["checks"]
            if (item.get("type", "api") == "ui") != (kind == "ui")
        ]
        candidate = copy.deepcopy(current)
        candidate["checks"] = typed + other if kind == "api" else other + typed
        if kind == "api" and auth_flows is not None:
            candidate["api_auth_flows"] = copy.deepcopy(auth_flows)
        validate_config(candidate)
        if self.split:
            path = self.api_path if kind == "api" else self.ui_path
            document = {"schema_version": 1, "items": normalized}
            if kind == "api" and "api_auth_flows" in candidate:
                document["auth_flows"] = candidate["api_auth_flows"]
            return self._write(path, document, expected_version)
        current_version = self.versions()[f"{kind}_version"]
        if expected_version != current_version:
            raise RuntimeError("配置已被其他页面更新，请重新加载后再保存")
        return save_config(self.legacy_path, candidate, expected_version)

    def save_aggregate(self, config: dict, expected_version: str) -> str:
        validate_config(config)
        _, current_version = self.load()
        if expected_version != current_version:
            raise RuntimeError("配置已被其他页面更新，请重新加载后再保存")
        if not self.split:
            return save_config(self.legacy_path, config, expected_version)
        system = copy.deepcopy(config)
        checks = system.pop("checks")
        api_items = [self._without_type(item) for item in checks if item.get("type", "api") != "ui"]
        ui_items = [self._without_type(item) for item in checks if item.get("type", "api") == "ui"]
        api_document = {"schema_version": 1, "items": api_items}
        if "api_auth_flows" in system:
            api_document["auth_flows"] = system.pop("api_auth_flows")
        self._write(self.system_path, system)
        self._write(self.api_path, api_document)
        self._write(self.ui_path, {"schema_version": 1, "items": ui_items})
        return self.load()[1]

    def migration_preview(self) -> dict:
        config, version = load_config(self.legacy_path)
        api_items = [item for item in config["checks"] if item.get("type", "api") != "ui"]
        ui_items = [item for item in config["checks"] if item.get("type", "api") == "ui"]
        return {
            "system_id": config["system_id"], "legacy_version": version,
            "api_count": len(api_items), "ui_count": len(ui_items),
            "target": str(self.root), "already_migrated": self.split,
        }

    def migrate(self) -> dict:
        preview = self.migration_preview()
        if self.split:
            return preview
        config, _ = load_config(self.legacy_path)
        system = copy.deepcopy(config)
        checks = system.pop("checks")
        api_items = [self._without_type(item) for item in checks if item.get("type", "api") != "ui"]
        ui_items = [self._without_type(item) for item in checks if item.get("type", "api") == "ui"]
        api_document = {"schema_version": 1, "items": api_items}
        if "api_auth_flows" in system:
            api_document["auth_flows"] = system.pop("api_auth_flows")
        self._write(self.system_path, system)
        self._write(self.api_path, api_document)
        self._write(self.ui_path, {"schema_version": 1, "items": ui_items})
        migrated, _ = self.load()
        if migrated != {
            **config,
            "checks": [
                {**self._without_type(item), "type": "api"}
                for item in checks if item.get("type", "api") != "ui"
            ] + [
                {**self._without_type(item), "type": "ui"}
                for item in checks if item.get("type", "api") == "ui"
            ],
        }:
            raise RuntimeError("迁移后配置校验不一致")
        return {**preview, "migrated": True, "config_version": self.load()[1]}


def api_callback_urls(check: dict) -> list:
    path = check.get("path", "")
    if not isinstance(path, str):
        return []
    return [urlparse(value) for _, value in parse_qsl(urlparse(path).query)
            if value.lower().startswith(("http://", "https://"))]


def valid_http_callback_confirmation(value) -> bool:
    if not isinstance(value, str) or not value.startswith("http://"):
        return False
    try:
        parsed = urlparse(value)
        port = parsed.port or 80
    except ValueError:
        return False
    return bool(parsed.hostname and 1 <= port <= 65535 and not parsed.username
                and not parsed.password and not parsed.fragment)


def confirmed_http_callback(check: dict, callback) -> bool:
    confirmations = check.get("confirmed_callback_urls", [])
    return (callback.scheme == "http" and not callback.username and not callback.password
            and not callback.fragment and isinstance(confirmations, list)
            and callback.geturl() in confirmations and valid_http_callback_confirmation(callback.geturl()))


def pending_argument_reasons(check: dict) -> list[str]:
    descriptions = {
        "insecure_callback": "CAS 回调地址使用 HTTP，需核实并确认实际回调地址",
        "business_assertion": "缺少业务断言，请根据接口成功响应补充断言",
        "body_template": "导入的请求体模板无法解析，请填写有效的 JSON 请求体",
    }
    return list(dict.fromkeys(
        descriptions.get(item.get("name"), "需先确认导出参数的位置和用途")
        if isinstance(item, dict) else "需先确认导出参数的位置和用途"
        for item in check.get("pending_arguments", [])
    ))


def refresh_api_pending_arguments(check: dict, config: dict) -> None:
    """Recheck known import markers; retain unknown items needing human review."""
    callbacks = api_callback_urls(check)
    allowed = set(config.get("allowed_origins", [])) | {config.get("base_url", "").rstrip("/")}
    approved_callbacks = bool(callbacks) and all(
        (url.scheme == "https" and f"{url.scheme}://{url.netloc}" in allowed)
        or confirmed_http_callback(check, url)
        for url in callbacks
    )
    resolved = {
        "insecure_callback": approved_callbacks,
        "business_assertion": bool(check.get("assertions")),
        "body_template": isinstance(check.get("body"), (dict, list)),
    }
    pending = [item for item in check.get("pending_arguments", [])
               if not isinstance(item, dict) or not resolved.get(item.get("name"), False)]
    if pending:
        check["pending_arguments"] = pending
    else:
        check.pop("pending_arguments", None)


def api_enablement_issues(check: dict, config: dict) -> list[str]:
    candidate = copy.deepcopy(check)
    refresh_api_pending_arguments(candidate, config)
    reasons = pending_argument_reasons(candidate)
    pending_names = {item.get("name") for item in candidate.get("pending_arguments", [])
                     if isinstance(item, dict)}
    candidate.pop("pending_arguments", None)
    try:
        validate_enabled_check(candidate, config)
    except ValueError as error:
        reason = str(error).removeprefix(f"{check.get('id', '')}: ")
        duplicate = ("insecure_callback" in pending_names and "CAS 回调地址使用 HTTP" in reason
                     or "business_assertion" in pending_names and "至少需要一条业务断言" in reason)
        if not duplicate:
            reasons.append(reason)
    return list(dict.fromkeys(reasons))


def validate_enabled_check(check: dict, config: dict | None = None) -> None:
    if check.get("pending_arguments"):
        raise ValueError(f"{check['id']}: {'；'.join(pending_argument_reasons(check))}")
    if check.get("type", "api") == "ui":
        validate_enabled_ui_check(check, config)
        return
    path = check.get("path")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "#" in path:
        raise ValueError(f"{check['id']}: 需要站点内的真实接口路径")
    if (config or {}).get("adapter") == "cas-session-v1":
        confirmations = check.get("confirmed_callback_urls", [])
        if not isinstance(confirmations, list) or any(
            not valid_http_callback_confirmation(value)
            for value in confirmations
        ):
            raise ValueError(f"{check['id']}: confirmed_callback_urls 必须是已确认的完整 HTTP 回调地址列表")
        allowed = set(config.get("allowed_origins", [])) | {config.get("base_url", "").rstrip("/")}
        for callback in api_callback_urls(check):
            if confirmed_http_callback(check, callback):
                continue
            if callback.scheme != "https":
                raise ValueError(f"{check['id']}: CAS 回调地址使用 HTTP，需确认实际回调地址")
            if f"{callback.scheme}://{callback.netloc}" not in allowed:
                raise ValueError(f"{check['id']}: CAS 回调来源不在 allowed_origins 中")
    if check.get("origin"):
        origin = urlparse(check["origin"])
        allowed = set((config or {}).get("allowed_origins", []))
        normalized = f"{origin.scheme}://{origin.netloc}"
        if origin.scheme not in ("http", "https") or not origin.netloc or normalized not in allowed:
            raise ValueError(f"{check['id']}: 请求来源不在 allowed_origins 中")
    if check.get("method") not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        raise ValueError(f"{check['id']}: 请求方法必须为 GET、POST、PUT、PATCH、DELETE、HEAD 或 OPTIONS")
    if check.get("timeout_seconds") is not None:
        timeout = check["timeout_seconds"]
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 30:
            raise ValueError(f"{check['id']}: 超时必须在 1 到 30 秒之间")
    expected_status = check.get("expected_status", 200)
    if not isinstance(expected_status, int) or isinstance(expected_status, bool) or not 100 <= expected_status <= 599:
        raise ValueError(f"{check['id']}: 预期 HTTP 状态码必须在 100 到 599 之间")
    if not isinstance(check.get("headers", {}), dict):
        raise ValueError(f"{check['id']}: 请求头必须是 JSON 对象")
    if check.get("body_encoding", "json") not in ("json", "form"):
        raise ValueError(f"{check['id']}: 请求体编码无效")
    if check.get("body_encoding") == "form" and (check.get("method") not in ("POST", "PUT", "PATCH", "DELETE") or not isinstance(check.get("body"), dict)):
        raise ValueError(f"{check['id']}: 表单请求需要 POST、PUT、PATCH 或 DELETE 和对象请求体")
    if not isinstance(check.get("assertions"), list) or (
        not check["assertions"] and not check.get("login_precheck") and not check.get("session_setup")
        and check.get("method") != "HEAD" and expected_status not in (204, 205, 304)
    ):
        raise ValueError(f"{check['id']}: 至少需要一条业务断言")
    if (check.get("login_precheck") or check.get("session_setup")) and not check["assertions"] and not check.get("extract"):
        raise ValueError(f"{check['id']}: 无业务断言的登录项需要提取会话票据")
    for rule in check["assertions"]:
        if rule.get("op") not in (
            "equals", "present", "nonempty", "one_of", "type_is",
            "greater_than", "contains", "matches",
        ) or not rule.get("path"):
            raise ValueError(f"{check['id']}: 断言格式无效")
        if rule.get("op") == "type_is" and rule.get("value") not in ("object", "array", "string", "number", "boolean", "null"):
            raise ValueError(f"{check['id']}: 类型断言值无效")
    for extractor in check.get("extract", []):
        variable_valid = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", extractor.get("variable", ""))
        json_valid = extractor.get("path", "").startswith("$.")
        regex_valid = extractor.get("source") in ("body", "headers") and bool(extractor.get("pattern"))
        if not variable_valid or not (json_valid or regex_valid):
            raise ValueError(f"{check['id']}: 响应变量提取配置无效")
        if regex_valid:
            try:
                re.compile(extractor["pattern"])
            except (re.error, TypeError) as error:
                raise ValueError(f"{check['id']}: 响应变量提取正则无效") from error


def validate_enabled_ui_check(check: dict, config: dict | None = None) -> None:
    check_id = check["id"]
    steps = check.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"{check_id}: UI 检查至少需要一个步骤")
    step_ids = set()
    for index, step in enumerate(steps, 1):
        label = f"{check_id}.steps[{index}]"
        if not isinstance(step, dict):
            raise ValueError(f"{label}: 步骤必须是对象")
        step_id = step.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", str(step_id)) or step_id in step_ids:
            raise ValueError(f"{label}: 步骤 ID 格式无效或重复")
        step_ids.add(step_id)
        if not isinstance(step.get("description"), str) or not step["description"].strip():
            raise ValueError(f"{label}: description 不能为空")
        action = step.get("action")
        if action not in UI_ACTIONS:
            raise ValueError(f"{label}: 不支持的 UI 动作")
        if step.get("screenshot") is False:
            raise ValueError(f"{label}: 启用的 UI 步骤必须保留截图证据")
        timeout = step.get("timeout_seconds")
        if timeout is not None and (
            not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 1 <= timeout <= 60
        ):
            raise ValueError(f"{label}: timeout_seconds 必须在 1 到 60 秒之间")
        if "sensitive" in step and not isinstance(step["sensitive"], bool):
            raise ValueError(f"{label}: sensitive 必须是布尔值")
        if "authentication_assertion" in step and not isinstance(step["authentication_assertion"], bool):
            raise ValueError(f"{label}: authentication_assertion 必须是布尔值")
        if step.get("authentication_assertion") and (
            not check.get("login_precheck") or not str(action).startswith("assert_")
        ):
            raise ValueError(f"{label}: authentication_assertion 仅用于登录预检的断言步骤")
        if step.get("sensitive") and (
            action != "fill" or not isinstance(step.get("value"), str)
            or not re.fullmatch(r"\$\{[A-Za-z][A-Za-z0-9_]*\}", step["value"])
        ):
            raise ValueError(f"{label}: 敏感输入必须使用 fill 和完整的 ${{VARIABLE}} 凭据引用")
        if action == "goto":
            path = step.get("path")
            if not isinstance(path, str) or not path.strip():
                raise ValueError(f"{label}: goto.path 必须是同源站内路径或完整地址")
            parsed_path = urlparse(path)
            if parsed_path.scheme or parsed_path.netloc:
                ui_base = (config or {}).get("ui", {}).get("base_url", (config or {}).get("base_url", ""))
                parsed_base = urlparse(ui_base)
                path_origin = f"{parsed_path.scheme.lower()}://{parsed_path.netloc.lower()}"
                base_origin = f"{parsed_base.scheme.lower()}://{parsed_base.netloc.lower()}"
                if parsed_path.scheme not in ("http", "https") or not parsed_path.netloc or path_origin != base_origin:
                    raise ValueError(f"{label}: goto.path 完整地址必须与 UI 基础地址同源")
            elif not path.startswith("/") or path.startswith("//"):
                raise ValueError(f"{label}: goto.path 必须是同源站内路径或完整地址")
            if step.get("wait_until", "domcontentloaded") not in ("domcontentloaded", "load", "networkidle"):
                raise ValueError(f"{label}: wait_until 无效")
        elif action == "assert_url":
            if not isinstance(step.get("expected"), str) or not step["expected"]:
                raise ValueError(f"{label}: assert_url.expected 不能为空")
        else:
            _validate_ui_locator(step.get("locator"), label)
        if action in ("fill", "select") and "value" not in step:
            raise ValueError(f"{label}: {action} 需要 value")
        if action == "assert_text" and not isinstance(step.get("expected"), str):
            raise ValueError(f"{label}: assert_text.expected 必须是字符串")
        if action == "assert_count" and (
            not isinstance(step.get("expected"), int) or isinstance(step.get("expected"), bool)
            or step["expected"] < 0
        ):
            raise ValueError(f"{label}: assert_count.expected 必须是非负整数")
        if action in ("assert_text", "assert_url") and step.get("match", "contains") not in (
            "contains", "equals", "not_contains", "not_equals",
        ):
            raise ValueError(f"{label}: match 仅支持 contains、equals、not_contains 或 not_equals")
    if check.get("login_precheck") and not any(
        step.get("authentication_assertion") is True for step in steps
    ):
        raise ValueError(f"{check_id}: 登录前置必须包含一条登录成功断言")
    for index, locator in enumerate(check.get("screenshot_masks", []), 1):
        _validate_ui_locator(locator, f"{check_id}.screenshot_masks[{index}]")


def resolve_env(value, variables=None):
    if isinstance(value, str):
        pattern = r"\$\{([A-Za-z][A-Za-z0-9_]*)(?:\|([A-Za-z][A-Za-z0-9_]*))?\}"
        def resolve(match):
            name, transform = match.groups()
            result = (variables or {}).get(name)
            if result is None:
                result = os.environ.get(name)
            if result is None:
                raise ValueError(f"缺少运行变量或环境变量 {name}")
            if transform:
                if transform not in ("base64", "lower"):
                    raise ValueError(f"变量 {name} 不支持转换 {transform}")
                if not isinstance(result, str):
                    raise ValueError(f"变量 {name} 的 {transform} 转换需要字符串")
                result = base64.b64encode(result.encode("utf-8")).decode("ascii") if transform == "base64" else result.lower()
            return result
        exact = re.fullmatch(pattern, value)
        if exact:
            return resolve(exact)
        return re.sub(pattern, lambda match: str(resolve(match)), value)
    if isinstance(value, list):
        return [resolve_env(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: resolve_env(item, variables) for key, item in value.items()}
    return value


def lookup(data, path: str):
    if not path.startswith("$."):
        raise ValueError(f"断言路径须以 $. 开头: {path}")
    current = data
    for part in re.findall(r"[^.\[\]]+", path[2:]):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def evaluate(data, rules: list[dict]) -> list[dict]:
    results = []
    for rule in rules:
        exists, actual = lookup(data, rule["path"])
        op = rule["op"]
        if op == "type_is":
            type_checks = {
                "object": lambda value: isinstance(value, dict),
                "array": lambda value: isinstance(value, list),
                "string": lambda value: isinstance(value, str),
                "number": lambda value: isinstance(value, (int, float)) and not isinstance(value, bool),
                "boolean": lambda value: isinstance(value, bool),
                "null": lambda value: value is None,
            }
            passed = exists and type_checks[rule["value"]](actual)
        elif op == "equals":
            passed = exists and actual == rule.get("value")
        elif op == "present":
            passed = exists
        elif op == "nonempty":
            passed = exists and actual not in (None, "", [], {})
        elif op == "one_of":
            passed = exists and actual in rule.get("values", [])
        elif op == "greater_than":
            try:
                passed = exists and float(actual) > float(rule.get("value"))
            except (TypeError, ValueError):
                passed = False
        elif op == "contains":
            try:
                passed = exists and rule.get("value") in actual
            except TypeError:
                passed = False
        else:
            passed = exists and re.fullmatch(str(rule.get("value", "")), str(actual)) is not None
        item = {"path": rule["path"], "op": op, "passed": bool(passed)}
        if op in ("equals", "type_is", "greater_than", "contains", "matches"):
            item["expected"] = rule.get("value")
        elif op == "one_of":
            item["expected"] = rule.get("values", [])
        if rule.get("record_actual"):
            item["actual"] = actual if exists else "<字段不存在>"
        results.append(item)
    return results


class CredentialStore:
    """Small local credential store. The file is readable only by its owner."""

    FIELDS = (
        "SRM_ACCOUNT", "SRM_USERNAME", "SRM_PASSWORD", "SRM_CLIENT_ID",
        "SRM_UI_USERNAME", "SRM_UI_PASSWORD",
        "ALERT_WEBHOOK_URL", "DINGTALK_SECRET",
    )

    def __init__(self, path: Path, use_environment_fallback: bool = True):
        self.path = path
        self.use_environment_fallback = use_environment_fallback

    def read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            value = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("凭据文件无法读取") from error
        if not isinstance(value, dict):
            raise ValueError("凭据文件格式无效")
        return {key: str(value[key]) for key in self.FIELDS if value.get(key) not in (None, "")}

    def runtime_variables(self) -> dict:
        stored = self.read()
        if self.use_environment_fallback:
            for key in self.FIELDS:
                if key not in stored and os.environ.get(key):
                    stored[key] = os.environ[key]
        return stored

    def public_status(self) -> dict:
        stored = self.read()
        fallback = os.environ if self.use_environment_fallback else {}
        account = stored.get("SRM_ACCOUNT", fallback.get("SRM_ACCOUNT", ""))
        username = stored.get("SRM_USERNAME", fallback.get("SRM_USERNAME", ""))
        client_id = stored.get("SRM_CLIENT_ID", fallback.get("SRM_CLIENT_ID", ""))
        ui_username = stored.get("SRM_UI_USERNAME", fallback.get("SRM_UI_USERNAME", ""))
        password_configured = bool(stored.get("SRM_PASSWORD") or fallback.get("SRM_PASSWORD"))
        ui_password_configured = bool(
            stored.get("SRM_UI_PASSWORD") or fallback.get("SRM_UI_PASSWORD")
        )
        webhook_configured = bool(stored.get("ALERT_WEBHOOK_URL") or fallback.get("ALERT_WEBHOOK_URL"))
        dingtalk_secret_configured = bool(stored.get("DINGTALK_SECRET") or fallback.get("DINGTALK_SECRET"))
        return {
            "account": account, "username": username, "client_id": client_id,
            "password_configured": password_configured, "ui_username": ui_username,
            "ui_password_configured": ui_password_configured,
            "webhook_configured": webhook_configured,
            "dingtalk_secret_configured": dingtalk_secret_configured,
        }

    def update(self, values: dict) -> None:
        if not isinstance(values, dict):
            raise ValueError("凭据配置必须是 JSON 对象")
        stored = self.read()
        mappings = {
            "account": "SRM_ACCOUNT",
            "username": "SRM_USERNAME",
            "password": "SRM_PASSWORD",
            "client_id": "SRM_CLIENT_ID",
            "ui_username": "SRM_UI_USERNAME",
            "ui_password": "SRM_UI_PASSWORD",
            "webhook_url": "ALERT_WEBHOOK_URL",
            "dingtalk_secret": "DINGTALK_SECRET",
        }
        for public_name, environment_name in mappings.items():
            value = values.get(public_name)
            if value is not None and value != "":
                if not isinstance(value, str) or len(value) > 4096:
                    raise ValueError(f"{public_name} 格式无效")
                stored[environment_name] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(stored, ensure_ascii=False, indent=2) + "\n")
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)


def _parse_template_json(raw: str):
    """Parse JSON containing unquoted ${variable} placeholders without evaluating them."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        output, index, quoted, escaped = [], 0, False, False
        while index < len(raw):
            char = raw[index]
            if char == '"' and not escaped:
                quoted = not quoted
            if not quoted and raw.startswith("${", index):
                end = raw.find("}", index + 2)
                if end < 0:
                    break
                output.append(json.dumps(raw[index:end + 1]))
                index = end + 1
                escaped = False
                continue
            output.append(char)
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            index += 1
        return json.loads("".join(output))


def _typed_meter_value(value):
    if not isinstance(value, str) or value.startswith("${"):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _meter_assertions(step: dict) -> list[dict]:
    rules = []
    for child in step.get("hashTree", []):
        if not isinstance(child, dict) or child.get("type") != "Assertions":
            continue
        for item in child.get("jsonPath", []):
            if not item.get("valid") or item.get("enable") is False or not item.get("expression"):
                continue
            path = str(item["expression"]).strip()
            expected = _typed_meter_value(item.get("expect"))
            option = str(item.get("option", "EQUALS")).upper()
            if option == "GT":
                rule = {"path": path, "op": "greater_than", "value": expected}
            elif option == "CONTAINS" and expected == []:
                rule = {"path": path, "op": "type_is", "value": "array"}
            elif option == "CONTAINS":
                rule = {"path": path, "op": "contains", "value": expected}
            elif option == "REGEX" and expected == ".+":
                rule = {"path": path, "op": "nonempty"}
            elif option == "REGEX" and isinstance(expected, str) and re.search(r"[.*+?\[\](){}|^$\\]", expected):
                rule = {"path": path, "op": "matches", "value": expected}
            else:
                rule = {"path": path, "op": "equals", "value": expected}
            rules.append(rule)
    return rules


def _meter_extractors(step: dict) -> list[dict]:
    extractors = []
    for child in step.get("hashTree", []):
        if not isinstance(child, dict) or child.get("type") != "Extract":
            continue
        for item in child.get("json", []):
            if item.get("valid") and item.get("variable") and item.get("expression"):
                extractors.append({"variable": item["variable"], "path": item["expression"]})
        for item in child.get("regex", []):
            if item.get("valid") and item.get("variable") and item.get("expression"):
                extractors.append({
                    "variable": item["variable"], "pattern": item["expression"],
                    "source": "headers" if str(item.get("useHeaders", "false")).lower() == "true" else "body",
                })
    return extractors


def import_metersphere(content: str, current_config: dict) -> dict:
    """Convert a MeterSphere export into a disabled, credential-safe system draft."""
    try:
        exported = json.loads(content)
        scenario_source = exported["data"][0]["scenarioDefinition"]
        scenario = json.loads(scenario_source) if isinstance(scenario_source, str) else scenario_source
        roots = scenario["hashTree"]
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("不是可识别的 MeterSphere 场景导出") from error
    if not isinstance(roots, list) or not roots:
        raise ValueError("MeterSphere 场景中没有请求步骤")

    def request_steps(nodes, inherited=None, category="导入项"):
        inherited = dict(inherited or {})
        for node in nodes:
            if not isinstance(node, dict):
                continue
            scoped = dict(inherited)
            for variable in node.get("variables", []):
                if variable.get("enable") is not False and variable.get("name"):
                    scoped[variable["name"]] = _typed_meter_value(variable.get("value", ""))
            node_category = node.get("name", category) if node.get("type") == "scenario" else category
            if node.get("type") == "HTTPSamplerProxy" or node.get("url") or node.get("method"):
                yield node, scoped, category
            children = node.get("hashTree")
            if isinstance(children, list):
                yield from request_steps(children, scoped, node_category)

    steps = list(request_steps(roots))
    if not steps:
        raise ValueError("MeterSphere 场景中没有可识别的 HTTP 请求")

    result = copy.deepcopy(current_config)
    current_by_name: dict[str, list[dict]] = {}
    for item in result["checks"]:
        current_by_name.setdefault(item.get("source_step", item.get("name")), []).append(item)
    imported_checks, excluded_steps, used_ids, origins = [], [], set(), set()
    adapter = current_config.get("adapter", "http-scenario-v1")
    for index, (step, scoped_variables, category) in enumerate(steps):
        name = step.get("name") or f"步骤 {index + 1}"
        if adapter == "cas-session-v1" and "退出登录" in name:
            excluded_steps.append({"name": name, "reason": "cleanup"})
            continue
        raw_url = str(step.get("url") or step.get("path") or "").strip()
        url = urlparse(raw_url)
        if not url.netloc and raw_url.startswith("/"):
            base = urlparse(current_config["base_url"])
            url = urlparse(f"{base.scheme}://{base.netloc}{raw_url}")
        if adapter == "cas-session-v1" and url.scheme == "http":
            secure_origin = f"https://{url.netloc}"
            if secure_origin in set(current_config.get("allowed_origins", [])):
                url = urlparse(f"{secure_origin}{url.path}" + (f"?{url.query}" if url.query else ""))
        if url.scheme not in ("http", "https") or not url.netloc:
            raise ValueError(f"第 {index + 1} 个步骤缺少有效 URL")
        origin = f"{url.scheme}://{url.netloc}"
        origins.add(origin)

        matches = current_by_name.get(name, [])
        existing = matches.pop(0) if matches else None
        if existing is None and adapter != "cas-session-v1" and index < len(result["checks"]):
            existing = result["checks"][index]
        check = copy.deepcopy(existing or {
            "id": f"imported-check-{index + 1}", "name": name, "category": category,
            "enabled": False, "expected_status": 200,
        })
        check.update({"name": name, "source_step": name, "method": str(step.get("method", "POST")).upper()})
        check["category"] = check.get("category") or category
        if check["id"] in used_ids:
            base_id = f"imported-check-{index + 1}"
            candidate, suffix = base_id, 2
            while candidate in used_ids:
                candidate = f"{base_id}-{suffix}"
                suffix += 1
            check["id"] = candidate
        used_ids.add(check["id"])

        arguments = {
            item["name"]: item.get("value", "") for item in step.get("arguments", [])
            if item.get("enable") is not False and item.get("valid") is not False and item.get("name")
        }
        body = step.get("body") or {}
        raw_body = body.get("raw") or ""
        form_items = {
            item.get("name"): item.get("value", "") for item in body.get("kvs", [])
            if item.get("enable") is not False and item.get("name")
        }
        path = url.path + (f"?{url.query}" if url.query else "")
        if arguments and (check["method"] == "GET" or raw_body or form_items):
            separator = "&" if "?" in path else "?"
            path += separator + urlencode(arguments, doseq=True, safe="${}")
            arguments = {}
        check["path"] = path
        if origin != current_config["base_url"].rstrip("/"):
            check["origin"] = origin
        else:
            check.pop("origin", None)

        pending = []
        if adapter == "cas-session-v1" and any(
            callback.scheme == "http" and not confirmed_http_callback(check, callback)
            for callback in api_callback_urls(check)
        ):
            pending.append({"name": "insecure_callback", "value": "MeterSphere 回调地址使用 HTTP，需确认实际回调地址"})
        if raw_body:
            try:
                check["body"] = _parse_template_json(raw_body)
            except json.JSONDecodeError:
                check["body"] = None
                pending.append({"name": "body_template", "value": "MeterSphere 请求体不是可解析的 JSON 模板"})
            check.pop("body_encoding", None)
        elif form_items or arguments:
            check["body"] = form_items or arguments
            check["body_encoding"] = "form"
        else:
            check["body"] = None
            check.pop("body_encoding", None)
        if check["method"] == "GET":
            check["body"] = None
            check.pop("body_encoding", None)

        if isinstance(check.get("body"), dict):
            credential_fields = {
                "elsAccount": "SRM_ACCOUNT", "elsSubAccount": "SRM_USERNAME",
                "elsSubAccountPassword": "SRM_PASSWORD", "userName": "SRM_USERNAME",
                "username": "SRM_USERNAME", "portal_username": "SRM_USERNAME",
                "password": "SRM_PASSWORD", "clientId": "SRM_CLIENT_ID",
            }
            for field, variable in credential_fields.items():
                if field in check["body"]:
                    check["body"][field] = "${" + variable + "}"

        skipped_headers = {"content-type", "content-length", "host", "cookie", "accept-encoding"}
        check["headers"] = {
            item["name"]: item.get("value", "") for item in step.get("headers", [])
            if item.get("enable") is not False and item.get("name")
            and item["name"].lower() not in skipped_headers
        }
        assertions = _meter_assertions(step)
        for rule in assertions:
            if rule.get("path") == "$.data.elsSubAccount" and rule.get("op") == "equals":
                rule["value"] = "${SRM_USERNAME}"
        extractors = _meter_extractors(step)
        if assertions:
            check["assertions"] = assertions
        elif not check.get("assertions"):
            check["assertions"] = []
        if extractors:
            check["extract"] = extractors
        elif not check.get("extract"):
            check["extract"] = []
        if scoped_variables:
            check["variables"] = scoped_variables
        else:
            check.pop("variables", None)
        check["follow_redirects"] = step.get("followRedirects", True) is not False
        if not check["follow_redirects"] and any(item.get("source") == "headers" for item in check.get("extract", [])):
            check["expected_status"] = 302

        login_name = any(word in name.lower() for word in ("登录", "login"))
        if adapter == "cas-session-v1" and (login_name or name == "获取用户信息"):
            check["session_setup"] = True
            check["response_type"] = "text" if name != "获取用户信息" else "json"
            check["login_precheck"] = name == "获取用户信息"
        elif index == 0 or check.get("login_precheck"):
            check["login_precheck"] = True
        else:
            check.pop("login_precheck", None)
            check.pop("session_setup", None)
            check.pop("response_type", None)

        if adapter == "cas-session-v1":
            check["enabled"] = False
        if not check.get("assertions") and not check.get("session_setup") and not check.get("login_precheck"):
            pending.append({"name": "business_assertion", "value": "MeterSphere 场景未提供可验证的业务断言"})
        if pending:
            check["pending_arguments"] = pending
        else:
            check.pop("pending_arguments", None)
        imported_checks.append(check)

    if len(origins) != 1 and adapter != "cas-session-v1":
        raise ValueError("场景请求必须属于同一个站点")
    if len(origins) == 1:
        result["base_url"] = next(iter(origins))
        for check in imported_checks:
            if check.get("origin") == result["base_url"]:
                check.pop("origin", None)
    else:
        configured = set(result.get("allowed_origins", []))
        if not origins.issubset(configured):
            missing = ", ".join(sorted(origins - configured))
            raise ValueError(f"场景包含未授权站点：{missing}")
    result["checks"] = imported_checks
    # Reimporting authentication steps creates drafts for the entire flow.
    for flow in result.get("api_auth_flows", []):
        flow["enabled"] = False
        token_source = flow["outputs"]["token"]
        def map_token(value):
            if isinstance(value, str):
                return value.replace("${" + token_source + "}", "${token}")
            if isinstance(value, list):
                return [map_token(item) for item in value]
            if isinstance(value, dict):
                return {key: map_token(item) for key, item in value.items()}
            return value
        for index, check in enumerate(result["checks"]):
            if check["id"] in flow["step_ids"]:
                check["enabled"] = False
            elif check.get("auth_flow_id") == flow["id"]:
                result["checks"][index] = map_token(check)
                result["checks"][index]["enabled"] = False
    result.setdefault("onboarding", {})["excluded_steps"] = excluded_steps
    validate_config(result)
    return result


class SameOriginNoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class AllowedOriginRedirect(HTTPRedirectHandler):
    """Follow allowed origins and explicitly confirmed HTTP callback endpoints."""

    def __init__(self, origins: set[str], confirmed_callbacks: set[str] | None = None):
        self.origins = origins
        self.confirmed_callbacks = confirmed_callbacks or set()
        super().__init__()

    def confirmed_callback_redirect(self, newurl: str) -> bool:
        target = urlparse(newurl)
        if target.scheme != "http" or target.username or target.password or target.fragment:
            return False
        for value in self.confirmed_callbacks:
            approved = urlparse(value)
            try:
                target_endpoint = (target.scheme, target.hostname, target.port or 80, target.path, target.params)
                approved_endpoint = (approved.scheme, approved.hostname, approved.port or 80, approved.path, approved.params)
            except ValueError:
                continue
            if target_endpoint != approved_endpoint:
                continue
            remaining = parse_qsl(target.query, keep_blank_values=True)
            for pair in parse_qsl(approved.query, keep_blank_values=True):
                if pair not in remaining:
                    break
                remaining.remove(pair)
            else:
                # CAS may append a dynamic ticket to the confirmed service URL.
                if not remaining or len(remaining) == 1 and remaining[0][0] == "ticket":
                    return True
        return False

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if (f"{parsed.scheme}://{parsed.netloc}" not in self.origins
                and not self.confirmed_callback_redirect(newurl)):
            return None
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def build_system_openers(config: dict):
    cookie_jar = http.cookiejar.CookieJar()
    if config.get("adapter") == "cas-session-v1":
        origins = set(config.get("allowed_origins", []))
        origins.add(config["base_url"].rstrip("/"))
        callbacks = {callback.geturl() for check in config.get("checks", [])
                     for callback in api_callback_urls(check) if confirmed_http_callback(check, callback)}
        return (
            build_opener(HTTPCookieProcessor(cookie_jar), AllowedOriginRedirect(origins, callbacks)),
            build_opener(HTTPCookieProcessor(cookie_jar), SameOriginNoRedirect()),
        )
    opener = build_opener(HTTPCookieProcessor(cookie_jar), SameOriginNoRedirect())
    return opener, opener


def build_system_opener(config: dict):
    return build_system_openers(config)[0]


def classify_http(status: int) -> str:
    if status == 401:
        return "authentication_failed"
    if status == 403:
        return "authorization_denied"
    if status == 404:
        return "automation_contract_changed"
    if status >= 500:
        return "dependency_unhealthy"
    return "assertion_failed"


def safe_error_fields(raw: bytes, variables=None) -> dict:
    """Keep only bounded, non-secret diagnostic fields from a JSON error body."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    result = {}
    code = data.get("code")
    if isinstance(code, (str, int, float)) and not isinstance(code, bool):
        result["server_code"] = code
    message = data.get("message")
    if isinstance(message, str) and message.strip():
        message = message.strip()[:300]
        for value in (variables or {}).values():
            if value not in (None, ""):
                message = message.replace(str(value), "***")
                if isinstance(value, str):
                    message = message.replace(base64.b64encode(value.encode()).decode(), "***")
        result["server_message"] = message
    return result


def execute_check(check: dict, config: dict, opener, variables=None) -> dict:
    started = time.monotonic()
    path = check["path"]
    resolved_path = resolve_env(path, variables)
    url = check.get("origin", config["base_url"]).rstrip("/") + resolved_path
    result = {
        "id": check["id"], "name": check["name"], "status": "failed",
        "category": check.get("category"), "type": "api",
        "method": check["method"], "path": path, "started_at": utc_now(),
        "assertions": [], "evidence": {}, "classification": None,
        "severity": check.get("severity", "P2"),
        "alert_enabled": check.get("alert_enabled", True),
    }
    try:
        body = resolve_env(check.get("body"), variables)
        headers = resolve_env(check.get("headers", {}), variables)
        if body is None:
            payload = None
        elif check.get("body_encoding") == "form":
            payload = urlencode(body, doseq=True).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            payload = json.dumps(body, ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        request = Request(url, data=payload, headers=headers, method=check["method"])
        try:
            timeout = check.get("timeout_seconds", config.get("default_timeout_seconds", 10))
            response = opener.open(request, timeout=min(max(float(timeout), 1), 30))
        except HTTPError as error:
            response = error
        with response:
            status = response.status
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("响应超过 1 MiB 上限")
            result["evidence"] = {
                "http_status": status,
                "content_type": response.headers.get("Content-Type", ""),
                "request_id": response.headers.get("X-Request-Id", ""),
                "response_sha256": hashlib.sha256(raw).hexdigest(),
                "response_bytes": len(raw),
            }
            if status != check.get("expected_status", 200):
                error_fields = safe_error_fields(raw, variables)
                result["evidence"].update(error_fields)
                if check.get("login_precheck") and status in (400, 401, 403):
                    result["classification"] = "authentication_failed"
                else:
                    result["classification"] = classify_http(status)
                reason = f"HTTP 状态 {status}，预期 {check.get('expected_status', 200)}"
                if error_fields.get("server_message"):
                    reason += f"；服务端：{error_fields['server_message']}"
                result["reason"] = reason
            else:
                no_response_body = check["method"] == "HEAD" or status in (204, 205, 304)
                data = None if no_response_body or check.get("response_type", "json") == "text" else json.loads(raw)
                resolved_assertions = resolve_env(check["assertions"], variables)
                result["assertions"] = evaluate(data, resolved_assertions) if data is not None else []
                if data is None and resolved_assertions:
                    result["classification"] = "automation_contract_changed"
                    result["reason"] = "无响应体或文本响应不能执行 JSON 业务断言"
                elif not all(item["passed"] for item in result["assertions"]):
                    result["classification"] = "assertion_failed"
                    result["reason"] = "业务断言未通过"
                else:
                    extracted = {}
                    for rule in check.get("extract", []):
                        if rule.get("path"):
                            exists, value = lookup(data, rule["path"]) if data is not None else (False, None)
                        else:
                            source = str(response.headers) if rule.get("source") == "headers" else raw.decode("utf-8", "replace")
                            matched = re.search(rule["pattern"], source)
                            exists, value = bool(matched), matched.group(1) if matched and matched.groups() else (matched.group(0) if matched else None)
                        if not exists or value in (None, "", [], {}):
                            result["classification"] = "automation_contract_changed"
                            result["reason"] = f"无法提取运行变量 {rule['variable']}"
                            break
                        extracted[rule["variable"]] = value
                    else:
                        if variables is not None:
                            variables.update(extracted)
                        result["status"] = "passed"
    except (TimeoutError, socket.timeout) as error:
        result["classification"], result["reason"] = "timeout", str(error)
    except URLError as error:
        result["classification"], result["reason"] = "network_unreachable", str(error.reason)
    except (json.JSONDecodeError, UnicodeDecodeError):
        result["classification"], result["reason"] = "automation_contract_changed", "响应不是预期 JSON"
    except ValueError as error:
        result["classification"], result["reason"] = "data_precondition_missing", str(error)
    finally:
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        result["finished_at"] = utc_now()
    return result


def run_ui_with_api_auth(checks, config, variables, store, flow_contexts=None):
    """Prepare fresh API authentication even for a UI-only run or editor test.

    A combined run can reuse the same run's API flow. Separate authentication
    flows/entry URLs get separate browser contexts so accounts cannot mix.
    """
    cache = flow_contexts if flow_contexts is not None else {}
    flows = {flow["id"]: flow for flow in config.get("api_auth_flows", [])}
    groups = {}
    for check in checks:
        dependency = check.get("auth_dependency") or {}
        flow_id = dependency.get("api_flow_id")
        entry = dependency.get("entry_url") or flows.get(flow_id, {}).get("browser_entry_url", "")
        key = (flow_id, entry)
        groups.setdefault(key, []).append(check)
    results = []
    for (flow_id, entry_url), group in groups.items():
        if not flow_id:
            results.extend(run_ui_checks(group, config, variables, store))
            continue
        flow = flows.get(flow_id)
        if not flow or not flow.get("enabled"):
            raise ValueError(f"API 登录前置流程不存在或未启用: {flow_id}")
        if flow_id not in cache:
            cache[flow_id] = execute_auth_flow(config, flow, variables, execute_check, build_system_openers)
        outcome, exports, openers = cache[flow_id]
        auth = {
            "id": flow_id, "name": flow["name"], "status": outcome["status"],
            "variables": exports, "cookies": browser_cookies(openers) if outcome["status"] == "passed" else [],
            "entry_url": entry_url,
            "duration_ms": sum(item.get("duration_ms", 0) for item in outcome["checks"]),
            "reason": next((item.get("reason") for item in outcome["checks"] if item["status"] == "failed"), None),
        }
        results.extend(run_ui_checks(group, config, variables, store, api_auth_context=auth))
    return results


def inspection_timeout_budget(config, enabled):
    """Include implicit API authentication and browser bootstrap in the lease."""
    ui_timeout = config.get("ui", {}).get("default_timeout_seconds", 15)
    api_timeout = config.get("default_timeout_seconds", 10)
    total = sum(
        sum(step.get("timeout_seconds", ui_timeout) for step in check.get("steps", []))
        if check.get("type", "api") == "ui" else check.get("timeout_seconds", api_timeout)
        for check in enabled
    )
    flows = {flow["id"]: flow for flow in config.get("api_auth_flows", [])}
    dependencies = {(check["auth_dependency"]["api_flow_id"], check["auth_dependency"].get("entry_url")
                     or flows.get(check["auth_dependency"]["api_flow_id"], {}).get("browser_entry_url", ""))
                    for check in enabled if check.get("type") == "ui"
                    and (check.get("auth_dependency") or {}).get("api_flow_id")}
    counted = {check["id"] for check in enabled if check.get("type", "api") == "api"}
    by_id = {check["id"]: check for check in config["checks"]}
    for flow in config.get("api_auth_flows", []):
        if flow["id"] in {flow_id for flow_id, _ in dependencies}:
            for step_id in flow["step_ids"]:
                if step_id not in counted:
                    total += by_id[step_id].get("timeout_seconds", api_timeout)
                    counted.add(step_id)
    total += sum(3 * ui_timeout + min(ui_timeout, 5) for _, entry in dependencies if entry)
    return int(total)


def run_inspection(config: dict, config_version: str, initial_variables: dict | None = None,
                   run_id: str | None = None, trigger: str = "manual",
                   scheduled_for: str | None = None,
                   artifact_root: Path | None = None,
                   targets: list[str] | None = None) -> dict:
    active_targets, enabled = enabled_run_targets(
        config, targets, strict=targets is not None,
    )
    report = {
        "run_id": run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8],
        "system_id": config["system_id"], "environment": config["environment"],
        "config_version": config_version, "started_at": utc_now(),
        "finished_at": None, "status": "running", "checks": [],
        "trigger": trigger, "scheduled_for": scheduled_for,
        "targets": active_targets,
        "phase_status": {target: "running" for target in active_targets},
    }
    api_checks = [item for item in enabled if item.get("type", "api") == "api"]
    ui_checks = [item for item in enabled if item.get("type", "api") == "ui"]
    flow_contexts = {}
    if api_checks:
        redirect_opener, no_redirect_opener = build_system_openers(config)
        api_variables = dict(config.get("variables", {}))
        api_variables.update(initial_variables or {})
        grouped = flow_step_ids(config)
        for flow in config.get("api_auth_flows", []):
            if not flow["enabled"]:
                continue
            outcome, exports, openers = execute_auth_flow(config, flow, api_variables, execute_check, build_system_openers)
            flow_contexts[flow["id"]] = (outcome, exports, openers)
            report["checks"].extend(outcome["checks"])
        login_failed = False
        for check in api_checks:
            if check["id"] in grouped:
                continue
            dependency = check.get("auth_flow_id")
            if dependency:
                outcome, exports, openers = flow_contexts[dependency]
                if outcome["status"] != "passed":
                    report["checks"].append({"id": check["id"], "name": check["name"], "type": "api", "status": "skipped",
                        "classification": "authentication_failed", "reason": f"登录前置 {outcome['name']} 失败，未执行业务请求",
                        "assertions": [], "evidence": {}, "severity": check.get("severity", "P2"),
                        "alert_enabled": check.get("alert_enabled", True)})
                    continue
                scoped = dict(api_variables)
                scoped.update(exports)
                scoped.update(check.get("variables", {}))
                result = execute_check(check, config, openers[0] if check.get("follow_redirects", True) else openers[1], scoped)
                redact_auth_evidence(result, [exports.get("token"), scoped.get("SRM_PASSWORD")])
                report["checks"].append(result)
                if result["status"] == "passed":
                    exports.update({rule["variable"]: scoped[rule["variable"]] for rule in check.get("extract", [])
                                    if rule["variable"] in scoped and rule["variable"] not in check.get("variables", {})})
                continue
            if login_failed:
                report["checks"].append({
                    "id": check["id"], "name": check["name"], "type": "api", "status": "skipped",
                    "classification": "authentication_failed", "reason": "登录预检失败，停止后续业务检查",
                    "assertions": [], "evidence": {},
                    "severity": check.get("severity", "P2"),
                    "alert_enabled": check.get("alert_enabled", True),
                })
                continue
            scoped_variables = dict(api_variables)
            local_variables = set(check.get("variables", {}))
            scoped_variables.update(check.get("variables", {}))
            opener = redirect_opener if check.get("follow_redirects", True) else no_redirect_opener
            result = execute_check(check, config, opener, scoped_variables)
            api_variables.update({key: value for key, value in scoped_variables.items() if key not in local_variables})
            report["checks"].append(result)
            if (check.get("login_precheck") or check.get("session_setup")) and result["status"] != "passed":
                login_failed = True
    if ui_checks:
        if artifact_root is None:
            raise RuntimeError("UI 巡检缺少证据存储目录")
        store = ArtifactStore(artifact_root, report["run_id"])
        store.reset()
        ui_variables = dict(config.get("variables", {}))
        ui_variables.update(initial_variables or {})
        report["checks"].extend(run_ui_with_api_auth(ui_checks, config, ui_variables, store, flow_contexts))
    for target in active_targets:
        target_checks = [item for item in report["checks"] if item.get("type", "api") == target]
        report["phase_status"][target] = (
            "failed" if any(item.get("status") == "failed" for item in target_checks)
            else "passed" if any(item.get("status") == "passed" for item in target_checks)
            else "skipped"
        )
    report["status"] = "passed" if all(item["status"] == "passed" for item in report["checks"]) else "failed"
    report["finished_at"] = utc_now()
    report["counts"] = {key: sum(item["status"] == key for item in report["checks"])
                        for key in ("passed", "failed", "skipped")}
    return report


def _failed_runner_report(config: dict, config_version: str, run_id: str, trigger: str,
                          scheduled_for: str | None, error: Exception,
                          targets: list[str] | None = None) -> dict:
    now = utc_now()
    active_targets = normalize_run_targets(targets)
    checks = [{
        "id": f"__runner__:{target}", "name": f"{target.upper()} 巡检执行器",
        "type": target, "status": "failed", "classification": "execution_failed",
        "reason": f"巡检执行异常: {type(error).__name__}", "assertions": [],
        "evidence": {}, "duration_ms": 0, "severity": "P1", "alert_enabled": False,
    } for target in active_targets]
    return {
        "run_id": run_id, "system_id": config["system_id"],
        "environment": config["environment"], "config_version": config_version,
        "status": "failed", "started_at": now, "finished_at": now, "checks": checks,
        "counts": {"passed": 0, "failed": len(checks), "skipped": 0},
        "trigger": trigger, "scheduled_for": scheduled_for,
        "targets": active_targets,
        "phase_status": {target: "failed" for target in active_targets},
        "error": f"巡检执行异常: {type(error).__name__}",
    }


def run_inspection_with_retry(config: dict, config_version: str,
                              initial_variables: dict | None = None,
                              run_id: str | None = None, trigger: str = "manual",
                              scheduled_for: str | None = None,
                              sleep_fn=None, run_once=None,
                              artifact_root: Path | None = None,
                              targets: list[str] | None = None) -> dict:
    """Run API and UI as independently retried phases and combine their final results."""
    run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    active_targets, _ = enabled_run_targets(config, targets, strict=targets is not None)
    retry = config.get("run_retry", {})
    enabled = bool(retry.get("enabled", False))
    max_retries = int(retry.get("max_retries", 2)) if enabled else 0
    delay_seconds = int(retry.get("delay_seconds", 30))
    runner = run_once or run_inspection
    sleeper = sleep_fn or time.sleep
    phase_reports = {}
    phase_retries = {}
    for target in active_targets:
        attempts = []
        phase_report = None
        for attempt_number in range(1, max_retries + 2):
            if attempt_number > 1:
                sleeper(delay_seconds)
            try:
                phase_report = runner(
                    config, config_version, initial_variables,
                    run_id=run_id, trigger=trigger, scheduled_for=scheduled_for,
                    artifact_root=artifact_root, targets=[target],
                )
            except Exception as error:
                phase_report = _failed_runner_report(
                    config, config_version, run_id, trigger, scheduled_for, error, [target]
                )
            attempts.append({
                "attempt": attempt_number,
                "status": phase_report.get("status", "failed"),
                "started_at": phase_report.get("started_at"),
                "finished_at": phase_report.get("finished_at"),
                "counts": phase_report.get("counts", {}),
                "failures": [
                    {"id": item.get("id"), "classification": item.get("classification")}
                    for item in phase_report.get("checks", []) if item.get("status") == "failed"
                ],
            })
            if phase_report.get("status") == "passed":
                break
        phase_report["started_at"] = attempts[0]["started_at"]
        phase_retry = {
            "enabled": enabled,
            "max_retries": max_retries,
            "delay_seconds": delay_seconds,
            "attempt_count": len(attempts),
            "recovered": len(attempts) > 1 and phase_report.get("status") == "passed",
            "exhausted": enabled and phase_report.get("status") != "passed" and len(attempts) == max_retries + 1,
            "attempts": attempts,
        }
        phase_report["retry"] = phase_retry
        phase_reports[target] = phase_report
        phase_retries[target] = phase_retry

    if len(active_targets) == 1:
        report = phase_reports[active_targets[0]]
        report["targets"] = active_targets
        report["phase_status"] = {active_targets[0]: report.get("status", "failed")}
        report["phase_retry"] = phase_retries
        return report

    first = phase_reports[active_targets[0]]
    last = phase_reports[active_targets[-1]]
    checks = []
    phase_errors = {}
    for target in active_targets:
        for item in phase_reports[target].get("checks", []):
            item.setdefault("type", target)
            checks.append(item)
        if phase_reports[target].get("error"):
            phase_errors[target] = phase_reports[target]["error"]
    counts = {
        status: sum(item.get("status") == status for item in checks)
        for status in ("passed", "failed", "skipped")
    }
    phase_status = {target: phase_reports[target].get("status", "failed") for target in active_targets}
    report = {
        "run_id": run_id, "system_id": config["system_id"],
        "environment": config["environment"], "config_version": config_version,
        "started_at": first.get("started_at"), "finished_at": last.get("finished_at"),
        "status": "passed" if all(value == "passed" for value in phase_status.values()) else "failed",
        "checks": checks, "counts": counts, "trigger": trigger,
        "scheduled_for": scheduled_for, "targets": active_targets,
        "phase_status": phase_status, "phase_retry": phase_retries,
        "retry": {
            "enabled": enabled, "max_retries": max_retries, "delay_seconds": delay_seconds,
            "attempt_count": max(value["attempt_count"] for value in phase_retries.values()),
            "recovered": any(value["recovered"] for value in phase_retries.values()),
            "exhausted": any(value["exhausted"] for value in phase_retries.values()),
        },
    }
    if phase_errors:
        report["phase_errors"] = phase_errors
    return report


class InspectionState:
    def __init__(self, config_path: Path, data_dir: Path, secrets_path: Path | None = None,
                 runtime_path: Path | None = None, expected_system_id: str | None = None,
                 use_environment_fallback: bool = True,
                 run_semaphore: threading.BoundedSemaphore | None = None):
        self.config_path = config_path
        self.repository = ConfigRepository(config_path)
        self.data_dir = data_dir
        self.expected_system_id = expected_system_id
        self.run_semaphore = run_semaphore
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_dir = data_dir.parent / "artifacts"
        self.ui_test_artifact_dir = data_dir.parent / "ui-test-artifacts"
        self.credentials = CredentialStore(
            secrets_path or data_dir.parent / "secrets.json", use_environment_fallback
        )
        self.audit_dir = data_dir.parent / "config-audit"
        self.lock = threading.Lock()
        self.active: dict | None = None
        self.runtime = RuntimeStore(runtime_path or data_dir.parent / "runtime.db")
        self.public_url = inspection_public_url()
        self.alerts = AlertEngine(self.runtime, lambda: self.public_url)
        self.notifier = WebhookNotifier(
            self.runtime,
            lambda: self.credentials.runtime_variables().get("ALERT_WEBHOOK_URL", ""),
            lambda: self.credentials.runtime_variables().get("DINGTALK_SECRET", ""),
        )
        self.scheduler = ScheduleEngine(
            self.repository.load, self.runtime,
            self.start_run, self.alerts, self.notifier,
        )

    def start_background(self) -> None:
        self.scheduler.start()

    def stop_background(self) -> None:
        self.scheduler.stop()

    def list_report_details(self, limit: int | None = 30) -> list[dict]:
        reports = []
        paths = sorted(self.data_dir.glob("*.json"), reverse=True)
        if limit is not None:
            paths = paths[:limit]
        for path in paths:
            try:
                reports.append(json.loads(path.read_text()))
            except (OSError, json.JSONDecodeError):
                continue
        return reports

    @staticmethod
    def report_view(report: dict, kind: str) -> dict | None:
        """Return one independent API or UI view of a combined inspection run."""
        if kind not in ("api", "ui"):
            raise ValueError("报告类型无效")
        checks = [
            copy.deepcopy(item) for item in report.get("checks", [])
            if item.get("type", "api") == kind
        ]
        if not checks:
            return None
        counts = {
            status: sum(item.get("status") == status for item in checks)
            for status in ("passed", "failed", "skipped")
        }
        status = "failed" if counts["failed"] else "passed" if counts["passed"] else "skipped"
        durations = sorted(max(0, int(item.get("duration_ms") or 0)) for item in checks)
        percentile_index = max(0, math.ceil(len(durations) * .95) - 1)
        screenshot_count = sum(
            int((item.get("evidence") or {}).get("screenshot_count") or 0)
            for item in checks
        )
        steps = [step for item in checks for step in item.get("steps", [])]
        view = copy.deepcopy(report)
        view.update({
            "report_kind": kind,
            "status": status,
            "counts": counts,
            "checks": checks,
            "duration_ms": sum(durations),
            "average_duration_ms": round(sum(durations) / len(durations)) if durations else 0,
            "p95_duration_ms": durations[percentile_index] if durations else 0,
            "screenshot_count": screenshot_count,
            "step_count": len(steps),
            "failed_step_count": sum(step.get("status") == "failed" for step in steps),
            "retry": copy.deepcopy((report.get("phase_retry") or {}).get(kind, report.get("retry", {}))),
        })
        return view

    @staticmethod
    def report_summary(report: dict) -> dict:
        return {key: report.get(key) for key in (
            "run_id", "system_id", "environment", "report_kind", "status",
            "started_at", "finished_at", "counts", "trigger", "duration_ms",
            "average_duration_ms", "p95_duration_ms", "screenshot_count",
            "step_count", "failed_step_count", "targets", "phase_status",
        )}

    def list_reports(self, limit: int = 30, kind: str | None = None) -> list[dict]:
        if kind is None:
            return [self.report_summary(item) for item in self.list_report_details(limit)]
        reports = []
        for item in self.list_report_details(None):
            view = self.report_view(item, kind)
            if view:
                reports.append(self.report_summary(view))
            if len(reports) >= limit:
                break
        return reports

    def read_report(self, run_id: str) -> dict | None:
        if not re.fullmatch(r"[0-9TZ-]+[a-f0-9]{8}", run_id):
            return None
        with self.lock:
            if self.active and self.active["run_id"] == run_id:
                return self.active.copy()
        path = self.data_dir / f"{run_id}.json"
        return json.loads(path.read_text()) if path.exists() else None

    def read_report_view(self, run_id: str, kind: str) -> dict | None:
        report = self.read_report(run_id)
        return self.report_view(report, kind) if report else None

    def read_artifact(self, run_id: str, artifact_id: str) -> Path | None:
        if not re.fullmatch(r"[0-9TZ-]+[a-f0-9]{8}", run_id):
            return None
        return resolve_artifact(self.artifact_dir, run_id, artifact_id)

    def read_ui_test_artifact(self, test_id: str, artifact_id: str) -> Path | None:
        if not re.fullmatch(r"uitest-[a-f0-9]{12}", test_id):
            return None
        return resolve_artifact(self.ui_test_artifact_dir, test_id, artifact_id)

    def _cleanup_ui_test_artifacts(self, keep: int = 20) -> None:
        if not self.ui_test_artifact_dir.exists():
            return
        directories = sorted(
            (path for path in self.ui_test_artifact_dir.iterdir() if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for path in directories[keep:]:
            try:
                remove_run_artifacts(self.ui_test_artifact_dir, path.name)
            except (OSError, ValueError):
                continue

    def cleanup_reports(self, limit: int) -> None:
        for path in sorted(self.data_dir.glob("*.json"), reverse=True)[limit:]:
            run_id = path.stem
            path.unlink(missing_ok=True)
            try:
                remove_run_artifacts(self.artifact_dir, run_id)
            except ValueError:
                continue

    def summary(self) -> dict:
        config, version = self.repository.load()
        report_details = self.list_report_details(min(config.get("report_limit", 30), 180))
        reports = [{key: item.get(key) for key in
                    ("run_id", "system_id", "environment", "status", "started_at", "finished_at", "counts", "trigger", "targets", "phase_status")}
                   for item in report_details]
        with self.lock:
            active_id = self.active["run_id"] if self.active else None
        active_lease = self.runtime.active_lease()
        return {
            "system_id": config["system_id"], "environment": config["environment"],
            "display_name": config.get("display_name", config["system_id"]),
            "adapter": config.get("adapter", "http-scenario-v1"),
            "config_version": version, "total_checks": len(config["checks"]),
            "enabled_checks": sum(bool(item.get("enabled")) for item in config["checks"]),
            "total_checks_by_type": {
                target: sum(item.get("type", "api") == target for item in config["checks"])
                for target in RUN_TARGETS
            },
            "enabled_checks_by_type": {
                target: sum(bool(item.get("enabled")) and item.get("type", "api") == target for item in config["checks"])
                for target in RUN_TARGETS
            },
            "report_limit": config.get("report_limit", 30),
            "active_run_id": active_id or (active_lease or {}).get("run_id"),
            "active_trigger": (self.active or {}).get("trigger") or (active_lease or {}).get("trigger_name"),
            "active_targets": (self.active or {}).get("targets"),
            "schedule": self.runtime.schedule_status(),
            "incidents": self.runtime.incident_counts(),
            "latest": reports[0] if reports else None,
            "trend": reports[:12][::-1],
            "analytics": build_overview_analytics(config, report_details),
        }

    def config_document(self) -> dict:
        config, version = self.repository.load()
        ui_verification = {}
        for check in config.get("checks", []):
            if check.get("type", "api") != "ui":
                continue
            record = self.runtime.get_metadata(_ui_verification_key(check["id"]), {})
            ui_verification[check["id"]] = {
                "verified": ui_verification_matches(check, record),
                "verified_at": record.get("verified_at") if isinstance(record, dict) else None,
            }
        versions = self.repository.versions()
        config = copy.deepcopy(config)
        for check in config.get("checks", []):
            check.pop("read_only", None)
        return {
            "config": config,
            "config_version": version,
            "settings_version": versions["settings_version"],
            "api_version": versions["api_version"],
            "ui_version": versions["ui_version"],
            "credentials": self.credentials.public_status(),
            "ui_verification": ui_verification,
        }

    def settings_document(self) -> dict:
        document = self.repository.settings_document()
        document["config_version"] = self.repository.load()[1]
        document["credentials"] = self.credentials.public_status()
        return document

    def api_checks_document(self) -> dict:
        document = self.repository.collection_document("api")
        config, _ = self.repository.load()
        document["verification"] = {}
        for flow in config.get("api_auth_flows", []):
            record = self.runtime.get_metadata("api-auth-verification:" + flow["id"], {})
            document["verification"][flow["id"]] = {
                "verified": record.get("flow_hash") == auth_flow_hash(config, flow, self.credentials.runtime_variables()),
                "verified_at": record.get("verified_at"),
            }
        document["enablement"] = {}
        for check in document["items"]:
            check.pop("read_only", None)
            reasons = api_enablement_issues(check, config)
            document["enablement"][check["id"]] = {"can_enable": not reasons, "reasons": reasons}
        return document

    def ui_scenes_document(self) -> dict:
        document = self.repository.collection_document("ui")
        document["verification"] = {}
        for scene in document["items"]:
            typed = {**scene, "type": "ui"}
            scene.pop("read_only", None)
            record = self.runtime.get_metadata(_ui_verification_key(scene.get("id", "")), {})
            document["verification"][scene.get("id", "")] = {
                "verified": ui_verification_matches(typed, record),
                "verified_at": record.get("verified_at") if isinstance(record, dict) else None,
            }
        return document

    def update_settings(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("settings"), dict):
            raise ValueError("缺少系统设置内容")
        expected_version = payload.get("version")
        if not isinstance(expected_version, str):
            raise ValueError("缺少系统设置版本")
        settings = copy.deepcopy(payload["settings"])
        if self.expected_system_id and settings.get("system_id") != self.expected_system_id:
            raise ValueError("system_id 与系统注册表不一致，不允许在设置页修改")
        credentials = payload.get("credentials", {})
        if not isinstance(credentials, dict) or any(
            value not in (None, "") and (not isinstance(value, str) or len(value) > 4096)
            for value in credentials.values()
        ):
            raise ValueError("凭据配置格式无效")
        old, _ = self.repository.load()
        new_version = self.repository.save_settings(settings, expected_version)
        self.credentials.update(credentials)
        new, _ = self.repository.load()
        self._write_config_audit(old, new, expected_version, new_version, domain="settings")
        return self.settings_document()

    def update_api_checks(self, payload: dict) -> dict:
        return self._update_collection("api", payload)

    def update_ui_scenes(self, payload: dict) -> dict:
        return self._update_collection("ui", payload)

    def _update_collection(self, kind: str, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise ValueError("缺少巡检配置集合")
        expected_version = payload.get("version")
        if not isinstance(expected_version, str):
            raise ValueError("缺少巡检配置版本")
        items = copy.deepcopy(payload["items"])
        old, _ = self.repository.load()
        if kind == "api":
            issues = []
            for item in items:
                if not isinstance(item, dict):
                    raise ValueError("检查项必须是 JSON 对象")
                refresh_api_pending_arguments(item, old)
                if item.get("enabled"):
                    reasons = api_enablement_issues(item, old)
                    if reasons:
                        issues.append(f"{item.get('name') or item.get('id')}（{item.get('id')}）：{'；'.join(reasons)}")
            if issues:
                raise ValueError("以下巡检项无法启用，整批未保存：\n" + "\n".join(issues))
        if kind == "api":
            candidate = copy.deepcopy(old)
            candidate["checks"] = [{**item, "type": "api"} for item in items] + [item for item in old["checks"] if item.get("type") == "ui"]
            candidate["api_auth_flows"] = copy.deepcopy(payload.get("auth_flows", old.get("api_auth_flows", [])))
            validate_config(candidate)
            self._require_auth_verification(candidate, old)
        new_version = self.repository.save_collection(kind, items, expected_version,
            candidate["api_auth_flows"] if kind == "api" else None)
        new, _ = self.repository.load()
        self._write_config_audit(old, new, expected_version, new_version, domain=kind)
        return self.ui_scenes_document() if kind == "ui" else self.api_checks_document()

    def create_collection_item(self, kind: str, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("item"), dict):
            raise ValueError("缺少巡检配置项")
        document = self.repository.collection_document(kind)
        item = copy.deepcopy(payload["item"])
        if any(existing.get("id") == item.get("id") for existing in document["items"]):
            raise ValueError(f"检查项 ID 已存在: {item.get('id', '')}")
        return self._update_collection(kind, {
            "version": payload.get("version"), "items": [*document["items"], item],
        })

    def update_collection_item(self, kind: str, item_id: str, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("item"), dict):
            raise ValueError("缺少巡检配置项")
        if payload["item"].get("id") != item_id:
            raise ValueError("检查项 ID 创建后不可修改")
        document = self.repository.collection_document(kind)
        index = next((i for i, item in enumerate(document["items"]) if item.get("id") == item_id), None)
        if index is None:
            raise ValueError("检查项不存在")
        document["items"][index] = copy.deepcopy(payload["item"])
        return self._update_collection(kind, {
            "version": payload.get("version"), "items": document["items"],
        })

    def delete_collection_item(self, kind: str, item_id: str, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("version"), str):
            raise ValueError("缺少巡检配置版本")
        document = self.repository.collection_document(kind)
        if payload["version"] != document["version"]:
            raise RuntimeError("配置已被其他页面更新，请重新加载后再删除")
        if not any(item.get("id") == item_id for item in document["items"]):
            raise ValueError("检查项不存在")
        if kind == "ui":
            dependents = [
                item.get("name") or item["id"] for item in document["items"]
                if (item.get("auth_dependency") or {}).get("scene_id") == item_id
            ]
            if dependents:
                raise ValueError(f"该登录前置场景被以下场景引用，请先解除关联：{'、'.join(dependents)}")
        return self._update_collection(kind, {
            "version": payload["version"],
            "items": [item for item in document["items"] if item.get("id") != item_id],
        })

    def import_api_checks(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
            raise ValueError("缺少导入内容")
        expected_version = payload.get("version")
        if not isinstance(expected_version, str):
            raise ValueError("缺少 API 巡检版本")
        current, _ = self.repository.load()
        imported = import_metersphere(payload["content"], current)
        items = [
            ConfigRepository._without_type(item) for item in imported["checks"]
            if item.get("type", "api") != "ui"
        ]
        return self._update_collection("api", {"version": expected_version, "items": items,
            "auth_flows": imported.get("api_auth_flows", [])})

    def validate_document(self, payload: dict) -> dict:
        config = payload.get("config") if isinstance(payload, dict) else None
        validate_config(config)
        if self.expected_system_id and config["system_id"] != self.expected_system_id:
            raise ValueError("system_id 与系统注册表不一致，不允许在配置页修改")
        return {"valid": True, "enabled_checks": sum(bool(item.get("enabled")) for item in config["checks"])}

    def update_config(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("config"), dict):
            raise ValueError("缺少配置内容")
        config = payload["config"]
        expected_version = payload.get("config_version")
        validate_config(config)
        if self.expected_system_id and config["system_id"] != self.expected_system_id:
            raise ValueError("system_id 与系统注册表不一致，不允许在配置页修改")
        old_config, current_version = self.repository.load()
        if not isinstance(expected_version, str) or expected_version != current_version:
            raise RuntimeError("配置已被其他页面更新，请重新加载后再保存")
        self._require_auth_verification(config, old_config, payload.get("credentials", {}))
        self.credentials.update(payload.get("credentials", {}))
        new_version = self.repository.save_aggregate(config, expected_version)
        self._write_config_audit(old_config, config, current_version, new_version)
        return self.config_document()

    def _write_config_audit(self, old: dict, new: dict, old_version: str, new_version: str,
                            domain: str = "aggregate") -> None:
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        old_checks = {item["id"]: item for item in old.get("checks", [])}
        new_checks = {item["id"]: item for item in new.get("checks", [])}
        changed = sorted(key for key in set(old_checks) | set(new_checks) if old_checks.get(key) != new_checks.get(key))
        record = {
            "updated_at": utc_now(), "old_version": old_version, "new_version": new_version,
            "domain": domain,
            "environment_changed": old.get("environment") != new.get("environment"),
            "base_url_changed": old.get("base_url") != new.get("base_url"),
            "schedule_changed": old.get("schedule", {}) != new.get("schedule", {}),
            "run_retry_changed": old.get("run_retry", {}) != new.get("run_retry", {}),
            "alerts_changed": old.get("alerts", {}) != new.get("alerts", {}),
            "changed_checks": changed,
            "changed_auth_flows": sorted(key for key in {f["id"] for f in old.get("api_auth_flows", [])} | {f["id"] for f in new.get("api_auth_flows", [])}
                if next((f for f in old.get("api_auth_flows", []) if f["id"] == key), None) != next((f for f in new.get("api_auth_flows", []) if f["id"] == key), None)),
        }
        name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + ".json"
        target = self.audit_dir / name
        target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        os.chmod(target, 0o600)

    def import_config(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("content"), str):
            raise ValueError("缺少导入内容")
        current, version = self.repository.load()
        imported = import_metersphere(payload["content"], current)
        return {"config": imported, "config_version": version, "credentials": self.credentials.public_status()}

    def preflight(self) -> dict:
        config, version = self.repository.load()
        api_session_checks = [
            item for item in config["checks"]
            if item.get("enabled") and item.get("type", "api") == "api"
            and (item.get("session_setup") or item.get("login_precheck"))
        ]
        ui_session_checks = [
            item for item in config["checks"]
            if item.get("enabled") and item.get("type", "api") == "ui"
            and item.get("login_precheck")
        ]
        flows = [flow for flow in config.get("api_auth_flows", []) if flow["enabled"]]
        api_session_checks = [check for check in api_session_checks if check["id"] not in flow_step_ids(config)]
        if not api_session_checks and not ui_session_checks and not flows:
            raise ValueError("没有已启用的登录预检项")
        redirect_opener, no_redirect_opener = build_system_openers(config)
        variables = dict(config.get("variables", {}))
        variables.update(self.credentials.runtime_variables())
        results = []
        for flow in flows:
            outcome, exports, _ = execute_auth_flow(config, flow, variables, execute_check, build_system_openers)
            results.extend(outcome["checks"])
            if outcome["status"] != "passed":
                return {"config_version": version, "status": "failed", "check": next(item for item in outcome["checks"] if item["status"] == "failed"), "checks": results}
            variables.update(exports)
        for check in api_session_checks:
            scoped = dict(variables)
            scoped.update(check.get("variables", {}))
            opener = redirect_opener if check.get("follow_redirects", True) else no_redirect_opener
            result = execute_check(check, config, opener, scoped)
            results.append(result)
            variables.update({key: value for key, value in scoped.items() if key not in check.get("variables", {})})
            if result["status"] != "passed":
                break
        if all(item["status"] == "passed" for item in results) and ui_session_checks:
            with tempfile.TemporaryDirectory(prefix="srm-ui-preflight-") as temp:
                store = ArtifactStore(Path(temp), "ui-preflight")
                store.reset()
                ui_results = run_ui_with_api_auth(ui_session_checks, config, variables, store)
            for result in ui_results:
                for step in result.get("steps", []):
                    step.pop("screenshot", None)
                    step.pop("failure_screenshot", None)
                result.get("evidence", {}).pop("trace", None)
                result.get("evidence", {}).pop("screenshot_count", None)
            results.extend(ui_results)
        final = results[-1]
        return {
            "config_version": version,
            "status": "passed" if len(results) == sum(len(flow["step_ids"]) for flow in flows) + len(api_session_checks) + len(ui_session_checks)
            and all(item["status"] == "passed" for item in results) else "failed",
            "check": final,
            "checks": results,
        }

    def test_check(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("check"), dict):
            raise ValueError("缺少待测试的接口配置")
        config, version = self.repository.load()
        candidate = copy.deepcopy(payload["check"])
        check_id = candidate.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", check_id):
            raise ValueError("检查项 ID 格式无效")
        if not isinstance(candidate.get("name"), str) or not candidate["name"].strip():
            raise ValueError(f"{check_id}: 名称不能为空")
        candidate["enabled"] = True
        if candidate.get("type", "api") == "api":
            refresh_api_pending_arguments(candidate, config)
        validate_enabled_check(candidate, config)
        if candidate.get("type", "api") == "ui":
            raise ValueError("UI 检查请保存后通过完整巡检执行，以生成隔离的报告证据")

        if check_id in flow_step_ids(config):
            raise ValueError("登录步骤请在登录前置编辑器中执行完整流程测试")
        redirect_opener, no_redirect_opener = build_system_openers(config)
        variables = dict(config.get("variables", {}))
        variables.update(self.credentials.runtime_variables())
        dependency = candidate.get("auth_flow_id")
        if dependency:
            flow = next((f for f in config.get("api_auth_flows", []) if f["id"] == dependency), None)
            if not flow or not flow["enabled"]:
                raise ValueError("请先验证并启用所选登录前置流程")
            outcome, exports, openers = execute_auth_flow(config, flow, variables, execute_check, build_system_openers)
            if outcome["status"] != "passed":
                return {"config_version": version, "status": "failed", "session_checks": outcome["checks"], "check": None}
            variables.update(exports)
            scoped = dict(variables)
            scoped.update(candidate.get("variables", {}))
            result = execute_check(candidate, config, openers[0] if candidate.get("follow_redirects", True) else openers[1], scoped)
            redact_auth_evidence(result, [exports.get("token"), scoped.get("SRM_PASSWORD")])
            return {"config_version": version, "status": result["status"], "session_checks": outcome["checks"], "check": result}
        session_checks = [
            item for item in config["checks"]
            if item.get("enabled") and item.get("type", "api") == "api"
            and (item.get("session_setup") or item.get("login_precheck"))
            and item.get("id") != check_id and item.get("id") not in flow_step_ids(config)
        ]
        session_results = []
        for check in session_checks:
            scoped = dict(variables)
            local_variables = set(check.get("variables", {}))
            scoped.update(check.get("variables", {}))
            opener = redirect_opener if check.get("follow_redirects", True) else no_redirect_opener
            result = execute_check(check, config, opener, scoped)
            session_results.append(result)
            variables.update({key: value for key, value in scoped.items() if key not in local_variables})
            if result["status"] != "passed":
                return {
                    "config_version": version, "status": "failed",
                    "session_checks": session_results, "check": None,
                }

        scoped = dict(variables)
        scoped.update(candidate.get("variables", {}))
        opener = redirect_opener if candidate.get("follow_redirects", True) else no_redirect_opener
        result = execute_check(candidate, config, opener, scoped)
        return {
            "config_version": version, "status": result["status"],
            "session_checks": session_results, "check": result,
        }

    def _require_auth_verification(self, config: dict, old: dict, credentials=None) -> None:
        previous = {flow["id"]: flow for flow in old.get("api_auth_flows", [])}
        runtime_credentials = self.credentials.runtime_variables()
        for flow in config.get("api_auth_flows", []):
            if not flow["enabled"]:
                continue
            prior = previous.get(flow["id"])
            if prior and prior["enabled"] and auth_flow_hash(old, prior, runtime_credentials) == auth_flow_hash(config, flow, runtime_credentials):
                continue
            if any(value not in (None, "") for value in (credentials or {}).values()):
                raise ValueError("请先保存访问凭据，再完整测试并启用登录前置流程")
            record = self.runtime.get_metadata("api-auth-verification:" + flow["id"], {})
            if record.get("flow_hash") != auth_flow_hash(config, flow, runtime_credentials):
                raise ValueError(f"{flow['name']}: 请先完整测试通过，再整体启用登录前置流程")

    def test_auth_flow(self, payload: dict) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("flow"), dict) or not isinstance(payload.get("steps"), list):
            raise ValueError("需要登录前置流程及其步骤配置")
        config, version = self.repository.load()
        candidate = copy.deepcopy(config)
        flow = copy.deepcopy(payload["flow"])
        flow["enabled"] = True
        steps = copy.deepcopy(payload["steps"])
        if not isinstance(flow.get("step_ids"), list) or any(not isinstance(sid, str) for sid in flow["step_ids"]):
            raise ValueError("流程需要有效的步骤 ID 列表")
        if [step.get("id") for step in steps if isinstance(step, dict)] != flow.get("step_ids"):
            raise ValueError("测试步骤必须与流程步骤顺序一致")
        other_members = {sid for f in config.get("api_auth_flows", []) if f["id"] != flow.get("id") for sid in f["step_ids"]}
        if other_members.intersection(flow.get("step_ids", [])):
            raise ValueError("登录步骤已属于其他流程")
        original_members = {sid for f in config.get("api_auth_flows", []) if f["id"] == flow.get("id") for sid in f["step_ids"]}
        for step in steps:
            step.update(enabled=True, type="api", session_setup=True)
            refresh_api_pending_arguments(step, candidate)
        candidate["checks"] = [item for item in candidate["checks"] if item["id"] not in original_members | set(flow.get("step_ids", []))] + steps
        candidate["api_auth_flows"] = [f for f in config.get("api_auth_flows", []) if f["id"] != flow.get("id")] + [flow]
        validate_config(candidate)
        credentials = self.credentials.runtime_variables()
        variables = dict(candidate.get("variables", {}))
        variables.update(credentials)
        outcome, _, _ = execute_auth_flow(candidate, flow, variables, execute_check, build_system_openers)
        # Only the contract hash is stored; tokens and cookies are discarded.
        if outcome["status"] == "passed":
            self.runtime.set_metadata("api-auth-verification:" + flow["id"], {
                "flow_hash": auth_flow_hash(candidate, flow, credentials), "verified_at": utc_now(),
            })
        else:
            self.runtime.set_metadata("api-auth-verification:" + flow["id"], {})
        return {**outcome, "config_version": version, "verified": outcome["status"] == "passed"}

    def ui_capabilities(self) -> dict:
        return {
            "playwright_installed": importlib.util.find_spec("playwright") is not None,
            "browser": "chromium",
            "actions": sorted(UI_ACTIONS),
            "locators": ["test_id", "role", "label", "placeholder", "text", "css"],
            "read_only_enforced": False,
            "test_before_enable": False,
        }

    def test_ui_check(self, payload: dict, through_step: bool = False) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("check"), dict):
            raise ValueError("缺少待测试的 UI 场景配置")
        config, version = self.repository.load()
        candidate = copy.deepcopy(payload["check"])
        check_id = str(candidate.get("id", ""))
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", check_id):
            raise ValueError("检查项 ID 格式无效")
        if candidate.get("type") != "ui":
            raise ValueError("仅支持测试 type=ui 的场景")
        if not isinstance(candidate.get("name"), str) or not candidate["name"].strip():
            raise ValueError(f"{check_id}: 名称不能为空")

        candidate["enabled"] = True
        validate_enabled_check(candidate, config)
        full_test = not through_step
        if through_step:
            step_id = str(payload.get("through_step_id", ""))
            steps = candidate.get("steps") if isinstance(candidate.get("steps"), list) else []
            match_index = next((index for index, step in enumerate(steps) if step.get("id") == step_id), None)
            if match_index is None:
                raise ValueError("未找到需要测试到达的步骤")
            candidate["steps"] = steps[:match_index + 1]

        dependency_id = (candidate.get("auth_dependency") or {}).get("scene_id")
        session_checks = [] if candidate.get("login_precheck") or (candidate.get("auth_dependency") or {}).get("api_flow_id") else [
            copy.deepcopy(item) for item in config["checks"]
            if item.get("enabled") and item.get("type", "api") == "ui"
            and item.get("login_precheck") and item.get("id") != check_id
            and (not dependency_id or item.get("id") == dependency_id)
        ]
        checks = [*session_checks, candidate]
        dependency_config = {**config, "checks": [item for item in config["checks"] if item["id"] != check_id] + [candidate]}
        _validate_ui_auth_dependencies(dependency_config)
        variables = dict(config.get("variables", {}))
        variables.update(self.credentials.runtime_variables())
        test_id = f"uitest-{uuid.uuid4().hex[:12]}"
        store = ArtifactStore(self.ui_test_artifact_dir, test_id)
        store.reset()
        results = run_ui_with_api_auth(checks, config, variables, store)
        candidate_result = next((item for item in results if item.get("id") == check_id), None)
        status = "passed" if candidate_result and candidate_result.get("status") == "passed" \
            and all(item.get("status") == "passed" for item in results) else "failed"
        if full_test and status == "passed":
            self.runtime.set_metadata(_ui_verification_key(check_id), {
                "check_hash": ui_check_hash(payload["check"]),
                "verified_at": utc_now(),
                "config_version": version,
            })
        self._cleanup_ui_test_artifacts()
        return {
            "test_id": test_id,
            "config_version": version,
            "status": status,
            "full_test": full_test,
            "verified": full_test and status == "passed",
            "session_checks": [item for item in results if item.get("id") != check_id],
            "check": candidate_result,
        }

    def list_incidents(self) -> list[dict]:
        return self.runtime.list_incidents()

    def list_notifications(self) -> list[dict]:
        return self.runtime.list_notifications()

    def test_notification(self) -> dict:
        config, _ = self.repository.load()
        try:
            self.notifier.send_test(config)
        except ValueError:
            raise
        except Exception as error:
            code = getattr(error, "code", None)
            detail = f"HTTP {code}" if isinstance(code, int) else type(error).__name__
            raise RuntimeError(f"Webhook 发送失败：{detail}") from None
        return {"sent": True, "sent_at": utc_now()}

    def start_run(self, trigger: str = "manual", scheduled_for: str | None = None,
                  targets: list[str] | None = None) -> str:
        if trigger not in ("manual", "scheduled"):
            raise ValueError("运行触发类型无效")
        config, version = self.repository.load()
        active_targets, enabled = enabled_run_targets(
            config, targets, strict=targets is not None,
        )
        semaphore_acquired = bool(self.run_semaphore and self.run_semaphore.acquire(blocking=False))
        if self.run_semaphore and not semaphore_acquired:
            raise RuntimeError("巡检中心已达到跨系统并发上限")
        try:
            with self.lock:
                if self.active:
                    raise RuntimeError("已有巡检正在执行")
                run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
                single_attempt_ttl = inspection_timeout_budget(config, enabled)
                retry = config.get("run_retry", {})
                max_retries = int(retry.get("max_retries", 2)) if retry.get("enabled", False) else 0
                retry_delay = int(retry.get("delay_seconds", 30)) * max_retries
                lease_ttl = single_attempt_ttl * (max_retries + 1) + retry_delay + 120
                if not self.runtime.claim_lease(run_id, trigger, max(lease_ttl, 180)):
                    raise RuntimeError("已有巡检正在执行")
                self.active = {
                    "run_id": run_id, "status": "running", "started_at": utc_now(),
                    "checks": [], "trigger": trigger, "scheduled_for": scheduled_for,
                    "targets": active_targets,
                }
        except Exception:
            if semaphore_acquired:
                self.run_semaphore.release()
            raise

        def worker():
            try:
                report = run_inspection_with_retry(
                    config, version, self.credentials.runtime_variables(),
                    run_id=run_id, trigger=trigger, scheduled_for=scheduled_for,
                    artifact_root=self.artifact_dir, targets=active_targets,
                )
                target = self.data_dir / f"{run_id}.json"
                temporary = target.with_suffix(".tmp")
                temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2))
                temporary.replace(target)
                self.cleanup_reports(config.get("report_limit", 30))
                self.alerts.process_report(report, config)
                if config.get("alerts", {}).get("enabled", False):
                    self.notifier.drain()
            finally:
                self.runtime.release_lease(run_id)
                with self.lock:
                    self.active = None
                if semaphore_acquired:
                    self.run_semaphore.release()

        threading.Thread(target=worker, daemon=True).start()
        return run_id


class InspectionManager:
    """Own one isolated InspectionState for every registered business system."""

    def __init__(self, registry_path: Path, data_root: Path):
        self.registry_path = registry_path
        self.data_root = data_root
        try:
            registry = json.loads(registry_path.read_text())
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("系统注册表无法读取") from error
        entries = registry.get("systems") if isinstance(registry, dict) else None
        if not isinstance(entries, list) or not entries:
            raise ValueError("系统注册表至少需要一个系统")
        self.states: dict[str, InspectionState] = {}
        self.entries: dict[str, dict] = {}
        max_parallel = registry.get("max_parallel_runs", 2)
        if not isinstance(max_parallel, int) or isinstance(max_parallel, bool) or not 1 <= max_parallel <= 32:
            raise ValueError("max_parallel_runs 必须在 1 到 32 之间")
        self.run_semaphore = threading.BoundedSemaphore(max_parallel)
        config_root = registry_path.parent.resolve()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("系统注册项必须是 JSON 对象")
            system_id = str(entry.get("system_id", ""))
            if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", system_id) or system_id in self.states:
                raise ValueError(f"系统注册 ID 无效或重复: {system_id}")
            relative = Path(str(entry.get("config", "")))
            config_path = (registry_path.parent / relative).resolve()
            if not config_path.is_relative_to(config_root):
                raise ValueError(f"{system_id}: 配置路径越界")
            config, _ = ConfigRepository(config_path).load()
            if config["system_id"] != system_id:
                raise ValueError(f"{system_id}: 注册表与系统配置 ID 不一致")
            system_root = data_root / system_id
            state = InspectionState(
                config_path, system_root / "runs", system_root / "secrets.json",
                system_root / "runtime.db", expected_system_id=system_id,
                use_environment_fallback=False, run_semaphore=self.run_semaphore,
            )
            self.states[system_id] = state
            self.entries[system_id] = copy.deepcopy(entry)
        default_id = registry.get("default_system_id", entries[0].get("system_id"))
        if default_id not in self.states:
            raise ValueError("default_system_id 不在系统注册表中")
        self.default_system_id = default_id

    def start_background(self) -> None:
        for state in self.states.values():
            state.start_background()

    def stop_background(self) -> None:
        for state in self.states.values():
            state.stop_background()

    def get_state(self, system_id: str | None = None) -> InspectionState:
        key = system_id or self.default_system_id
        try:
            return self.states[key]
        except KeyError as error:
            raise ValueError("系统不存在") from error

    def list_systems(self) -> list[dict]:
        result = []
        for system_id, state in self.states.items():
            summary = state.summary()
            result.append({
                "system_id": system_id,
                "display_name": summary["display_name"],
                "environment": summary["environment"],
                "adapter": summary["adapter"],
                "enabled_checks": summary["enabled_checks"],
                "total_checks": summary["total_checks"],
                "latest": summary["latest"],
                "active_run_id": summary["active_run_id"],
                "schedule": summary["schedule"],
                "incidents": summary["incidents"],
                "default": system_id == self.default_system_id,
            })
        return result

    def overview(self) -> dict:
        systems = self.list_systems()
        return {
            "systems": systems,
            "counts": {
                "total": len(systems),
                "running": sum(bool(item["active_run_id"]) for item in systems),
                "failed": sum((item.get("latest") or {}).get("status") == "failed" for item in systems),
                "open_incidents": sum(int((item.get("incidents") or {}).get("open", 0)) for item in systems),
            },
        }


def make_handler(controller: InspectionState | InspectionManager, auth: AuthManager | None = None):
    class Handler(BaseHTTPRequestHandler):
        def security_headers(self):
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self'; "
                "img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )

        def send_json(self, value, status=200, extra_headers: list[tuple[str, str]] | None = None):
            raw = json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.security_headers()
            for key, header_value in extra_headers or []:
                self.send_header(key, header_value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def send_redirect(self, location: str):
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.security_headers()
            self.send_header("Content-Length", "0")
            self.end_headers()

        def send_static(self, filename: str):
            path = STATIC / filename
            raw = path.read_bytes()
            content_type = (
                "text/html" if filename.endswith(".html") else
                "text/css" if filename.endswith(".css") else "application/javascript"
            )
            self.send_response(200)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store" if filename.endswith(".html") else "public, max-age=300")
            self.security_headers()
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def send_artifact(self, path: Path):
            content_type = {
                ".png": "image/png", ".zip": "application/zip",
            }.get(path.suffix.lower(), "application/octet-stream")
            disposition = "inline" if content_type.startswith("image/") else "attachment"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'{disposition}; filename="{path.name}"')
            self.send_header("Cache-Control", "private, no-store")
            self.security_headers()
            self.send_header("Content-Length", str(path.stat().st_size))
            self.end_headers()
            with path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    self.wfile.write(chunk)

        def read_json(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as error:
                raise ValueError("Content-Length 无效") from error
            if length <= 0 or length > MAX_CONFIG_BYTES:
                raise ValueError("请求体为空或超过 2 MiB 上限")
            try:
                return json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ValueError("请求体不是有效 JSON") from error

        def session_token(self) -> str | None:
            if auth is None:
                return None
            try:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
            except Exception:
                return None
            for name in (auth.SECURE_SESSION_COOKIE, auth.SESSION_COOKIE):
                morsel = cookie.get(name)
                if morsel:
                    return morsel.value
            return None

        def request_session(self) -> dict | None:
            if auth is None:
                return {"username": "local", "csrf_token": ""}
            return auth.session(self.session_token())

        def require_api_session(self) -> dict | None:
            session = self.request_session()
            if session is None:
                self.send_json({"error": "登录会话已失效", "code": "authentication_required"}, 401)
            return session

        def verify_csrf(self, session: dict | None) -> bool:
            if auth is None:
                return True
            supplied = self.headers.get("X-CSRF-Token", "")
            expected = str((session or {}).get("csrf_token", ""))
            if supplied and expected and hmac.compare_digest(supplied, expected):
                return True
            self.send_json({"error": "安全校验失败，请刷新页面后重试", "code": "csrf_failed"}, 403)
            return False

        def cookie_is_secure(self) -> bool:
            return bool(auth and (
                auth.secure_cookie or self.headers.get("X-Forwarded-Proto", "").lower() == "https"
            ))

        def session_cookie_header(self, token: str, max_age: int | None = None) -> str:
            secure = self.cookie_is_secure()
            name = auth.SECURE_SESSION_COOKIE if secure else auth.SESSION_COOKIE
            value = token if max_age != 0 else ""
            parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Strict"]
            if secure:
                parts.append("Secure")
            if max_age is not None:
                parts.append(f"Max-Age={max_age}")
            return "; ".join(parts)

        def clear_cookie_headers(self) -> list[tuple[str, str]]:
            common = "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            return [
                ("Set-Cookie", auth.SESSION_COOKIE + common),
                ("Set-Cookie", auth.SECURE_SESSION_COOKIE + common + "; Secure"),
            ] if auth else []

        def scoped_state(self, raw_path: str) -> tuple[InspectionState, str]:
            if isinstance(controller, InspectionManager):
                prefix = "/api/systems/"
                if raw_path.startswith(prefix):
                    remainder = raw_path[len(prefix):]
                    parts = remainder.split("/", 1)
                    system_id = unquote(parts[0])
                    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", system_id):
                        raise ValueError("system_id 格式无效")
                    api_path = "/api" + ("/" + parts[1] if len(parts) == 2 else "")
                    return controller.get_state(system_id), api_path
                return controller.get_state(), raw_path
            return controller, raw_path

        def do_GET(self):
            try:
                raw_path = urlparse(self.path).path
                session = self.request_session()
                if raw_path in ("/login", "/login.html"):
                    if auth is not None and session is not None:
                        return self.send_redirect("/")
                    return self.send_static("login.html")
                if raw_path in ("/login.css", "/login.js"):
                    return self.send_static(raw_path.lstrip("/"))
                if raw_path == "/api/auth/session":
                    if session is None:
                        return self.send_json(
                            {"error": "登录会话已失效", "code": "authentication_required"}, 401,
                            self.clear_cookie_headers(),
                        )
                    expires_at = datetime.fromtimestamp(int(session["expires_at"]), timezone.utc).isoformat()
                    return self.send_json({
                        "authenticated": True, "username": session["username"],
                        "csrf_token": session["csrf_token"], "expires_at": expires_at,
                    })
                if auth is not None and session is None:
                    if raw_path.startswith("/api/"):
                        return self.send_json(
                            {"error": "登录会话已失效", "code": "authentication_required"}, 401,
                            self.clear_cookie_headers(),
                        )
                    requested_path = self.path
                    next_path = requested_path if (
                        requested_path.startswith("/") and not requested_path.startswith("//")
                        and "\\" not in requested_path and raw_path not in ("/login", "/login.html")
                    ) else "/"
                    return self.send_redirect("/login?" + urlencode({"next": next_path}))
                if raw_path == "/api/systems" and isinstance(controller, InspectionManager):
                    return self.send_json(controller.list_systems())
                if raw_path == "/api/overview" and isinstance(controller, InspectionManager):
                    return self.send_json(controller.overview())
                state, api_path = self.scoped_state(raw_path)
                if api_path == "/api/summary":
                    return self.send_json(state.summary())
                if api_path == "/api/checks":
                    config, _ = state.repository.load()
                    return self.send_json([{key: item.get(key) for key in
                                            ("id", "name", "category", "enabled", "type", "path", "steps")}
                                           for item in config["checks"]])
                if api_path == "/api/settings":
                    return self.send_json(state.settings_document())
                if api_path == "/api/api-checks":
                    return self.send_json(state.api_checks_document())
                if api_path == "/api/ui-scenes":
                    return self.send_json(state.ui_scenes_document())
                if api_path == "/api/config":
                    return self.send_json(state.config_document())
                if api_path == "/api/ui/capabilities":
                    return self.send_json(state.ui_capabilities())
                if api_path == "/api/config/export":
                    config, version = state.repository.load()
                    return self.send_json({"config_version": version, "config": config})
                if api_path == "/api/incidents":
                    return self.send_json(state.list_incidents())
                if api_path == "/api/notifications":
                    return self.send_json(state.list_notifications())
                if api_path == "/api/runs":
                    config, _ = state.repository.load()
                    return self.send_json(state.list_reports(config.get("report_limit", 30)))
                if api_path in ("/api/reports/api", "/api/reports/ui"):
                    config, _ = state.repository.load()
                    kind = api_path.rsplit("/", 1)[-1]
                    return self.send_json(state.list_reports(config.get("report_limit", 30), kind))
                if api_path.startswith("/api/reports/api/") or api_path.startswith("/api/reports/ui/"):
                    remainder = api_path.removeprefix("/api/reports/")
                    kind, run_id = remainder.split("/", 1)
                    report = state.read_report_view(unquote(run_id), kind)
                    return self.send_json(report, 200) if report else self.send_json({"error": "报告不存在"}, 404)
                if api_path.startswith("/api/runs/") and "/artifacts/" in api_path:
                    remainder = api_path.removeprefix("/api/runs/")
                    run_id, artifact_id = remainder.split("/artifacts/", 1)
                    artifact = state.read_artifact(unquote(run_id), unquote(artifact_id))
                    return self.send_artifact(artifact) if artifact else self.send_json({"error": "证据不存在"}, 404)
                if api_path.startswith("/api/ui/tests/") and "/artifacts/" in api_path:
                    remainder = api_path.removeprefix("/api/ui/tests/")
                    test_id, artifact_id = remainder.split("/artifacts/", 1)
                    artifact = state.read_ui_test_artifact(unquote(test_id), unquote(artifact_id))
                    return self.send_artifact(artifact) if artifact else self.send_json({"error": "测试证据不存在"}, 404)
                if api_path.startswith("/api/runs/"):
                    report = state.read_report(api_path.removeprefix("/api/runs/"))
                    return self.send_json(report, 200) if report else self.send_json({"error": "报告不存在"}, 404)
                path = "index.html" if raw_path == "/" else raw_path.lstrip("/")
                if path not in ("index.html", "style.css", "app.js"):
                    return self.send_json({"error": "未找到"}, 404)
                return self.send_static(path)
            except ValueError as error:
                self.send_json({"error": str(error)}, 400)
            except (OSError, json.JSONDecodeError) as error:
                self.send_json({"error": str(error)}, 500)

        def do_POST(self):
            try:
                raw_path = urlparse(self.path).path
                if raw_path == "/api/auth/login" and auth is not None:
                    payload = self.read_json()
                    username = payload.get("username", "") if isinstance(payload, dict) else ""
                    password = payload.get("password", "") if isinstance(payload, dict) else ""
                    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 128 or len(password) > 4096:
                        raise ValueError("登录信息格式无效")
                    result = auth.login(
                        username.strip(), password, self.client_address[0], self.headers.get("User-Agent", "")
                    )
                    if not result["ok"]:
                        retry_after = int(result.get("retry_after", 0))
                        status = HTTPStatus.TOO_MANY_REQUESTS if retry_after else HTTPStatus.UNAUTHORIZED
                        headers = [("Retry-After", str(retry_after))] if retry_after else []
                        return self.send_json({
                            "error": "用户名或密码错误" if not retry_after else "登录尝试过于频繁，请稍后再试",
                            "code": "login_rate_limited" if retry_after else "invalid_credentials",
                            "retry_after": retry_after,
                        }, status, headers)
                    response = {
                        "authenticated": True, "username": result["username"],
                        "csrf_token": result["csrf_token"],
                        "expires_at": datetime.fromtimestamp(result["expires_at"], timezone.utc).isoformat(),
                    }
                    return self.send_json(response, 200, [
                        ("Set-Cookie", self.session_cookie_header(result["token"], auth.session_ttl_seconds))
                    ])

                session = self.require_api_session()
                if session is None:
                    return
                if not self.verify_csrf(session):
                    return
                if raw_path == "/api/auth/logout" and auth is not None:
                    auth.logout(self.session_token())
                    return self.send_json({"authenticated": False}, 200, self.clear_cookie_headers())

                state, api_path = self.scoped_state(raw_path)
                if api_path == "/api/runs":
                    payload = {} if self.headers.get("Content-Length", "0") in ("", "0") else self.read_json()
                    if not isinstance(payload, dict):
                        raise ValueError("运行参数必须是 JSON 对象")
                    unknown = set(payload) - {"targets"}
                    if unknown:
                        raise ValueError(f"不支持的运行参数: {', '.join(sorted(unknown))}")
                    targets = payload.get("targets") if "targets" in payload else None
                    config, _ = state.repository.load()
                    response_targets, _ = enabled_run_targets(
                        config, targets, strict=targets is not None,
                    )
                    run_id = state.start_run(targets=targets)
                    return self.send_json({
                        "run_id": run_id,
                        "targets": response_targets,
                    }, HTTPStatus.ACCEPTED)
                if api_path == "/api/config/validate":
                    return self.send_json(state.validate_document(self.read_json()))
                if api_path == "/api/config/import":
                    return self.send_json(state.import_config(self.read_json()))
                if api_path == "/api/api-checks/import":
                    return self.send_json(state.import_api_checks(self.read_json()))
                if api_path == "/api/api-auth-flows/test":
                    return self.send_json(state.test_auth_flow(self.read_json()))
                if api_path in ("/api/config/checks/test", "/api/api-checks/test"):
                    return self.send_json(state.test_check(self.read_json()))
                if api_path in ("/api/ui/checks/test", "/api/ui-scenes/test"):
                    return self.send_json(state.test_ui_check(self.read_json()))
                if api_path in ("/api/ui/checks/test-through-step", "/api/ui-scenes/test-through-step"):
                    return self.send_json(state.test_ui_check(self.read_json(), through_step=True))
                if api_path in ("/api/config/preflight", "/api/settings/preflight"):
                    if self.headers.get("Content-Length", "0") not in ("", "0"):
                        return self.send_json({"error": "此操作不接受请求体"}, 400)
                    return self.send_json(state.preflight())
                if api_path == "/api/api-checks":
                    return self.send_json(state.create_collection_item("api", self.read_json()), HTTPStatus.CREATED)
                if api_path == "/api/ui-scenes":
                    return self.send_json(state.create_collection_item("ui", self.read_json()), HTTPStatus.CREATED)
                if api_path == "/api/notifications/test":
                    if self.headers.get("Content-Length", "0") not in ("", "0"):
                        return self.send_json({"error": "此操作不接受请求体"}, 400)
                    return self.send_json(state.test_notification())
                return self.send_json({"error": "未找到"}, 404)
            except ValueError as error:
                self.send_json({"error": str(error)}, 422)
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)

        def do_PUT(self):
            try:
                session = self.require_api_session()
                if session is None:
                    return
                if not self.verify_csrf(session):
                    return
                state, api_path = self.scoped_state(urlparse(self.path).path)
                if api_path == "/api/config":
                    return self.send_json(state.update_config(self.read_json()))
                if api_path == "/api/settings":
                    return self.send_json(state.update_settings(self.read_json()))
                if api_path == "/api/api-checks":
                    return self.send_json(state.update_api_checks(self.read_json()))
                if api_path == "/api/ui-scenes":
                    return self.send_json(state.update_ui_scenes(self.read_json()))
                if api_path.startswith("/api/api-checks/"):
                    item_id = unquote(api_path.removeprefix("/api/api-checks/"))
                    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", item_id):
                        raise ValueError("检查项 ID 格式无效")
                    return self.send_json(state.update_collection_item("api", item_id, self.read_json()))
                if api_path.startswith("/api/ui-scenes/"):
                    item_id = unquote(api_path.removeprefix("/api/ui-scenes/"))
                    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", item_id):
                        raise ValueError("场景 ID 格式无效")
                    return self.send_json(state.update_collection_item("ui", item_id, self.read_json()))
                return self.send_json({"error": "未找到"}, 404)
            except ValueError as error:
                self.send_json({"error": str(error)}, 422)
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)

        def do_DELETE(self):
            try:
                session = self.require_api_session()
                if session is None:
                    return
                if not self.verify_csrf(session):
                    return
                state, api_path = self.scoped_state(urlparse(self.path).path)
                for kind, prefix in (("api", "/api/api-checks/"), ("ui", "/api/ui-scenes/")):
                    if api_path.startswith(prefix):
                        item_id = unquote(api_path.removeprefix(prefix))
                        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", item_id):
                            raise ValueError("检查项 ID 格式无效")
                        return self.send_json(state.delete_collection_item(kind, item_id, self.read_json()))
                return self.send_json({"error": "未找到"}, 404)
            except ValueError as error:
                self.send_json({"error": str(error)}, 422)
            except RuntimeError as error:
                self.send_json({"error": str(error)}, 409)

        def log_message(self, format, *args):
            pass

    return Handler


def main():
    parser = argparse.ArgumentParser(description="SRM 多系统巡检中心")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--system-data", type=Path, default=DEFAULT_SYSTEM_DATA)
    parser.add_argument("--config", type=Path, default=None,
                        help="兼容旧版单系统运行；指定后忽略 --registry")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--secrets", type=Path, default=None)
    parser.add_argument("--auth-db", type=Path, default=DEFAULT_AUTH_DB)
    parser.add_argument("--auth-config", type=Path, default=DEFAULT_AUTH_CONFIG)
    parser.add_argument("--reset-admin", action="store_true",
                        help="重置本地管理员密码、注销现有会话并退出")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    args = parser.parse_args()
    secure_cookie = os.environ.get("INSPECTION_COOKIE_SECURE", "").strip().lower() in ("1", "true", "yes", "on")
    if args.reset_admin:
        auth = AuthManager(args.auth_db, args.auth_config, secure_cookie=secure_cookie)
        try:
            password = auth.reset_credentials()
        except ValueError as error:
            raise SystemExit(str(error)) from None
        print("管理员密码已重置，所有现有登录会话已注销：", flush=True)
        print(f"  用户名: {auth.username}", flush=True)
        print(f"  新密码: {password}", flush=True)
        return
    if args.config is not None:
        controller: InspectionState | InspectionManager = InspectionState(
            args.config, args.data_dir, args.secrets
        )
        load_config(args.config)
    else:
        controller = InspectionManager(args.registry, args.system_data)
    server = ThreadingHTTPServer(
        (args.host, args.port), BaseHTTPRequestHandler, bind_and_activate=False
    )
    try:
        server.server_bind()
        server.server_activate()
    except OSError as error:
        server.server_close()
        if error.errno == errno.EADDRINUSE:
            raise SystemExit(
                f"无法启动：{args.host}:{args.port} 已被占用。\n"
                f"请先执行 lsof -nP -iTCP:{args.port} -sTCP:LISTEN 查看占用进程，"
                f"或使用 python3 app.py --port {args.port + 1}。"
            ) from None
        raise
    try:
        auth = AuthManager(args.auth_db, args.auth_config, secure_cookie=secure_cookie)
        server.RequestHandlerClass = make_handler(controller, auth)
    except Exception:
        server.server_close()
        raise
    controller.start_background()
    print(f"SRM 巡检中心: http://{args.host}:{args.port}/", flush=True)
    if auth.bootstrap_password:
        print("首次启动管理员账户已创建，请登录后妥善轮换凭据：", flush=True)
        print(f"  用户名: {auth.username}", flush=True)
        print(f"  初始密码: {auth.bootstrap_password}", flush=True)
        print(f"  认证配置: {auth.config_path}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSRM 巡检中心已停止。", flush=True)
    finally:
        controller.stop_background()
        server.server_close()


if __name__ == "__main__":
    main()
