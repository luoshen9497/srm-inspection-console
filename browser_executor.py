"""Playwright UI inspection adapter.

Playwright is imported lazily so API-only installations keep working without the
browser dependency. The adapter emits the same high-level status fields as the
HTTP executor and adds step-by-step screenshot evidence.
"""

from __future__ import annotations

import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from artifact_store import ArtifactStore


class UiAssertionError(AssertionError):
    pass


class UiContractError(ValueError):
    pass


class UiAuthenticationError(UiAssertionError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_variables(value, variables: dict | None = None):
    if isinstance(value, str):
        exact = re.fullmatch(r"\$\{([A-Za-z][A-Za-z0-9_]*)\}", value)
        if exact:
            name = exact.group(1)
            if name not in (variables or {}):
                raise UiContractError(f"缺少运行变量 {name}")
            return (variables or {})[name]

        def replace(match):
            name = match.group(1)
            if name not in (variables or {}):
                raise UiContractError(f"缺少运行变量 {name}")
            return str((variables or {})[name])

        return re.sub(r"\$\{([A-Za-z][A-Za-z0-9_]*)\}", replace, value)
    if isinstance(value, list):
        return [resolve_variables(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: resolve_variables(item, variables) for key, item in value.items()}
    return value


def safe_page_url(value: str) -> str:
    try:
        parsed = urlsplit(str(value))
        hostname = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme, hostname + port, parsed.path, "", ""))
    except (TypeError, ValueError):
        return ""


def _redact(text: object, variables: dict | None) -> str:
    result = str(text)
    for value in (variables or {}).values():
        if value not in (None, ""):
            result = result.replace(str(value), "***").replace(quote(str(value), safe=""), "***")
    return result[:500]


def _locator_in_scope(scope, definition: dict):
    if "test_id" in definition:
        return scope.get_by_test_id(definition["test_id"])
    if "role" in definition:
        return scope.get_by_role(definition["role"], name=definition.get("name"), exact=definition.get("exact", False))
    if "label" in definition:
        return scope.get_by_label(definition["label"], exact=definition.get("exact", False))
    if "placeholder" in definition:
        return scope.get_by_placeholder(definition["placeholder"], exact=definition.get("exact", False))
    if "text" in definition:
        return scope.get_by_text(definition["text"], exact=definition.get("exact", False))
    if "css" in definition:
        return scope.locator(definition["css"])
    raise UiContractError("步骤缺少受支持的定位器")


def _locator_scopes(page):
    """Yield the page followed by every attached child frame.

    Playwright exposes ``page.frames`` as a flat collection, so nested iframes
    are included without relying on a caller-provided frame selector. The main
    frame is skipped because the page scope already represents it.
    """
    yield page
    main_frame = getattr(page, "main_frame", None)
    for frame in getattr(page, "frames", ()) or ():
        if frame is main_frame:
            continue
        yield frame


def _locator(page, definition: dict, timeout_ms: int | None = None):
    """Resolve a locator from the page or any child iframe.

    Frame contents can be attached or rendered after the outer document is
    ready. When a timeout is supplied, keep rescanning all current frames for
    the duration of the step instead of binding permanently to the main page.
    """
    deadline = time.monotonic() + timeout_ms / 1000 if timeout_ms is not None else None
    fallback = _locator_in_scope(page, definition)
    while True:
        for scope in _locator_scopes(page):
            locator = _locator_in_scope(scope, definition)
            try:
                if locator.count() > 0:
                    return locator
            except Exception:
                # A frame may detach or navigate while the collection is read.
                # The next scan observes the current frame tree.
                continue
        if deadline is None:
            return fallback
        remaining_ms = round((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise TimeoutError("在主页面及所有子 iframe 中均未找到目标元素")
        wait_ms = min(100, remaining_ms)
        if hasattr(page, "wait_for_timeout"):
            page.wait_for_timeout(wait_ms)
        else:
            time.sleep(wait_ms / 1000)


def _matches(actual: str, expected: str, match: str) -> bool:
    if match == "equals":
        return actual == expected
    if match == "not_equals":
        return actual != expected
    if match == "not_contains":
        return expected not in actual
    return expected in actual


def _is_login_page(page) -> bool:
    try:
        url = urlsplit(str(getattr(page, "url", "")))
        paths = (url.path.lower().rstrip("/"), url.fragment.split("?", 1)[0].lower().rstrip("/"))
    except (TypeError, ValueError):
        return False
    return any(re.search(r"/(?:login|signin|sign-in)(?:\.html)?$", path) for path in paths)


def _perform_step(page, step: dict, config: dict, variables: dict, timeout_ms: int) -> dict | None:
    action = step["action"]
    if action == "goto":
        path = resolve_variables(step["path"], variables)
        base_url = config.get("ui", {}).get("base_url", config["base_url"])
        target_url = path if urlsplit(path).scheme else base_url.rstrip("/") + path
        response = page.goto(
            target_url,
            wait_until=step.get("wait_until", "domcontentloaded"),
            timeout=timeout_ms,
        )
        status = getattr(response, "status", None) if response is not None else None
        if isinstance(status, int) and status >= 400:
            raise UiAssertionError(f"页面返回 HTTP {status}")
        page.wait_for_function(
            """() => {
                const body = document.body;
                if (!body) return false;
                if ((body.innerText || '').trim().length > 0) return true;
                const element = body.querySelector('img[src], svg, canvas, input, button, [role]');
                if (!element) return false;
                const rect = element.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            }""",
            timeout=timeout_ms,
        )
        network_settled = True
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 5000))
        except Exception as settle_error:
            if type(settle_error).__name__ != "TimeoutError":
                raise
            network_settled = False
        return {
            "type": "navigation", "passed": True, "http_status": status,
            "visible_content_ready": True, "network_settled": network_settled,
        }

    if action == "assert_url":
        expected = str(resolve_variables(step["expected"], variables))
        # URL assertions must see the complete browser URL. In particular, SPA
        # routes live in the fragment (for example ``/#/workbench``), while
        # safe_page_url intentionally removes query/fragment data from reports.
        actual = str(page.url)
        match = step.get("match", "contains")
        passed = _matches(actual, expected, match)
        if not passed:
            raise UiAssertionError("页面地址与预期不符")
        return {"type": "url", "match": match, "expected": expected, "passed": True}

    locator_timeout = None if action == "assert_count" and int(step["expected"]) == 0 else timeout_ms
    locator = _locator(page, step["locator"], locator_timeout)
    if action == "click":
        locator.click(timeout=timeout_ms)
        return None
    if action == "fill":
        locator.fill(str(resolve_variables(step["value"], variables)), timeout=timeout_ms)
        return None
    if action == "select":
        locator.select_option(resolve_variables(step["value"], variables), timeout=timeout_ms)
        return None
    if action == "wait_visible":
        locator.wait_for(state="visible", timeout=timeout_ms)
        return None
    if action == "assert_visible":
        locator.wait_for(state="visible", timeout=timeout_ms)
        return {"type": "visible", "passed": True}
    if action == "assert_text":
        locator.wait_for(state="visible", timeout=timeout_ms)
        actual = locator.inner_text(timeout=timeout_ms)
        expected = str(resolve_variables(step["expected"], variables))
        match = step.get("match", "contains")
        passed = _matches(str(actual), expected, match)
        if not passed:
            raise UiAssertionError("页面文本与预期不符")
        assertion = {"type": "text", "match": match, "expected": expected, "passed": True}
        if step.get("record_actual"):
            assertion["actual"] = str(actual)[:300]
        return assertion
    if action == "assert_count":
        expected = int(step["expected"])
        actual = locator.count()
        if actual != expected:
            raise UiAssertionError(f"元素数量为 {actual}，预期 {expected}")
        return {"type": "count", "expected": expected, "actual": actual, "passed": True}
    raise UiContractError(f"不支持的 UI 动作 {action}")


def _mask_locators(page, config: dict, check: dict, step: dict) -> list:
    masks = []
    for definition in config.get("ui", {}).get("screenshot_masks", []):
        masks.append(_locator(page, definition))
    for definition in check.get("screenshot_masks", []):
        masks.append(_locator(page, definition))
    for configured_step in check.get("steps", []):
        if configured_step.get("sensitive") and isinstance(configured_step.get("locator"), dict):
            masks.append(_locator(page, configured_step["locator"]))
    return masks


def _capture(page, store: ArtifactStore, check: dict, step: dict, sequence: int,
             config: dict, suffix: str = "", full_page: bool = False) -> dict:
    target = store.screenshot_path(check["id"], sequence, step["id"], suffix)
    page.screenshot(
        path=str(target), full_page=full_page,
        mask=_mask_locators(page, config, check, step),
        animations="disabled", caret="hide",
    )
    return store.metadata(target)


def _classify_step_failure(error: Exception, action: str, authentication_assertion: bool) -> str:
    if authentication_assertion or isinstance(error, UiAuthenticationError):
        return "authentication_failed"
    if isinstance(error, UiAssertionError):
        return "assertion_failed"
    if type(error).__name__ == "TimeoutError":
        return "timeout" if action == "goto" else "automation_contract_changed"
    if "net::" in str(error).lower():
        return "network_unreachable"
    return "automation_contract_changed"


def execute_ui_check(check: dict, config: dict, page, variables: dict,
                     store: ArtifactStore, console_errors: list[str] | None = None,
                     failed_requests: list[str] | None = None) -> dict:
    started = time.monotonic()
    result = {
        "id": check["id"], "name": check["name"], "category": check.get("category"),
        "type": "ui", "method": "UI", "path": next(
            (step.get("path") for step in check.get("steps", []) if step.get("action") == "goto"), ""
        ),
        "status": "failed", "started_at": utc_now(), "steps": [], "assertions": [],
        "evidence": {}, "classification": None,
        "severity": check.get("severity", "P2"),
        "alert_enabled": check.get("alert_enabled", True),
    }
    default_timeout = config.get("ui", {}).get("default_timeout_seconds", 15)
    for sequence, step in enumerate(check.get("steps", []), 1):
        step_started = time.monotonic()
        step_result = {
            "id": step["id"], "sequence": sequence,
            "description": step["description"], "action": step["action"],
            "status": "failed", "started_at": utc_now(),
        }
        error = None
        try:
            timeout_ms = round(float(step.get("timeout_seconds", default_timeout)) * 1000)
            assertion = _perform_step(page, step, config, variables, timeout_ms)
            if check.get("auth_dependency") and _is_login_page(page):
                raise UiAuthenticationError("业务页面跳回登录页，浏览器登录态未建立或已失效；请检查浏览器登录入口")
            if assertion:
                if "expected" in assertion and isinstance(assertion["expected"], str):
                    assertion["expected"] = _redact(assertion["expected"], variables)
                if "actual" in assertion and isinstance(assertion["actual"], str):
                    assertion["actual"] = _redact(assertion["actual"], variables)
                step_result["assertion"] = assertion
            step_result["status"] = "passed"
        except Exception as caught:  # Playwright errors are optional runtime types.
            error = caught
            step_result["classification"] = _classify_step_failure(
                caught, step.get("action", ""), bool(step.get("authentication_assertion"))
            )
            step_result["reason"] = _redact(caught, variables) or "UI 步骤执行失败"
            if (
                type(caught).__name__ == "TimeoutError"
                and step.get("action") != "goto"
                and _is_login_page(page)
            ):
                step_result["classification"] = "authentication_failed"
                step_result["reason"] = "当前仍停留在登录页，前置登录未成功或登录态已失效"
        try:
            step_result["screenshot"] = _capture(page, store, check, step, sequence, config)
            if error is not None:
                step_result["failure_screenshot"] = _capture(
                    page, store, check, step, sequence, config,
                    suffix="failure-full", full_page=True,
                )
        except Exception as screenshot_error:
            if error is None:
                error = screenshot_error
                step_result["status"] = "failed"
                step_result["classification"] = "dependency_unhealthy"
                step_result["reason"] = "页面截图证据生成失败"
            step_result["screenshot_error"] = type(screenshot_error).__name__
        finally:
            step_result["duration_ms"] = round((time.monotonic() - step_started) * 1000)
            step_result["finished_at"] = utc_now()
            result["steps"].append(step_result)
        if error is not None:
            result["classification"] = step_result["classification"]
            result["reason"] = step_result["reason"]
            break
    else:
        result["status"] = "passed"

    try:
        title = _redact(page.title(), variables)[:200]
    except Exception:
        title = ""
    result["evidence"] = {
        "page_url": _redact(safe_page_url(getattr(page, "url", "")), variables),
        "page_title": title,
        "console_errors": list((console_errors or [])[-10:]),
        "failed_requests": list((failed_requests or [])[-10:]),
        "screenshot_count": sum(bool(item.get("screenshot")) for item in result["steps"]),
    }
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    result["finished_at"] = utc_now()
    return result


@contextmanager
def _playwright_runtime():
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as error:
        raise RuntimeError("Playwright 未安装；请安装 requirements.txt 并执行 playwright install chromium") from error
    with sync_playwright() as runtime:
        yield runtime


def _startup_failure(checks: list[dict], error: Exception, variables: dict) -> list[dict]:
    reason = _redact(error, variables)
    results = []
    for index, check in enumerate(checks):
        results.append({
            "id": check["id"], "name": check["name"], "category": check.get("category"),
            "type": "ui", "method": "UI", "path": "",
            "status": "failed" if index == 0 else "skipped",
            "classification": "dependency_unhealthy",
            "reason": reason if index == 0 else "浏览器运行环境不可用，停止后续 UI 检查",
            "assertions": [], "steps": [], "evidence": {}, "duration_ms": 0,
            "started_at": utc_now(), "finished_at": utc_now(),
            "severity": check.get("severity", "P2"),
            "alert_enabled": check.get("alert_enabled", True),
        })
    return results


def _launch_browser(runtime, headless: bool):
    """Prefer the managed browser, then reuse an installed stable Chrome."""
    try:
        return runtime.chromium.launch(headless=headless)
    except Exception as managed_error:
        if "executable doesn't exist" not in str(managed_error).lower():
            raise
        try:
            return runtime.chromium.launch(headless=headless, channel="chrome")
        except Exception as chrome_error:
            raise RuntimeError(
                "浏览器运行时不可用；请执行 playwright install chromium，"
                "或在运行机器上安装 Google Chrome"
            ) from chrome_error


def _api_auth_result(auth, status, reason=None):
    now = utc_now()
    return {
        "id": "api-auth-" + auth["id"], "name": "API 登录 · " + auth["name"],
        "category": "认证前置", "type": "ui", "method": "UI", "path": "",
        "status": status, "started_at": now, "finished_at": now,
        "classification": "authentication_failed" if status != "passed" else None,
        "reason": reason, "steps": [], "assertions": [],
        "evidence": {"api_flow_id": auth["id"]},
        "duration_ms": auth.get("duration_ms", 0), "severity": "P2", "alert_enabled": True,
    }


def _blocked_by_api_auth(checks, auth, reason):
    now = utc_now()
    return [_api_auth_result(auth, "failed", reason)] + [{
        "id": check["id"], "name": check["name"], "category": check.get("category"),
        "type": "ui", "method": "UI", "path": "", "status": "skipped",
        "classification": "authentication_failed", "reason": "API 登录前置失败，业务场景未执行",
        "steps": [], "assertions": [], "evidence": {}, "duration_ms": 0,
        "started_at": now, "finished_at": now, "severity": check.get("severity", "P2"),
        "alert_enabled": check.get("alert_enabled", True),
    } for check in checks]


def run_ui_checks(checks: list[dict], config: dict, variables: dict,
                  store: ArtifactStore, runtime_factory=None, api_auth_context=None) -> list[dict]:
    """Run UI checks in one browser context, resolving per-scene login dependencies."""
    if not checks:
        return []
    if api_auth_context and api_auth_context["status"] != "passed":
        return _blocked_by_api_auth(checks, api_auth_context,
                                   api_auth_context.get("reason") or "API 登录流程失败")
    variables = dict(variables)
    if api_auth_context:
        variables.update(api_auth_context.get("variables", {}))
        variables.update({f"api_auth_secret_{index}": value for index, value in
                          enumerate(api_auth_context.get("variables", {}).values())})
        variables.update({f"api_cookie_{index}": item["value"]
                          for index, item in enumerate(api_auth_context.get("cookies", []))})
    factory = runtime_factory or _playwright_runtime
    browser = context = None
    trace_started = False
    results: list[dict] = []
    completed: dict[str, dict] = {}
    console_errors: list[str] = []
    failed_requests: list[str] = []
    redaction_variables = dict(variables)
    for configured_check in checks:
        redaction_variables.update(configured_check.get("variables", {}))
    ui_config = config.get("ui", {})
    try:
        with factory() as runtime:
            browser = _launch_browser(runtime, ui_config.get("headless", True))
            viewport = ui_config.get("viewport", {"width": 1440, "height": 900})
            context = browser.new_context(
                viewport=viewport,
                locale=ui_config.get("locale", "zh-CN"),
                ignore_https_errors=ui_config.get("ignore_https_errors", False),
            )
            if api_auth_context:
                context.add_cookies(api_auth_context.get("cookies", []))
            # OAuth entry navigation and response headers contain credentials.
            # Never persist them in a trace for API-authenticated UI runs.
            if ui_config.get("trace_on_failure", False) and not api_auth_context:
                context.tracing.start(screenshots=True, snapshots=True, sources=False)
                trace_started = True
            page = context.new_page()

            def on_console(message):
                if getattr(message, "type", "") == "error":
                    console_errors.append(_redact(getattr(message, "text", "浏览器控制台错误"), redaction_variables))

            def on_request_failed(request):
                failed_requests.append(_redact(safe_page_url(getattr(request, "url", "")), redaction_variables))

            page.on("console", on_console)
            page.on("requestfailed", on_request_failed)
            if api_auth_context:
                auth_started = time.monotonic()
                try:
                    entry = api_auth_context.get("entry_url", "")
                    if entry:
                        def entry_variable(match):
                            name = match.group(1)
                            if name not in api_auth_context.get("variables", {}):
                                raise UiContractError(f"API 登录流程缺少输出变量 {name}")
                            return quote(str(api_auth_context["variables"][name]), safe="")
                        entry = re.sub(r"\$\{([A-Za-z][A-Za-z0-9_]*)\}", entry_variable, entry)
                        timeout_ms = round(ui_config.get("default_timeout_seconds", 15) * 1000)
                        _perform_step(page, {"action": "goto", "path": entry}, config, {}, timeout_ms)
                        page.wait_for_function(r"""() => {
                            const url = new URL(location.href);
                            const route = url.pathname + url.hash.split('?')[0];
                            if (/\/(?:login|signin|sign-in)(?:\.html)?(?:\/|$|[?#])|\/user\/oauth(?:\/|$|[?#])/i.test(route)) return false;
                            if (url.searchParams.has('ticket') || /[?&](ticket|token)=/i.test(url.hash)) return false;
                            return !!document.body && !!document.body.innerText.trim();
                        }""", timeout=timeout_ms)
                    prepared = _api_auth_result(api_auth_context, "passed")
                    prepared["evidence"].update({
                        "cookie_count": len(api_auth_context.get("cookies", [])),
                        "browser_entry_completed": bool(entry),
                        "page_url": _redact(safe_page_url(page.url), redaction_variables),
                    })
                    prepared["duration_ms"] += round((time.monotonic() - auth_started) * 1000)
                    results.append(prepared)
                except Exception as auth_error:
                    return _blocked_by_api_auth(checks, api_auth_context,
                                               "浏览器认证初始化失败：" + _redact(auth_error, redaction_variables))
            checks_by_id = {check.get("id"): check for check in checks}
            for configured_check in config.get("checks", []):
                if (
                    configured_check.get("enabled")
                    and configured_check.get("type", "api") == "ui"
                    and configured_check.get("id") not in checks_by_id
                ):
                    checks_by_id[configured_check.get("id")] = configured_check
            legacy_login_failure = None

            def skipped(check: dict, classification: str, reason: str) -> dict:
                now = utc_now()
                return {
                    "id": check["id"], "name": check["name"], "category": check.get("category"),
                    "type": "ui", "method": "UI", "path": "", "status": "skipped",
                    "classification": classification, "reason": reason,
                    "assertions": [], "steps": [], "evidence": {}, "duration_ms": 0,
                    "started_at": now, "finished_at": now,
                    "severity": check.get("severity", "P2"),
                    "alert_enabled": check.get("alert_enabled", True),
                }

            def execute(check: dict) -> dict:
                nonlocal legacy_login_failure
                check_id = check["id"]
                if check_id in completed:
                    return completed[check_id]

                dependency_id = (check.get("auth_dependency") or {}).get("scene_id")
                if dependency_id:
                    provider = checks_by_id.get(dependency_id)
                    if provider is None:
                        result = skipped(
                            check, "data_precondition_missing",
                            f"前置登录场景不存在: {dependency_id}",
                        )
                        completed[check_id] = result
                        results.append(result)
                        return result
                    provider_result = execute(provider)
                    if provider_result.get("status") != "passed":
                        result = skipped(
                            check,
                            provider_result.get("classification") or "authentication_failed",
                            f"前置登录场景 {provider.get('name', dependency_id)} 失败，业务场景未执行",
                        )
                        completed[check_id] = result
                        results.append(result)
                        return result
                elif legacy_login_failure and not check.get("login_precheck"):
                    result = skipped(check, legacy_login_failure, "UI 登录预检失败，停止后续 UI 检查")
                    completed[check_id] = result
                    results.append(result)
                    return result

                scoped_variables = dict(variables)
                scoped_variables.update(check.get("variables", {}))
                console_errors.clear()
                failed_requests.clear()
                result = execute_ui_check(
                    check, config, page, scoped_variables, store,
                    console_errors=console_errors, failed_requests=failed_requests,
                )
                completed[check_id] = result
                results.append(result)
                if check.get("login_precheck") and result["status"] != "passed":
                    legacy_login_failure = result.get("classification") or "authentication_failed"
                return result

            for check in checks:
                execute(check)

            if trace_started:
                failed = any(item["status"] == "failed" for item in results)
                if failed:
                    trace_path = store.trace_path()
                    context.tracing.stop(path=str(trace_path))
                    trace_started = False
                    trace = store.metadata(trace_path)
                    for item in results:
                        if item["status"] == "failed":
                            item.setdefault("evidence", {})["trace"] = trace
                else:
                    context.tracing.stop()
                    trace_started = False
            return results
    except Exception as error:
        if results:
            remaining = [check for check in checks if check["id"] not in completed]
            results.extend(_startup_failure(remaining, error, redaction_variables))
            return results
        return _startup_failure(checks, error, redaction_variables)
    finally:
        if context is not None:
            if trace_started:
                try:
                    context.tracing.stop()
                except Exception:
                    pass
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
