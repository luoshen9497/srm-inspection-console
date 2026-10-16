"""Ordered API authentication flows; credentials live only in a run's context."""
import copy
import base64
import hashlib
import json
import re
import time
from urllib.request import HTTPCookieProcessor
from urllib.parse import urlparse


def validate_browser_entry_url(entry, config, outputs):
    if not isinstance(entry, str):
        raise ValueError("浏览器登录入口必须是 URL 模板")
    if not entry:
        return
    parsed = urlparse(entry)
    allowed = {config["base_url"].rstrip("/"), *config.get("allowed_origins", [])}
    if (parsed.scheme not in ("http", "https") or not parsed.netloc
            or f"{parsed.scheme}://{parsed.netloc}" not in allowed
            or parsed.username is not None or parsed.password is not None
            or "${" in parsed.netloc):
        raise ValueError("浏览器登录入口必须属于当前系统的允许来源")
    refs = set(re.findall(r"\$\{([A-Za-z][A-Za-z0-9_]*)\}", entry))
    if refs - set(outputs):
        raise ValueError("浏览器登录入口只能引用所选流程的输出变量")
    if "${" in re.sub(r"\$\{[A-Za-z][A-Za-z0-9_]*\}", "", entry):
        raise ValueError("浏览器登录入口变量格式无效")


def flow_step_ids(config):
    return {step for flow in config.get("api_auth_flows", []) for step in flow["step_ids"]}


def validate_auth_flows(config, validate_check):
    flows = config.get("api_auth_flows", [])
    if not isinstance(flows, list):
        raise ValueError("登录前置流程必须是列表")
    checks = {check["id"]: check for check in config["checks"]}
    ids, members = set(), set()
    for flow in flows:
        if not isinstance(flow, dict):
            raise ValueError("登录前置流程必须是对象")
        fid = flow.get("id", "")
        if not isinstance(fid, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", fid) or fid in ids:
            raise ValueError("登录前置流程 ID 无效或重复")
        ids.add(fid)
        if not isinstance(flow.get("name"), str) or not flow["name"].strip():
            raise ValueError(f"{fid}: 流程名称不能为空")
        if not isinstance(flow.get("enabled"), bool):
            raise ValueError(f"{fid}: 流程启用状态必须是布尔值")
        steps = flow.get("step_ids")
        if not isinstance(steps, list) or not steps or any(not isinstance(s, str) for s in steps):
            raise ValueError(f"{fid}: 需要有序的登录步骤列表")
        if len(set(steps)) != len(steps) or members.intersection(steps):
            raise ValueError(f"{fid}: 步骤重复或已属于其他流程")
        members.update(steps)
        for sid in steps:
            check = checks.get(sid)
            if not check or check.get("type", "api") != "api":
                raise ValueError(f"{fid}: 登录步骤 {sid} 不存在")
            if check.get("auth_flow_id"):
                raise ValueError(f"{fid}: 登录步骤不能再依赖其他前置流程")
            if bool(check.get("enabled")) != flow["enabled"]:
                raise ValueError(f"{fid}: 请整体启用或停用登录流程")
            if flow["enabled"]:
                validate_check(check, config)
        outputs = flow.get("outputs")
        if not isinstance(outputs, dict) or "token" not in outputs or any(
            not isinstance(k, str) or not isinstance(v, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", k)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v)
            for k, v in outputs.items()
        ):
            raise ValueError(f"{fid}: 输出映射必须包含 token，例如 {{\"token\": \"suposTicket\"}}")
        validate_browser_entry_url(flow.get("browser_entry_url", ""), config, outputs)
        extracted = {rule.get("variable") for sid in steps for rule in checks[sid].get("extract", [])}
        if flow["enabled"] and any(source not in extracted for source in outputs.values()):
            raise ValueError(f"{fid}: 输出变量必须由流程步骤提取")
        available = set()
        for sid in steps:
            check = checks[sid]
            refs = set(re.findall(r"\$\{([A-Za-z][A-Za-z0-9_]*)(?:\|[A-Za-z][A-Za-z0-9_]*)?\}", json.dumps(
                {k: check.get(k) for k in ("path", "headers", "body", "assertions")}
            )))
            if flow["enabled"] and (refs & extracted) - available:
                raise ValueError(f"{fid}: {sid} 引用了尚未提取的变量，请调整步骤顺序")
            available.update(rule.get("variable") for rule in check.get("extract", []))
        if flow["enabled"] and not checks[steps[-1]].get("assertions"):
            raise ValueError(f"{fid}: 最后一步需要业务断言验证登录成功")
    by_id = {flow["id"]: flow for flow in flows}
    for check in checks.values():
        fid = check.get("auth_flow_id")
        if fid is None:
            continue
        if not isinstance(fid, str) or fid not in by_id or check.get("type", "api") != "api":
            raise ValueError(f"{check['id']}: 登录前置流程不存在或类型无效")
        if check.get("enabled") and not by_id[fid]["enabled"]:
            raise ValueError(f"{check['id']}: 请先验证并启用登录前置流程")


def auth_flow_hash(config, flow, credentials=None):
    checks = {item["id"]: item for item in config["checks"]}
    steps = [{k: v for k, v in checks[sid].items()
              if k not in ("enabled", "pending_arguments", "read_only")}
             for sid in flow["step_ids"]]
    value = {
        # The default browser entry is validated independently and exercised by
        # UI tests; it does not change the API request/extraction contract.
        "flow": {k: v for k, v in flow.items() if k not in ("enabled", "browser_entry_url")}, "steps": steps,
        "environment": {k: config.get(k) for k in
                        ("base_url", "allowed_origins", "adapter", "variables", "default_timeout_seconds")},
        "credentials": credentials or {},
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def redact_auth_evidence(result, values):
    """Keep runtime credentials out of messages and recorded assertion values."""
    secrets = sorted({value for value in values if isinstance(value, str) and value}, key=len, reverse=True)
    secrets = sorted(set(secrets) | {base64.b64encode(value.encode()).decode() for value in secrets}, key=len, reverse=True)

    def redact(value):
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, "***")
            return value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    for key in ("reason", "assertions", "evidence"):
        if key in result:
            result[key] = redact(result[key])
    return result


def execute_auth_flow(config, flow, initial_variables, execute_check, build_openers):
    """Return public evidence, exported values, and isolated cookie-aware openers."""
    checks = {check["id"]: check for check in config["checks"]}
    openers = build_openers(config)
    variables = copy.deepcopy(initial_variables or {})
    # Stale configured tokens must never satisfy a missing extraction.
    for sid in flow["step_ids"]:
        for rule in checks[sid].get("extract", []):
            variables.pop(rule["variable"], None)
    results, failed = [], False
    for sid in flow["step_ids"]:
        step = checks[sid]
        if failed:
            results.append({"id": sid, "name": step["name"], "type": "api", "status": "skipped",
                            "classification": "authentication_failed", "reason": "前序登录步骤失败，未执行",
                            "assertions": [], "evidence": {}, "alert_enabled": False,
                            "severity": step.get("severity", "P2"), "auth_flow_id": flow["id"]})
            continue
        scoped = dict(variables)
        scoped.update(step.get("variables", {}))
        result = execute_check(step, config, openers[0] if step.get("follow_redirects", True) else openers[1], scoped)
        result["auth_flow_id"] = flow["id"]
        result["extracted_variables"] = [{"name": rule["variable"], "present": scoped.get(rule["variable"]) not in (None, "", [], {})}
                                          for rule in step.get("extract", [])]
        results.append(result)
        variables.update({k: v for k, v in scoped.items() if k not in step.get("variables", {})})
        failed = result["status"] != "passed"
    exports = {name: variables.get(source) for name, source in flow["outputs"].items()} if not failed else {}
    if not failed and any(value in (None, "", [], {}) for value in exports.values()):
        failed = True
        results[-1].update(status="failed", classification="authentication_failed", reason="流程输出变量为空，未发布凭证")
    if not failed and (not isinstance(exports.get("token"), str) or not exports["token"].strip()):
        failed = True
        results[-1].update(status="failed", classification="authentication_failed", reason="token 输出必须是非空字符串，未发布凭证")
    sensitive_names = {"token", "ticket", "suposTicket", "lt", "JSESSIONID", "SRM_PASSWORD", flow["outputs"]["token"]}
    for result in results:
        # Authentication assertions only expose the pass/fail decision.
        for assertion in result.get("assertions", []):
            assertion.pop("actual", None)
        redact_auth_evidence(result, [variables.get(name) for name in sensitive_names])
    if failed:
        exports = {}
    public = {"id": flow["id"], "name": flow["name"], "status": "failed" if failed else "passed",
              "checks": results, "outputs": [{"name": name, "source": source,
              "present": name in exports, "value": "已获取 · 已脱敏" if name in exports else "未获取"}
              for name, source in flow["outputs"].items()]}
    return public, exports, openers


def browser_cookies(openers):
    """Export the live cookie jar without changing any domain or path scope.

    This is runtime-only data. It must not be attached to public results or
    written to configuration, reports, or the verification store.
    """
    for handler in openers[0].handlers:
        if not isinstance(handler, HTTPCookieProcessor):
            continue
        cookies = []
        for cookie in handler.cookiejar:
            if cookie.expires is not None and cookie.expires <= time.time():
                continue
            item = {
                "name": cookie.name, "value": cookie.value,
                "domain": cookie.domain, "path": cookie.path or "/",
                "secure": bool(cookie.secure),
                "httpOnly": cookie.has_nonstandard_attr("HttpOnly"),
            }
            if cookie.expires is not None:
                item["expires"] = cookie.expires
            same_site = cookie.get_nonstandard_attr("SameSite")
            if isinstance(same_site, str) and same_site.lower() in ("strict", "lax", "none"):
                item["sameSite"] = same_site.capitalize()
            cookies.append(item)
        return cookies
    return []
