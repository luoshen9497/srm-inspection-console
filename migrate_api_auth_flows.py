#!/usr/bin/env python3
"""Group the existing UBD CAS login chain without executing any requests."""
import argparse
import copy
import json
from pathlib import Path

from app import ConfigRepository


def prepare(config):
    candidate = copy.deepcopy(config)
    if candidate.get("api_auth_flows"):
        return candidate, False
    names = ("/cas/login", "登录-step1", "登录-step2", "获取用户信息")
    matches = [[c for c in candidate["checks"] if c.get("name") == name and c.get("type", "api") == "api"] for name in names]
    if candidate.get("adapter") != "cas-session-v1" or any(len(items) != 1 for items in matches):
        raise ValueError("配置中没有唯一的四步 UBD 登录链，请在页面中创建登录前置流程")
    steps = [items[0] for items in matches]
    steps[0]["path"] = steps[1]["path"]
    if steps[1].get("origin"):
        steps[0]["origin"] = steps[1]["origin"]
    else:
        steps[0].pop("origin", None)
    steps[0]["extract"] = [
        {"variable": "lt", "source": "body", "pattern": r'''name=["']lt["'][^>]*value=["']([^"']+)'''},
        {"variable": "JSESSIONID", "source": "headers", "pattern": r"(?im)^set-cookie:\s*JSESSIONID=([^;\s]+)"},
    ]
    for index, step in enumerate(steps):
        step.update(enabled=False, session_setup=True, login_precheck=index == 3)
    for step, variable in zip(steps[1:3], ("ticket", "suposTicket")):
        step["follow_redirects"] = False
        step["expected_status"] = 302
        step["extract"] = [{"variable": variable, "source": "headers", "pattern": r"[?&]ticket=([^&\s]+)"}]
    flow = {"id": "ubd-login", "name": "UBD 登录流程", "enabled": False,
            "step_ids": [step["id"] for step in steps], "outputs": {
                "token": "suposTicket", **{rule["variable"]: rule["variable"] for rule in steps[-1].get("extract", [])},
            }}
    candidate["api_auth_flows"] = [flow]

    def replace_token(value):
        if isinstance(value, str):
            return value.replace("${suposTicket}", "${token}")
        if isinstance(value, list):
            return [replace_token(item) for item in value]
        if isinstance(value, dict):
            return {key: replace_token(item) for key, item in value.items()}
        return value

    for index, check in enumerate(candidate["checks"]):
        if check.get("type", "api") == "api" and check["id"] not in flow["step_ids"] and "${suposTicket}" in json.dumps(check):
            candidate["checks"][index] = {**replace_token(check), "auth_flow_id": flow["id"], "enabled": False}
    return candidate, True


def main():
    parser = argparse.ArgumentParser(description="将四步 UBD 登录链迁移为停用的登录前置流程")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    repo = ConfigRepository(args.config)
    config, version = repo.load()
    candidate, changed = prepare(config)
    if changed and not args.dry_run:
        # Keep a versioned backup alongside the original configuration.
        source = repo.api_path if repo.split else repo.legacy_path
        backup = source.with_name(source.name + "." + version + ".pre-auth-flow.bak")
        if not backup.exists():
            backup.write_bytes(source.read_bytes())
            backup.chmod(0o600)
        document = repo.collection_document("api")
        repo.save_collection("api", [check for check in candidate["checks"] if check.get("type", "api") == "api"],
                             document["version"], candidate["api_auth_flows"])
    print(json.dumps({"changed": changed, "dry_run": args.dry_run, "flow_count": len(candidate.get("api_auth_flows", []))}))


if __name__ == "__main__":
    main()
