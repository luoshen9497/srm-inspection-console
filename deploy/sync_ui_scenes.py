#!/usr/bin/env python3
"""Merge UI scenes through the running server's versioned, audited APIs.

Run on the deployment host; verification_session requires Docker access.
The bundle contains one system's UI collection and optionally UI credentials.
"""
import argparse
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen

if __package__:
    from .verification_session import verification_session
else:
    from verification_session import verification_session


def request(system_id, endpoint, payload=None, method=None):
    # A fresh short-lived session per request also supports long browser tests.
    with verification_session() as (cookie, csrf):
        data = None if payload is None else json.dumps(payload).encode()
        req = Request(
            f"http://127.0.0.1:18091/api/systems/{system_id}/{endpoint}",
            data=data, method=method,
            headers={"Cookie": cookie, "X-CSRF-Token": csrf,
                     "Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=600) as response:
                return json.load(response)
        except HTTPError as error:
            # Keep server details and any sensitive values out of terminal logs.
            raise RuntimeError(f"{endpoint}: HTTP {error.code}") from None


def merge_scenes(current, source):
    """Replace matching IDs, append new IDs, retain other production scenes."""
    incoming = {scene["id"]: copy.deepcopy(scene) for scene in source}
    if len(incoming) != len(source):
        raise ValueError("待同步场景 ID 重复")
    merged = [incoming.pop(scene["id"], copy.deepcopy(scene)) for scene in current]
    return merged + list(incoming.values())


def save_backup(system_id, config, scenes, root=Path("/var/backups/srm-inspection")):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    folder = root / f"ui-{system_id}-{stamp}"
    folder.mkdir(mode=0o700, parents=True)
    # Config API is already redacted; the previous UI collection is recoverable.
    for name, value in (("config.json", config), ("ui-scenes.json", scenes)):
        path = folder / name
        with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
            json.dump(value, file, ensure_ascii=False, indent=2)
            file.write("\n")
    return str(folder)


def sync(bundle, apply=False, enable=False, api=request, backup=save_backup):
    system_id = bundle.get("system_id", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", system_id):
        raise ValueError("system_id 格式无效")
    source = bundle.get("items")
    if not isinstance(source, list) or not source:
        raise ValueError("没有待同步 UI 场景；空集合不会删除线上场景")
    for scene in source:
        if not isinstance(scene, dict) or scene.get("type", "ui") != "ui":
            raise ValueError("仅支持 UI 场景")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", str(scene.get("id", ""))):
            raise ValueError("场景 ID 格式无效")
        scene.pop("type", None)
    credentials = bundle.get("credentials", {})
    if (not isinstance(credentials, dict)
            or set(credentials) - {"ui_username", "ui_password"}
            or any(not isinstance(value, str) or not value for value in credentials.values())):
        raise ValueError("只允许同步非空 UI 账号和密码")

    before = api(system_id, "config")
    current = api(system_id, "ui-scenes")
    final_items = merge_scenes(current["items"], source)
    candidate = copy.deepcopy(before["config"])
    candidate["checks"] = [item for item in candidate["checks"]
                           if item.get("type", "api") != "ui"]
    candidate["checks"] += [{**item, "type": "ui"} for item in final_items]
    api(system_id, "config/validate", {"config": candidate})
    summary = {"system_id": system_id, "apply": apply,
               "source_ids": [item["id"] for item in source],
               "total_ui_scenes": len(final_items),
               "sync_ui_credentials": bool(credentials)}
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    if not apply:
        return summary
    if current["items"] == final_items and not credentials and not enable:
        return {**summary, "unchanged": True}

    summary["backup"] = backup(system_id, before, current)
    print("backup:", summary["backup"], flush=True)
    if credentials:
        settings = api(system_id, "settings")
        api(system_id, "settings", {"version": settings["version"],
                                    "settings": settings["settings"],
                                    "credentials": credentials}, method="PUT")
        # Legacy deployments share one version across settings and scenes.
        refreshed = api(system_id, "ui-scenes")
        if refreshed["items"] != current["items"]:
            raise RuntimeError("同步凭据期间 UI 场景被其他页面修改，请重新预演")
        current = refreshed

    old = {item["id"]: item for item in current["items"]}
    pending = []
    staged = copy.deepcopy(final_items)
    for scene in staged:
        if scene["id"] in {item["id"] for item in source}:
            unchanged_enabled = old.get(scene["id"]) == scene and scene.get("enabled")
            if scene.get("enabled") and not unchanged_enabled:
                pending.append(copy.deepcopy(scene))
                scene["enabled"] = False
    current = api(system_id, "ui-scenes", {"version": current["version"],
                                          "items": staged}, method="PUT")
    failures = []
    if enable:
        # Login dependencies must be saved as enabled before business tests.
        for scene in sorted(pending, key=lambda item: not item.get("login_precheck", False)):
            result = api(system_id, "ui-scenes/test", {"check": {**scene, "type": "ui"}})
            print(json.dumps({"scene_id": scene["id"], "test_id": result.get("test_id"),
                              "status": result.get("status")}, ensure_ascii=False), flush=True)
            if result.get("status") != "passed" or result.get("verified") is not True:
                failures.append(scene["id"])
                continue
            items = [copy.deepcopy(scene) if item["id"] == scene["id"] else item
                     for item in current["items"]]
            current = api(system_id, "ui-scenes", {"version": current["version"],
                                                  "items": items}, method="PUT")
    after = api(system_id, "config")
    before_settings = {k: v for k, v in before["config"].items() if k != "checks"}
    after_settings = {k: v for k, v in after["config"].items() if k != "checks"}
    before_api = [item for item in before["config"]["checks"] if item.get("type", "api") != "ui"]
    after_api = [item for item in after["config"]["checks"] if item.get("type", "api") != "ui"]
    if before_settings != after_settings or before_api != after_api:
        raise RuntimeError("系统设置或 API 配置发生变化，请检查备份及并发修改")
    saved = api(system_id, "ui-scenes")
    if saved["items"] != current["items"]:
        raise RuntimeError("同步后 UI 配置发生并发修改，请重新检查")
    summary["scenes"] = [{"id": item["id"], "enabled": item.get("enabled", False)}
                         for item in saved["items"]]
    summary["failed_tests"] = failures
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    if failures:
        raise RuntimeError("场景已同步为草稿，完整测试未通过：" + ", ".join(failures))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--enable", action="store_true", help="完整测试通过后启用本地已启用场景")
    args = parser.parse_args()
    try:
        sync(json.loads(args.bundle.read_text()), apply=args.apply, enable=args.enable)
    except (RuntimeError, ValueError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
