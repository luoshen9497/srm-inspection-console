#!/usr/bin/env python3
"""Split legacy per-system configuration into independently versioned documents."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app import ConfigRepository, DEFAULT_REGISTRY


def repositories(registry_path: Path) -> list[ConfigRepository]:
    registry = json.loads(registry_path.read_text())
    result = []
    for entry in registry.get("systems", []):
        config_path = (registry_path.parent / entry["config"]).resolve()
        result.append(ConfigRepository(config_path))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="拆分系统、API 巡检和 UI 场景配置")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--dry-run", action="store_true", help="只显示迁移计划，不写入文件")
    args = parser.parse_args()

    reports = []
    for repository in repositories(args.registry.resolve()):
        reports.append(repository.migration_preview() if args.dry_run else repository.migrate())
    print(json.dumps({"dry_run": args.dry_run, "systems": reports}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
