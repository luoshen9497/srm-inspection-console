"""Evidence artifact storage with strict run and path boundaries."""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import shutil
from pathlib import Path


SAFE_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _safe_segment(value: str, label: str) -> str:
    value = str(value)
    if not SAFE_SEGMENT.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"{label}格式无效")
    return value


class ArtifactStore:
    """Own artifacts for a single run beneath one system-specific root."""

    def __init__(self, root: Path, run_id: str):
        self.root = Path(root)
        self.run_id = _safe_segment(run_id, "run_id")
        self.run_dir = self.root / self.run_id

    def reset(self) -> None:
        if self.run_dir.exists():
            shutil.rmtree(self.run_dir)
        self.run_dir.mkdir(parents=True, mode=0o700)
        os.chmod(self.run_dir, 0o700)

    def check_dir(self, check_id: str) -> Path:
        target = self.run_dir / _safe_segment(check_id, "检查项 ID")
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target, 0o700)
        return target

    def screenshot_path(self, check_id: str, sequence: int, step_id: str,
                        suffix: str = "") -> Path:
        safe_step = _safe_segment(step_id, "步骤 ID")
        safe_suffix = f"-{_safe_segment(suffix, '截图后缀')}" if suffix else ""
        return self.check_dir(check_id) / f"{sequence:02d}-{safe_step}{safe_suffix}.png"

    def trace_path(self) -> Path:
        target = self.run_dir / "browser-trace.zip"
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        return target

    def metadata(self, path: Path) -> dict:
        resolved = path.resolve()
        run_root = self.run_dir.resolve()
        if not resolved.is_relative_to(run_root) or not resolved.is_file():
            raise ValueError("证据文件不存在或路径越界")
        digest = hashlib.sha256()
        size = 0
        with resolved.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        return {
            "artifact_id": resolved.relative_to(run_root).as_posix(),
            "sha256": digest.hexdigest(),
            "bytes": size,
            "content_type": mimetypes.guess_type(resolved.name)[0] or "application/octet-stream",
        }


def resolve_artifact(root: Path, run_id: str, artifact_id: str) -> Path | None:
    safe_run_id = _safe_segment(run_id, "run_id")
    parts = Path(str(artifact_id)).parts
    if not parts or any(not SAFE_SEGMENT.fullmatch(part) or part in (".", "..") for part in parts):
        raise ValueError("artifact_id 格式无效")
    run_root = (Path(root) / safe_run_id).resolve()
    target = run_root.joinpath(*parts).resolve()
    if not target.is_relative_to(run_root):
        raise ValueError("证据文件路径越界")
    return target if target.is_file() else None


def remove_run_artifacts(root: Path, run_id: str) -> None:
    safe_run_id = _safe_segment(run_id, "run_id")
    target = (Path(root) / safe_run_id).resolve()
    root_resolved = Path(root).resolve()
    if not target.is_relative_to(root_resolved):
        raise ValueError("证据清理路径越界")
    if target.exists():
        shutil.rmtree(target)
