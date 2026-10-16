#!/usr/bin/env python3
"""Create a code-only, checksummed release archive; never package live data."""
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    files = [ROOT / name for name in (
        "app.py", "api_auth.py", "operations.py", "artifact_store.py", "browser_executor.py",
        "migrate_config_v2.py", "migrate_api_auth_flows.py", "requirements.txt", ".dockerignore",
    )]
    files += sorted(p for folder in ("static", "deploy")
                    for p in (ROOT / folder).rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts)
    checksums = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in files}
    revision = hashlib.sha256(json.dumps(checksums, sort_keys=True).encode()).hexdigest()
    version = "r-" + revision[:16]
    destination = ROOT / ".releases" / version
    destination.mkdir(parents=True, exist_ok=True)
    manifest = {"version": version, "image": "srm-inspection:" + version,
                "source_sha256": revision, "files": checksums}
    manifest_path = destination / "release.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    archive_path = destination / "release.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for path in files:
            archive.add(path, arcname=str(path.relative_to(ROOT)), recursive=False)
        archive.add(manifest_path, arcname="release.json", recursive=False)
    print(json.dumps({"version": version, "image": manifest["image"],
                      "archive": str(archive_path),
                      "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
