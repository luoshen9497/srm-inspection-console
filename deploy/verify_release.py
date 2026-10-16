import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent
manifest = json.loads((root / "release.json").read_text())
for relative, expected in manifest["files"].items():
    path = (root / relative).resolve()
    assert root in path.parents, relative
    assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, relative
print("release_checksums_verified:", manifest["version"])
