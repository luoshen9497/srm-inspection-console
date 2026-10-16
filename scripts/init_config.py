#!/usr/bin/env python3
"""Copy public example configuration without overwriting existing settings."""
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
examples = ROOT / 'config' / 'examples'
for source in sorted(examples.rglob('*.json')):
    destination = ROOT / 'config' / source.relative_to(examples)
    if destination.exists():
        print('kept:', destination.relative_to(ROOT))
        continue
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    print('created:', destination.relative_to(ROOT))
