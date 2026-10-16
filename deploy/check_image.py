"""Validate mounted production configuration and local Chromium without running SRM."""
import json
from pathlib import Path
import tempfile

from app import ConfigRepository
from playwright.sync_api import sync_playwright

registry = Path("/config/systems.json")
systems = json.loads(registry.read_text())["systems"]
for entry in systems:
    config, _ = ConfigRepository(registry.parent / entry["config"]).load()
    print("configuration_valid:", config["system_id"], "checks:", len(config["checks"]))
with sync_playwright() as runtime:
    browser = runtime.chromium.launch(headless=True)
    page = browser.new_page()
    page.set_content("<main><h1>Release verification</h1></main>")
    assert page.locator("h1").inner_text() == "Release verification"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "verification.png"
        page.screenshot(path=str(path))
        assert path.stat().st_size > 0
    print("chromium_verified:", browser.version)
    browser.close()
