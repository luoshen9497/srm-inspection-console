import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from deploy.sync_ui_scenes import merge_scenes, save_backup, sync


class SyncUiScenesTests(unittest.TestCase):
    def setUp(self):
        self.items = [{"id": "server-only", "name": "线上独有", "enabled": False}]
        self.api_items = [{"id": "api-login", "enabled": True}]
        self.version = 1
        self.calls = []
        self.fail_test = None
        self.reject_save = False

    def api(self, system, endpoint, payload=None, method=None):
        self.calls.append((endpoint, copy.deepcopy(payload)))
        if endpoint == "config":
            return {"config": {"system_id": system, "schedule": {"enabled": True},
                               "checks": self.api_items + [{**x, "type": "ui"} for x in self.items]}}
        if endpoint == "config/validate":
            return {"valid": True}
        if endpoint == "settings":
            if method == "PUT":
                self.assertEqual(payload["version"], str(self.version))
                self.version += 1  # Legacy settings and UI share a version.
            return {"version": str(self.version), "settings": {"system_id": system}}
        if endpoint == "ui-scenes/test":
            check = payload["check"]
            dependency = check.get("auth_dependency", {}).get("scene_id")
            if dependency:
                self.assertTrue(next(x for x in self.items if x["id"] == dependency)["enabled"])
            passed = check["id"] != self.fail_test
            return {"status": "passed" if passed else "failed", "verified": passed}
        if endpoint == "ui-scenes":
            if method == "PUT":
                if self.reject_save:
                    raise RuntimeError("并发修改")
                self.assertEqual(payload["version"], str(self.version))
                self.items = copy.deepcopy(payload["items"])
                self.version += 1
            return {"items": copy.deepcopy(self.items), "version": str(self.version)}
        self.fail(endpoint)

    def run_sync(self, credentials=None, **kwargs):
        source = [
            {"id": "business", "name": "查询", "enabled": True,
             "auth_dependency": {"scene_id": "login"}},
            {"id": "login", "name": "登录", "enabled": True, "login_precheck": True},
        ]
        with redirect_stdout(io.StringIO()):
            return sync({"system_id": "overseas-srm", "items": source,
                         "credentials": credentials or {}},
                        api=self.api, backup=lambda *args: "/backup", **kwargs)

    def test_merge_preserves_unrelated_scenes_and_rejects_duplicate_ids(self):
        merged = merge_scenes(self.items, [{"id": "login"}])
        self.assertEqual(merged, self.items + [{"id": "login"}])
        with self.assertRaises(ValueError):
            merge_scenes(self.items, [{"id": "login"}, {"id": "login"}])

    def test_preview_does_not_save_or_test(self):
        self.run_sync()
        self.assertEqual(self.items, [{"id": "server-only", "name": "线上独有", "enabled": False}])
        self.assertFalse(any(payload and "version" in payload for _, payload in self.calls))
        self.assertNotIn("ui-scenes/test", [endpoint for endpoint, _ in self.calls])

    def test_apply_only_stages_imported_enabled_scenes(self):
        self.run_sync(apply=True)
        self.assertEqual([x["enabled"] for x in self.items], [False, False, False])
        self.assertEqual(self.api_items, [{"id": "api-login", "enabled": True}])

    def test_enable_tests_login_before_business_and_preserves_other_scenes(self):
        self.run_sync(apply=True, enable=True)
        tested = [payload["check"]["id"] for endpoint, payload in self.calls if endpoint == "ui-scenes/test"]
        self.assertEqual(tested, ["login", "business"])
        self.assertEqual([x["enabled"] for x in self.items], [False, True, True])

    def test_failed_business_test_remains_disabled(self):
        self.fail_test = "business"
        with self.assertRaisesRegex(RuntimeError, "business"):
            self.run_sync(apply=True, enable=True)
        saved = {x["id"]: x for x in self.items}
        self.assertTrue(saved["login"]["enabled"])
        self.assertFalse(saved["business"]["enabled"])

    def test_concurrent_save_failure_stops_before_tests(self):
        self.reject_save = True
        with self.assertRaisesRegex(RuntimeError, "并发修改"):
            self.run_sync(apply=True, enable=True)
        self.assertNotIn("ui-scenes/test", [endpoint for endpoint, _ in self.calls])

    def test_empty_source_is_not_a_delete_request(self):
        with self.assertRaisesRegex(ValueError, "空集合"):
            sync({"system_id": "overseas-srm", "items": []}, api=self.api)
        self.assertEqual(self.calls, [])

    def test_ui_credentials_refresh_shared_legacy_version_before_scene_save(self):
        self.run_sync(apply=True, enable=True,
                      credentials={"ui_username": "test-user", "ui_password": "test-password"})
        self.assertEqual([x["enabled"] for x in self.items], [False, True, True])
        credential_updates = [payload for endpoint, payload in self.calls
                              if endpoint == "settings" and payload]
        self.assertEqual(len(credential_updates), 1)
        self.assertEqual(set(credential_updates[0]["credentials"]), {"ui_username", "ui_password"})

    def test_backup_writes_private_recoverable_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(save_backup("overseas-srm", {"config": {}},
                                      {"items": self.items}, root=Path(directory)))
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            for name in ("config.json", "ui-scenes.json"):
                self.assertEqual((folder / name).stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((folder / "ui-scenes.json").read_text())["items"], self.items)


if __name__ == "__main__":
    unittest.main()
