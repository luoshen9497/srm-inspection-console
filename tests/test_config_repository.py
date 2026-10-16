import json
import tempfile
import unittest
from pathlib import Path

from app import ConfigRepository


class ConfigRepositoryTests(unittest.TestCase):
    def config(self):
        return {
            "system_id": "demo-system",
            "display_name": "Demo",
            "environment": "test",
            "base_url": "https://example.test",
            "checks": [
                {"id": "api-login", "name": "API 登录", "category": "会话", "enabled": False},
                {
                    "id": "ui-home", "name": "首页", "category": "门户", "type": "ui",
                    "enabled": False, "steps": [],
                },
            ],
        }

    def repository(self, root: Path) -> ConfigRepository:
        path = root / "demo-system.json"
        path.write_text(json.dumps(self.config(), ensure_ascii=False, indent=2) + "\n")
        return ConfigRepository(path)

    def test_migration_splits_documents_without_changing_runtime_config(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = self.repository(Path(temp))
            legacy, _ = repository.load()
            preview = repository.migration_preview()
            self.assertEqual((preview["api_count"], preview["ui_count"]), (1, 1))

            result = repository.migrate()

            self.assertTrue(result["migrated"])
            self.assertTrue(repository.split)
            migrated, _ = repository.load()
            self.assertEqual(migrated, {
                **legacy,
                "checks": [
                    {**legacy["checks"][0], "type": "api"},
                    legacy["checks"][1],
                ],
            })
            self.assertNotIn("checks", json.loads(repository.system_path.read_text()))
            self.assertNotIn("type", json.loads(repository.api_path.read_text())["items"][0])
            self.assertNotIn("type", json.loads(repository.ui_path.read_text())["items"][0])

    def test_split_domains_have_independent_versions_and_global_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = self.repository(Path(temp))
            repository.migrate()
            before = repository.versions()
            api = repository.collection_document("api")
            api["items"][0]["name"] = "新的 API 登录"

            repository.save_collection("api", api["items"], api["version"])
            after = repository.versions()

            self.assertNotEqual(before["api_version"], after["api_version"])
            self.assertEqual(before["settings_version"], after["settings_version"])
            self.assertEqual(before["ui_version"], after["ui_version"])
            with self.assertRaisesRegex(RuntimeError, "重新加载"):
                repository.save_collection("api", api["items"], api["version"])

            duplicate = [{"id": "ui-home", "name": "冲突", "category": "测试", "enabled": False}]
            with self.assertRaisesRegex(ValueError, "ID 已存在"):
                repository.save_collection("api", duplicate, after["api_version"])

    def test_settings_save_does_not_rewrite_check_documents(self):
        with tempfile.TemporaryDirectory() as temp:
            repository = self.repository(Path(temp))
            repository.migrate()
            before = repository.versions()
            document = repository.settings_document()
            document["settings"]["report_limit"] = 45

            repository.save_settings(document["settings"], document["version"])
            after = repository.versions()

            self.assertNotEqual(before["settings_version"], after["settings_version"])
            self.assertEqual(before["api_version"], after["api_version"])
            self.assertEqual(before["ui_version"], after["ui_version"])
            config, _ = repository.load()
            self.assertEqual(config["report_limit"], 45)


if __name__ == "__main__":
    unittest.main()
