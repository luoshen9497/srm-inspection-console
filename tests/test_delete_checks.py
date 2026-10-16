import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import AuthManager, ConfigRepository, InspectionManager, InspectionState, make_handler


class DeleteCheckTests(unittest.TestCase):
    def config(self, system_id="demo-system"):
        return {
            "system_id": system_id, "environment": "test",
            "base_url": "https://example.test",
            "checks": [
                {"id": "api-query", "name": "API 查询", "enabled": False},
                {"id": "ui-home", "name": "首页", "type": "ui", "enabled": False, "steps": []},
            ],
        }

    def state(self, root, split=True, config=None):
        path = root / "demo-system.json"
        path.write_text(json.dumps(config or self.config()))
        if split:
            ConfigRepository(path).migrate()
        return InspectionState(path, root / "runs", use_environment_fallback=False)

    def test_delete_each_kind_preserves_other_domain_and_records_audit(self):
        for split in (False, True):
            for kind, item_id in (("api", "api-query"), ("ui", "ui-home")):
                with self.subTest(split=split, kind=kind), tempfile.TemporaryDirectory() as temp:
                    state = self.state(Path(temp), split)
                    before = state.repository.versions()
                    result = state.delete_collection_item(kind, item_id, {"version": before[f"{kind}_version"]})
                    self.assertEqual(result["items"], [])
                    after = state.repository.versions()
                    self.assertNotEqual(result["version"], before[f"{kind}_version"])
                    self.assertEqual(len(after["config"]["checks"]), 1)
                    if split:
                        other = "ui" if kind == "api" else "api"
                        self.assertEqual(after[f"{other}_version"], before[f"{other}_version"])
                        self.assertEqual(after["settings_version"], before["settings_version"])
                    audit = json.loads(next(state.audit_dir.glob("*.json")).read_text())
                    self.assertEqual(audit["changed_checks"], [item_id])
                    self.assertEqual(audit["domain"], kind)

    def test_invalid_or_stale_delete_does_not_change_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp))
            document = state.api_checks_document()
            document["items"][0]["name"] = "其他页面的修改"
            saved = state.update_api_checks(document)
            for payload, error, message in (
                ({}, ValueError, "缺少巡检配置版本"),
                (None, ValueError, "缺少巡检配置版本"),
                ({"version": document["version"]}, RuntimeError, "重新加载"),
            ):
                with self.subTest(payload=payload), self.assertRaisesRegex(error, message):
                    state.delete_collection_item("api", "api-query", payload)
                self.assertEqual(state.api_checks_document(), saved)
            with self.assertRaisesRegex(ValueError, "不存在"):
                state.delete_collection_item("api", "ui-home", {"version": saved["version"]})
            self.assertEqual(state.api_checks_document(), saved)

    def test_referenced_login_scene_cannot_be_deleted_even_for_draft_dependents(self):
        config = self.config()
        config["checks"][1]["login_precheck"] = True
        config["checks"].append({
            "id": "ui-query", "name": "业务查询", "type": "ui", "enabled": False,
            "steps": [], "auth_dependency": {"scene_id": "ui-home"},
        })
        with tempfile.TemporaryDirectory() as temp:
            state = self.state(Path(temp), config=config)
            document = state.ui_scenes_document()
            with self.assertRaisesRegex(ValueError, "先解除关联.*业务查询"):
                state.delete_collection_item("ui", "ui-home", {"version": document["version"]})
            self.assertEqual(state.ui_scenes_document(), document)
            document["items"][1].pop("auth_dependency")
            saved = state.update_ui_scenes(document)
            result = state.delete_collection_item("ui", "ui-home", {"version": saved["version"]})
            self.assertEqual([item["id"] for item in result["items"]], ["ui-query"])

    def test_last_item_can_be_deleted_without_removing_historical_reports(self):
        for split in (False, True):
            with self.subTest(split=split), tempfile.TemporaryDirectory() as temp:
                state = self.state(Path(temp), split)
                report = state.data_dir / "20261009T010000Z-12345678.json"
                report.write_text(json.dumps({"run_id": report.stem, "checks": [{"id": "api-query"}]}))
                report_bytes = report.read_bytes()
                for kind, item_id in (("api", "api-query"), ("ui", "ui-home")):
                    document = state.repository.collection_document(kind)
                    state.delete_collection_item(kind, item_id, {"version": document["version"]})
                self.assertEqual(state.repository.load()[0]["checks"], [])
                self.assertEqual(state.summary()["enabled_checks"], 0)
                self.assertEqual(report.read_bytes(), report_bytes)
                with self.assertRaisesRegex(ValueError, "尚无.*巡检项"):
                    state.start_run()

    def test_http_delete_requires_session_csrf_and_scopes_both_kinds_to_system(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {
            "INSPECTION_ADMIN_USERNAME": "operator",
            "INSPECTION_ADMIN_PASSWORD": "delete-test-password-123",
        }):
            root = Path(temp)
            entries = []
            for system_id in ("alpha-system", "beta-system"):
                path = root / f"{system_id}.json"
                path.write_text(json.dumps(self.config(system_id)))
                ConfigRepository(path).migrate()
                entries.append({"system_id": system_id, "config": path.name})
            registry = root / "systems.json"
            registry.write_text(json.dumps({"systems": entries}))
            manager = InspectionManager(registry, root / "data")
            auth = AuthManager(root / "auth.db", root / "admin.json")
            def request(path, payload, headers=None):
                body = json.dumps(payload).encode()
                request_headers = {
                    "Host": "localhost", "Connection": "close",
                    "Content-Type": "application/json", "Content-Length": str(len(body)),
                    **(headers or {}),
                }
                raw = (f"DELETE {path} HTTP/1.1\r\n" + "".join(
                    f"{key}: {value}\r\n" for key, value in request_headers.items()
                ) + "\r\n").encode() + body

                class MemorySocket:
                    output = io.BytesIO()

                    def makefile(self, *_):
                        return io.BytesIO(raw)

                    def sendall(self, data):
                        self.output.write(data)

                connection = MemorySocket()
                make_handler(manager, auth)(connection, ("127.0.0.1", 12345), None)
                response_headers, response_body = connection.output.getvalue().split(b"\r\n\r\n", 1)
                return int(response_headers.split(b" ")[1]), json.loads(response_body)

            session = auth.login("operator", "delete-test-password-123")
            cookie = {"Cookie": f"{auth.SESSION_COOKIE}={session['token']}"}
            authorized = {**cookie, "X-CSRF-Token": session["csrf_token"]}
            alpha = manager.get_state("alpha-system")
            beta_before = manager.get_state("beta-system").repository.versions()
            for kind, collection, item_id in (("api", "api-checks", "api-query"), ("ui", "ui-scenes", "ui-home")):
                path = f"/api/systems/alpha-system/{collection}/{item_id}"
                payload = {"version": alpha.repository.collection_document(kind)["version"]}
                self.assertEqual(request(path, payload)[0], 401)
                self.assertEqual(request(path, payload, cookie)[0], 403)
                self.assertEqual(request(path + "/invalid", payload, authorized)[0], 422)
                self.assertEqual(request(path, {"version": "stale"}, authorized)[0], 409)
                status, result = request(path, payload, authorized)
                self.assertEqual(status, 200)
                self.assertEqual(result["items"], [])
            self.assertEqual(manager.get_state("beta-system").repository.versions(), beta_before)


if __name__ == "__main__":
    unittest.main()
