import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import AuthManager


class AuthManagerTests(unittest.TestCase):
    def manager(self, root: Path) -> AuthManager:
        return AuthManager(root / "auth.db", root / "admin.json")

    def test_bootstrap_credentials_are_hashed_and_create_session(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            root = Path(temp)
            manager = self.manager(root)
            self.assertEqual(manager.username, "admin")
            self.assertTrue(manager.bootstrap_password)
            saved = json.loads((root / "admin.json").read_text())
            self.assertNotIn(manager.bootstrap_password, (root / "admin.json").read_text())
            self.assertTrue(saved["password_hash"].startswith("scrypt$"))
            self.assertEqual(stat.S_IMODE((root / "admin.json").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((root / "auth.db").stat().st_mode), 0o600)

            login = manager.login("admin", manager.bootstrap_password, "127.0.0.1", "test")
            self.assertTrue(login["ok"])
            session = manager.session(login["token"])
            self.assertEqual(session["username"], "admin")
            self.assertEqual(session["csrf_token"], login["csrf_token"])
            manager.logout(login["token"])
            self.assertIsNone(manager.session(login["token"]))

    def test_reset_credentials_invalidates_sessions_and_rotates_password(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            manager = self.manager(Path(temp))
            old_password = manager.bootstrap_password
            old_session = manager.login("admin", old_password)
            new_password = manager.reset_credentials()
            self.assertNotEqual(old_password, new_password)
            self.assertIsNone(manager.session(old_session["token"]))
            self.assertFalse(manager.login("admin", old_password)["ok"])
            self.assertTrue(manager.login("admin", new_password)["ok"])

    def test_session_expires_after_thirty_minutes_without_activity_extension(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            manager = self.manager(Path(temp))
            started_at = 1_800_000_000
            with patch("app.time.time", return_value=started_at):
                login = manager.login("admin", manager.bootstrap_password)
            self.assertEqual(login["expires_at"], started_at + 1800)
            for elapsed in (60, 900, 1799):
                with patch("app.time.time", return_value=started_at + elapsed):
                    session = manager.session(login["token"])
                self.assertIsNotNone(session)
                self.assertEqual(session["expires_at"], started_at + 1800)
            with patch("app.time.time", return_value=started_at + 1800):
                self.assertIsNone(manager.session(login["token"]))
            with manager._connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0], 0)

    def test_restart_shortens_existing_eight_hour_session(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            root = Path(temp)
            manager = AuthManager(root / "auth.db", root / "admin.json", session_ttl_seconds=8 * 60 * 60)
            started_at = 1_800_000_000
            with patch("app.time.time", return_value=started_at):
                login = manager.login("admin", manager.bootstrap_password)
            manager = self.manager(root)
            with patch("app.time.time", return_value=started_at + 1799):
                self.assertEqual(manager.session(login["token"])["expires_at"], started_at + 1800)
            with patch("app.time.time", return_value=started_at + 1800):
                self.assertIsNone(manager.session(login["token"]))

    def test_restart_does_not_extend_a_shorter_session(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            root = Path(temp)
            manager = AuthManager(root / "auth.db", root / "admin.json", session_ttl_seconds=300)
            started_at = 1_800_000_000
            with patch("app.time.time", return_value=started_at):
                login = manager.login("admin", manager.bootstrap_password)
            manager = self.manager(root)
            with patch("app.time.time", return_value=started_at + 299):
                self.assertEqual(manager.session(login["token"])["expires_at"], started_at + 300)
            with patch("app.time.time", return_value=started_at + 300):
                self.assertIsNone(manager.session(login["token"]))

    def test_invalid_login_is_generic_and_rate_limited(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {}, clear=True):
            manager = self.manager(Path(temp))
            for _ in range(manager.LOGIN_LIMIT - 1):
                result = manager.login("admin", "wrong-password", "127.0.0.1")
                self.assertFalse(result["ok"])
                self.assertEqual(result["retry_after"], 0)
            blocked = manager.login("admin", "wrong-password", "127.0.0.1")
            self.assertFalse(blocked["ok"])
            self.assertGreater(blocked["retry_after"], 0)
            still_blocked = manager.login("admin", manager.bootstrap_password, "127.0.0.1")
            self.assertFalse(still_blocked["ok"])

    def test_environment_password_does_not_write_local_admin_file(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", {
            "INSPECTION_ADMIN_USERNAME": "operator",
            "INSPECTION_ADMIN_PASSWORD": "a-secure-password-123",
        }, clear=True):
            root = Path(temp)
            manager = self.manager(root)
            self.assertEqual(manager.username, "operator")
            self.assertIsNone(manager.bootstrap_password)
            self.assertFalse((root / "admin.json").exists())
            self.assertTrue(manager.login("operator", "a-secure-password-123")["ok"])


if __name__ == "__main__":
    unittest.main()
