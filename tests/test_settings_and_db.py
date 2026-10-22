"""Unit Tests for Database, Autostart, Theme Manager, and Settings Window

Tests the security architecture, encrypted database,
Windows autostart integration, multi-theme engine, and settings dialog.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import tkinter as tk
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
import autostart
import theme_manager
from settings_window import AppSettingsWindow
from main import RegistryMonitorApp


class TestThemeManager(unittest.TestCase):
    """Tests for theme definitions and palette integrity."""

    def test_all_five_themes_defined(self):
        """Verify that all 5 required cyber themes exist."""
        themes = theme_manager.list_theme_names()
        self.assertEqual(len(themes), 5)
        self.assertIn("Cyber Blue Team", themes)
        self.assertIn("Obsidian Stealth", themes)
        self.assertIn("Matrix Terminal", themes)
        self.assertIn("Crimson Alert", themes)
        self.assertIn("Nordic Frost", themes)

    def test_theme_color_keys_completeness(self):
        """Verify each theme has all mandatory UI color tokens."""
        required_keys = [
            "name", "description", "bg", "card_bg", "card_border", "card_border_accent",
            "accent_primary", "accent_secondary", "fg_primary", "fg_secondary",
            "tree_bg", "tree_fg", "tree_heading_bg", "tree_heading_fg",
            "tree_select_bg", "tree_select_fg", "btn_normal_bg", "btn_normal_fg",
            "btn_active_bg", "entry_bg", "entry_fg", "entry_border", "badge_border",
        ]
        for name in theme_manager.list_theme_names():
            theme = theme_manager.get_theme(name)
            for key in required_keys:
                self.assertIn(key, theme, f"Theme '{name}' missing token '{key}'")
                val = theme[key]
                if key not in ("name", "description"):
                    self.assertTrue(val.startswith("#"), f"Theme token {key} in {name} is not hex: {val}")
                    self.assertIn(len(val), (4, 7), f"Hex length invalid for {key} in {name}: {val}")

    def test_default_fallback_theme(self):
        """Unknown theme names safely fall back to Cyber Blue Team."""
        fallback = theme_manager.get_theme("NonExistentTheme")
        self.assertEqual(fallback["name"], "Cyber Blue Team")


class TestEncryptedDatabase(unittest.TestCase):
    """Tests for the local encrypted SQLite3 database manager."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test_monitor.db")
        self.key_path = os.path.join(self.test_dir, ".test_key.dpapi")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_dpapi_or_fallback_key_generation(self):
        """Test encryption key derivation and storage."""
        db_mgr = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        self.assertTrue(os.path.exists(self.key_path))
        self.assertIsNotNone(db_mgr._fernet)

        # Reloading existing key should not raise error and decrypt identical payload
        db_mgr2 = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        payload = {"secret": "confidential_registry_key_1234"}
        ciphertext = db_mgr.encrypt_payload(payload)
        decrypted = db_mgr2.decrypt_payload(ciphertext)
        self.assertEqual(decrypted, payload)

    def test_encrypt_decrypt_cycle(self):
        """Test encryption and decryption fidelity for strings and dicts."""
        db_mgr = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        sample_dict = {
            "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "name": "MalwareStartup",
            "value": "powershell.exe -enc AAAA==",
            "suspicious": True,
        }
        ciphertext = db_mgr.encrypt_payload(sample_dict)
        self.assertIsInstance(ciphertext, bytes)
        self.assertNotIn(b"powershell", ciphertext)  # Raw plain text must not be in ciphertext

        decrypted = db_mgr.decrypt_payload(ciphertext)
        self.assertEqual(decrypted, sample_dict)

    def test_store_and_retrieve_events(self):
        """Test inserting encrypted change events and querying them back."""
        db_mgr = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        event = {
            "event_id": "test-uuid-12345",
            "timestamp": "2026-10-21T21:00:00Z",
            "change_type": "ADDED",
            "severity": "suspicious",
            "full_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "BackdoorCmd",
            "current_value": "cmd.exe /c start.bat",
            "previous_value": None,
            "category": "Startup - Local Machine",
            "view": "64bit",
            "reason": "Suspicious pattern: cmd.exe /c",
            "resolved_file": {
                "command_info": {"executable_path": "C:\\Windows\\System32\\cmd.exe"},
                "file_metadata": {"exists": True, "sha256": "abc123hash"},
            },
        }

        saved = db_mgr.save_event(event)
        self.assertTrue(saved)

        # Retrieve events
        events = db_mgr.get_events(limit=10)
        self.assertEqual(len(events), 1)
        retrieved = events[0]
        self.assertEqual(retrieved["event_id"], "test-uuid-12345")
        self.assertEqual(retrieved["value_name"], "BackdoorCmd")
        self.assertEqual(retrieved["current_value"], "cmd.exe /c start.bat")
        self.assertEqual(retrieved["severity"], "suspicious")

    def test_store_and_retrieve_baseline(self):
        """Test storing encrypted baseline and retrieving the latest snapshot."""
        db_mgr = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        baseline_data = {
            "metadata": {
                "created_at": "2026-10-21T20:00:00Z",
                "total_keys_scanned": 15,
                "total_values_captured": 45,
                "integrity_sha256": "testintegrityhash",
            },
            "scan_results": [
                {"full_path": "HKCU\\Run", "values": [{"name": "App1", "data": "C:\\App1.exe"}]}
            ],
        }

        saved = db_mgr.save_baseline(baseline_data)
        self.assertTrue(saved)

        latest = db_mgr.load_latest_baseline()
        self.assertIsNotNone(latest)
        self.assertEqual(latest["metadata"]["total_values_captured"], 45)
        self.assertEqual(len(latest["scan_results"]), 1)

    def test_database_stats_and_vacuum(self):
        """Test database statistics reporting and VACUUM operation."""
        db_mgr = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        stats = db_mgr.get_db_stats()
        self.assertEqual(stats["total_events"], 0)
        self.assertEqual(stats["total_baselines"], 0)
        self.assertTrue(stats["is_encrypted"])
        self.assertIn("AES-256", stats["encryption_algorithm"])

        # Vacuum test
        vacuum_result = db_mgr.vacuum_db()
        self.assertTrue(vacuum_result)

    def test_save_and_get_settings(self):
        """Test encrypted and unencrypted settings persistence."""
        db_mgr = database.EncryptedDatabaseManager(self.db_path, key_path=self.key_path)
        db_mgr.save_setting("theme", "Obsidian Stealth", encrypt=False)
        self.assertEqual(db_mgr.get_setting("theme"), "Obsidian Stealth")

        db_mgr.save_setting("secret_token", "super_secret_token_value", encrypt=True)
        self.assertEqual(db_mgr.get_setting("secret_token", is_encrypted=True), "super_secret_token_value")


class TestAutostart(unittest.TestCase):
    """Tests for the Windows autostart utility."""

    def test_mock_autostart_registry_enable_disable(self):
        """Mock winreg calls for autostart registration and query."""
        with patch("autostart.winreg.OpenKey") as mock_open:
            mock_key = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_key

            # Query enabled
            with patch("autostart.winreg.QueryValueEx", return_value=('"C:\\app.exe" --minimized', 1)):
                self.assertTrue(autostart.is_autostart_enabled())
                self.assertEqual(autostart.get_autostart_command(), '"C:\\app.exe" --minimized')

            # Query disabled
            with patch("autostart.winreg.QueryValueEx", side_effect=FileNotFoundError):
                self.assertFalse(autostart.is_autostart_enabled())
                self.assertIsNone(autostart.get_autostart_command())

            # Test set_autostart enable
            with patch("autostart.winreg.SetValueEx") as mock_set:
                result = autostart.set_autostart(True, target_path="C:\\MyTool\\app.exe", start_minimized=True)
                self.assertTrue(result)
                mock_set.assert_called_once()
                args, _ = mock_set.call_args
                self.assertIn('"C:\\MyTool\\app.exe" --minimized', args)

            # Test set_autostart disable
            with patch("autostart.winreg.DeleteValue") as mock_del:
                result = autostart.set_autostart(False)
                self.assertTrue(result)
                mock_del.assert_called_once()


class TestSettingsWindow(unittest.TestCase):
    """Tests for AppSettingsWindow UI and callbacks."""

    @classmethod
    def setUpClass(cls):
        import gc
        gc.collect()
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()
        except Exception:
            cls.root = tk._default_root

    @classmethod
    def tearDownClass(cls):
        try:
            if hasattr(cls, "root") and cls.root:
                cls.root.destroy()
        except Exception:
            pass

    def test_settings_window_open_and_save(self):
        """Verify AppSettingsWindow initializes, reflects config, and invokes on_settings_applied callback."""
        mock_parent = MagicMock()
        mock_parent.root = self.root
        mock_parent.app_dir = tempfile.gettempdir()
        mock_parent.config = {
            "polling_interval_seconds": 10,
            "appearance": {"theme": "Matrix Terminal"},
            "registry_views": {"scan_64bit": True, "scan_32bit": False},
            "file_checks": {"resolve_paths": True, "compute_sha256": True, "check_file_exists": True},
            "alert_settings": {"popup_enabled": True, "popup_severity_threshold": "suspicious", "popup_rate_limit_seconds": 3, "mute_popups": False},
            "startup": {"start_minimized": True},
        }
        mock_parent.db = MagicMock()
        mock_parent.db.get_db_stats.return_value = {
            "total_events": 4, "total_baselines": 1, "size_bytes": 1024, "is_encrypted": True, "encryption_algorithm": "AES-256"
        }

        saved_config = {}

        def on_applied(new_cfg):
            saved_config.update(new_cfg)

        with patch("settings_window.messagebox.showinfo"):
            win = AppSettingsWindow(
                parent_app=mock_parent,
                on_settings_applied=on_applied
            )
            self.assertIsNotNone(win)
            self.assertEqual(win.var_theme.get(), "Matrix Terminal")
            self.assertEqual(win.var_polling.get(), 10)

            # Modify values
            win.var_theme.set("Obsidian Stealth")
            win.var_polling.set(2)
            win.var_scan_32.set(True)

            # Trigger save
            win._save_and_apply()

            self.assertEqual(saved_config.get("appearance", {}).get("theme"), "Obsidian Stealth")
            self.assertEqual(saved_config.get("polling_interval_seconds"), 2)
            self.assertTrue(saved_config.get("registry_views", {}).get("scan_32bit"))
            try:
                win.destroy()
            except Exception:
                pass


class TestMainAppIntegration(unittest.TestCase):
    """Tests verifying main application integration with database, themes, and settings."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        try:
            if tk._default_root is not None and tk._default_root.winfo_exists():
                tk._default_root.destroy()
        except Exception:
            pass
        self.app = RegistryMonitorApp()
        self.app.root.withdraw()

    def tearDown(self):
        if self.app.monitoring_thread and self.app.monitoring_thread.is_alive():
            self.app.monitoring_thread.stop()
        try:
            self.app._force_close()
        except Exception:
            pass
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_apply_theme_switches_palette(self):
        """Verify dynamic theme switching changes active palette and widget styles."""
        self.app.apply_theme("Nordic Frost")
        self.assertEqual(self.app.theme["name"], "Nordic Frost")
        self.assertEqual(self.app.current_theme_name, "Nordic Frost")

        # Switch to Obsidian Stealth
        self.app.apply_theme("Obsidian Stealth")
        self.assertEqual(self.app.theme["name"], "Obsidian Stealth")
        self.assertEqual(self.app.current_theme_name, "Obsidian Stealth")

    def test_on_settings_applied_updates_engine(self):
        """Verify updating settings live propagates interval, theme, and badges."""
        new_settings = {
            "polling_interval_seconds": 30,
            "appearance": {"theme": "Crimson Alert"},
            "registry_views": {"scan_64bit": True, "scan_32bit": True},
            "file_checks": {"resolve_paths": True, "compute_sha256": True},
            "alert_settings": {"popup_enabled": True, "popup_severity_threshold": "investigation_required"},
            "startup": {"start_minimized": True},
        }

        self.app._on_settings_applied(new_settings)
        self.assertEqual(self.app.config["polling_interval_seconds"], 30)
        self.assertEqual(self.app.theme["name"], "Crimson Alert")
        self.assertIn("30s", self.app.header_polling_badge.cget("text"))

    def test_database_persistence_on_new_event(self):
        """Verify incoming events are encrypted and saved to SQLite."""
        self.app.mute_var.set(True)
        now_ts = datetime.now(timezone.utc).isoformat()
        event = {
            "event_id": "test-int-evt-999",
            "timestamp": now_ts,
            "change_type": "ADDED",
            "severity": "informational",
            "full_path": "HKCU\\Software\\TestRun",
            "value_name": "TestVal",
            "current_value": "calc.exe",
            "previous_value": None,
            "category": "Startup - Current User",
            "view": "64bit",
            "reason": "Test",
        }
        self.app._process_new_events([event])

        # Verify event in in-memory list
        self.assertTrue(any(e.get("event_id") == "test-int-evt-999" for e in self.app.events))

        # Verify event stored in encrypted database
        db_events = self.app.db.get_events(limit=50)
        found = any(e.get("event_id") == "test-int-evt-999" for e in db_events)
        self.assertTrue(found, "Event was not persisted into encrypted SQLite database")


if __name__ == "__main__":
    unittest.main(verbosity=2)
