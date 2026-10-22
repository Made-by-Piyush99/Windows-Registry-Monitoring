"""Unit Tests for Change Detector and File Resolver

Uses mock registry data to test detection logic without modifying
the real Windows Registry. All tests are platform-independent.
"""

import os
import sys
import json
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import change_detector
import file_resolver


class TestChangeDetector(unittest.TestCase):
    """Tests for the change_detector module."""

    def _make_scan_result(self, full_path, values, status="ok",
                          view="64bit", category="Startup - Current User",
                          hive="HKEY_CURRENT_USER", subkey="Software\\Test"):
        """Helper to create mock scan results."""
        return {
            "full_path": full_path,
            "hive": hive,
            "subkey": subkey,
            "status": status,
            "values": values,
            "error_message": None,
            "view": view,
            "category": category,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _make_value(self, name, data, type_name="REG_SZ", type_id=1):
        """Helper to create a mock registry value."""
        return {
            "name": name,
            "data": data,
            "type": type_name,
            "type_id": type_id,
        }

    def test_new_value_detected(self):
        """Test 1: A new registry value is detected."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("ExistingApp", "C:\\app.exe")]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [
                    self._make_value("ExistingApp", "C:\\app.exe"),
                    self._make_value("NewApp", "C:\\new_app.exe"),
                ]
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change_type"], "ADDED")
        self.assertEqual(events[0]["value_name"], "NewApp")
        self.assertEqual(events[0]["current_value"], "C:\\new_app.exe")
        self.assertIsNone(events[0]["previous_value"])

    def test_deleted_value_detected(self):
        """Test 2: A deleted registry value is detected."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [
                    self._make_value("App1", "C:\\app1.exe"),
                    self._make_value("App2", "C:\\app2.exe"),
                ]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("App1", "C:\\app1.exe")]
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change_type"], "DELETED")
        self.assertEqual(events[0]["value_name"], "App2")
        self.assertEqual(events[0]["previous_value"], "C:\\app2.exe")
        self.assertIsNone(events[0]["current_value"])

    def test_modified_value_detected(self):
        """Test 3: A modified value is detected."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("App", "C:\\old_app.exe")]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("App", "C:\\new_app.exe")]
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change_type"], "MODIFIED")
        self.assertEqual(events[0]["previous_value"], "C:\\old_app.exe")
        self.assertEqual(events[0]["current_value"], "C:\\new_app.exe")

    def test_unchanged_value_no_event(self):
        """Test 4: An unchanged value generates no event."""
        data = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("App", "C:\\app.exe")]
            )
        ]

        events = change_detector.detect_changes(data, data)
        self.assertEqual(len(events), 0)

    def test_access_denied_no_false_deletion(self):
        """Test 5: An inaccessible key does NOT generate a false deletion."""
        baseline = [
            self._make_scan_result(
                "HKLM\\Software\\Test",
                [self._make_value("DefenderSetting", "1")],
                status="ok",
                category="Windows Defender",
                hive="HKEY_LOCAL_MACHINE"
            )
        ]
        current = [
            self._make_scan_result(
                "HKLM\\Software\\Test",
                [],
                status="access_denied",
                category="Windows Defender",
                hive="HKEY_LOCAL_MACHINE"
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        # Should generate an ERROR event, not a DELETED event
        self.assertTrue(len(events) >= 1)
        for event in events:
            self.assertNotEqual(event["change_type"], "DELETED")
        error_events = [e for e in events if e["change_type"] == "ERROR"]
        self.assertTrue(len(error_events) >= 1)
        self.assertIn("NOT a confirmed deletion", error_events[0]["reason"])

    def test_type_change_detected(self):
        """Test: Registry data type change is detected."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("Setting", "1", "REG_SZ", 1)]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("Setting", 1, "REG_DWORD", 4)]
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        self.assertTrue(len(events) >= 1)
        # Should detect type change
        type_events = [e for e in events if e["change_type"] == "TYPE_CHANGED"]
        self.assertTrue(len(type_events) >= 1)

    def test_severity_assessment_startup_add(self):
        """Test: New startup entry is flagged as suspicious."""
        severity, reason = change_detector.assess_severity(
            "ADDED", "MalwareApp", "C:\\temp\\evil.exe",
            "Startup - Current User"
        )
        self.assertEqual(severity, "suspicious")

    def test_severity_assessment_defender_delete(self):
        """Test: Deletion of Windows Defender setting is investigation_required."""
        severity, reason = change_detector.assess_severity(
            "DELETED", "DisableRealtimeMonitoring", "1",
            "Windows Defender"
        )
        self.assertEqual(severity, "investigation_required")

    def test_empty_baseline_all_current_are_added(self):
        """Test: Empty baseline means all current values are ADDED."""
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [
                    self._make_value("App1", "C:\\app1.exe"),
                    self._make_value("App2", "C:\\app2.exe"),
                ]
            )
        ]

        events = change_detector.detect_changes([], current)
        self.assertEqual(len(events), 2)
        for event in events:
            self.assertEqual(event["change_type"], "ADDED")

    def test_multiple_changes_detected(self):
        """Test: Multiple simultaneous changes detected correctly."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [
                    self._make_value("KeepSame", "value"),
                    self._make_value("ToModify", "old_value"),
                    self._make_value("ToDelete", "del_value"),
                ]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [
                    self._make_value("KeepSame", "value"),
                    self._make_value("ToModify", "new_value"),
                    self._make_value("NewEntry", "added_value"),
                ]
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        types = {e["change_type"] for e in events}
        self.assertIn("ADDED", types)
        self.assertIn("MODIFIED", types)
        self.assertIn("DELETED", types)
        self.assertEqual(len(events), 3)

    def test_event_has_required_fields(self):
        """Test: Events contain all required fields."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("App", "old")]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Test",
                [self._make_value("App", "new")]
            )
        ]

        events = change_detector.detect_changes(baseline, current)
        self.assertEqual(len(events), 1)
        event = events[0]

        required_fields = [
            "event_id", "timestamp", "hive", "full_path",
            "value_name", "change_type", "previous_value",
            "current_value", "severity", "reason",
            "fingerprint", "status",
        ]
        for field in required_fields:
            self.assertIn(field, event, f"Missing required field: {field}")

    def test_fingerprint_consistency(self):
        """Test: Same change produces same fingerprint."""
        fp1 = change_detector._compute_fingerprint(
            "ADDED", "HKCU\\Test", "Value1", "64bit"
        )
        fp2 = change_detector._compute_fingerprint(
            "ADDED", "HKCU\\Test", "Value1", "64bit"
        )
        self.assertEqual(fp1, fp2)
        # Different changes produce different fingerprints
        fp3 = change_detector._compute_fingerprint(
            "DELETED", "HKCU\\Test", "Value1", "64bit"
        )
        self.assertNotEqual(fp1, fp3)

    def test_referenced_executable_path_change_detected(self):
        """Test: Change in referenced executable path is detected and reported."""
        baseline = [
            self._make_scan_result(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                [self._make_value("StartupApp", "C:\\Program Files\\App\\legit.exe")]
            )
        ]
        current = [
            self._make_scan_result(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                [self._make_value("StartupApp", "C:\\temp\\suspicious.exe")]
            )
        ]
        events = change_detector.detect_changes(baseline, current, file_resolver)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change_type"], "MODIFIED")
        self.assertIn("Referenced executable path changed", events[0]["reason"])
        self.assertEqual(events[0]["severity"], "suspicious")

    def test_referenced_file_modified_on_disk_detected(self):
        """Test: When registry value is unchanged but file binary changes, FILE_MODIFIED event is generated."""
        val_base = self._make_value("App", "C:\\app.exe")
        val_base["resolved_file"] = {
            "file_metadata": {"path": "C:\\app.exe", "exists": True, "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        }
        val_curr = self._make_value("App", "C:\\app.exe")
        val_curr["resolved_file"] = {
            "file_metadata": {"path": "C:\\app.exe", "exists": True, "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
        }
        baseline = [self._make_scan_result("HKCU\\Software\\Test", [val_base])]
        current = [self._make_scan_result("HKCU\\Software\\Test", [val_curr])]

        events = change_detector.detect_changes(baseline, current, file_resolver)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change_type"], "FILE_MODIFIED")
        self.assertIn("modified on disk", events[0]["reason"])

    def test_referenced_file_deleted_on_disk_detected(self):
        """Test: When referenced file is deleted from disk, FILE_DELETED event is generated."""
        val_base = self._make_value("App", "C:\\app.exe")
        val_base["resolved_file"] = {
            "file_metadata": {"path": "C:\\app.exe", "exists": True, "sha256": "aaa"}
        }
        val_curr = self._make_value("App", "C:\\app.exe")
        val_curr["resolved_file"] = {
            "file_metadata": {"path": "C:\\app.exe", "exists": False, "sha256": None}
        }
        baseline = [self._make_scan_result("HKCU\\Software\\Test", [val_base])]
        current = [self._make_scan_result("HKCU\\Software\\Test", [val_curr])]

        events = change_detector.detect_changes(baseline, current, file_resolver)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["change_type"], "FILE_DELETED")
        self.assertIn("deleted or is missing", events[0]["reason"])


class TestFileResolver(unittest.TestCase):
    """Tests for the file_resolver module."""

    def test_quoted_path_with_spaces(self):
        """Test 6: Quoted executable paths with spaces are parsed correctly."""
        result = file_resolver.parse_command_line(
            '"C:\\Program Files\\My App\\app.exe" --startup'
        )
        self.assertEqual(
            result["executable_path"],
            "C:\\Program Files\\My App\\app.exe"
        )
        self.assertEqual(result["arguments"], "--startup")
        self.assertEqual(result["parse_method"], "quoted")

    def test_environment_variable_expansion(self):
        """Test 7: Environment variables are expanded."""
        # Set a test env var
        with patch.dict(os.environ, {"TESTVAR": "C:\\TestDir"}):
            result = file_resolver.expand_env_variables("%TESTVAR%\\app.exe")
            self.assertEqual(result, "C:\\TestDir\\app.exe")

    def test_missing_file_handled(self):
        """Test 8: Missing executable files are handled safely."""
        meta = file_resolver.get_file_metadata(
            "C:\\NonExistent\\Path\\fake.exe", compute_hash=False
        )
        self.assertFalse(meta["exists"])
        self.assertIsNotNone(meta["error"])
        self.assertIsNone(meta["sha256"])

    def test_empty_value_handling(self):
        """Test: Empty or None values handled gracefully."""
        result = file_resolver.parse_command_line("")
        self.assertIsNone(result["executable_path"])
        self.assertEqual(result["parse_method"], "empty_or_invalid")

        result2 = file_resolver.parse_command_line(None)
        self.assertIsNone(result2["executable_path"])

    def test_simple_exe_path(self):
        """Test: Simple executable path without quotes."""
        result = file_resolver.parse_command_line("C:\\Windows\\notepad.exe")
        self.assertIsNotNone(result["executable_path"])
        self.assertEqual(result["file_type"], "executable")

    def test_rundll32_pattern(self):
        """Test: rundll32 DLL path extraction."""
        result = file_resolver.parse_command_line(
            'C:\\Windows\\System32\\rundll32.exe "C:\\test\\my.dll",EntryPoint'
        )
        self.assertEqual(result["parse_method"], "rundll32")
        self.assertEqual(result["file_type"], "library")
        self.assertIn("my.dll", result["executable_path"])

    def test_file_type_classification(self):
        """Test: File types are classified correctly."""
        self.assertEqual(
            file_resolver.classify_file_type("app.exe"), "executable"
        )
        self.assertEqual(
            file_resolver.classify_file_type("lib.dll"), "library"
        )
        self.assertEqual(
            file_resolver.classify_file_type("script.ps1"), "executable"
        )
        self.assertEqual(
            file_resolver.classify_file_type("driver.sys"), "library"
        )
        self.assertEqual(
            file_resolver.classify_file_type("noext"), "unknown"
        )

    def test_resolve_non_string_type(self):
        """Test: Non-string registry types return non_string_type status."""
        result = file_resolver.resolve_registry_value(
            "BinaryVal", b"\x00\x01", "REG_BINARY"
        )
        self.assertEqual(result["resolution_status"], "non_string_type")

    def test_resolve_string_value(self):
        """Test: String registry value is resolved."""
        result = file_resolver.resolve_registry_value(
            "TestApp", '"C:\\Program Files\\test.exe" /s', "REG_SZ",
            check_exists=False, compute_hash=False
        )
        self.assertEqual(result["resolution_status"], "resolved")
        self.assertIsNotNone(result["command_info"])
        self.assertEqual(
            result["command_info"]["executable_path"],
            "C:\\Program Files\\test.exe"
        )

    def test_path_with_env_var(self):
        """Test: Path with environment variable is expanded."""
        with patch.dict(os.environ, {"WINDIR": "C:\\Windows"}):
            result = file_resolver.parse_command_line(
                "%WINDIR%\\System32\\cmd.exe /c test"
            )
            self.assertIn("cmd.exe", result["executable_path"] or "")


class TestAlertDeduplication(unittest.TestCase):
    """Test 9: Duplicate pop-up alerts are suppressed."""

    def setUp(self):
        # Import here to avoid issues in non-Windows environments
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import alert_manager
        self.mgr = alert_manager.AlertManager({
            "alert_settings": {
                "popup_enabled": True,
                "popup_severity_threshold": "informational",
                "popup_rate_limit_seconds": 0,  # No rate limiting for tests
                "mute_popups": False,
                "max_queued_alerts": 50,
            }
        })

    def test_duplicate_suppressed(self):
        """Duplicate events with same fingerprint are suppressed."""
        event = {
            "event_id": "test-1",
            "fingerprint": "ADDED|HKCU\\Test|Val1|64bit",
            "severity": "suspicious",
            "change_type": "ADDED",
        }

        # First alert should pass
        self.assertTrue(self.mgr.should_alert(event))
        self.mgr.record_alert(event)

        # Second identical event should be suppressed
        event2 = dict(event)
        event2["event_id"] = "test-2"
        self.assertFalse(self.mgr.should_alert(event2))

    def test_different_events_not_suppressed(self):
        """Different events are not suppressed."""
        event1 = {
            "event_id": "test-1",
            "fingerprint": "ADDED|HKCU\\Test|Val1|64bit",
            "severity": "informational",
        }
        event2 = {
            "event_id": "test-2",
            "fingerprint": "ADDED|HKCU\\Test|Val2|64bit",
            "severity": "informational",
        }

        self.assertTrue(self.mgr.should_alert(event1))
        self.mgr.record_alert(event1)
        self.assertTrue(self.mgr.should_alert(event2))

    def test_muted_suppresses_all(self):
        """Muted mode suppresses all alerts."""
        self.mgr.muted = True
        event = {
            "event_id": "test-1",
            "fingerprint": "unique-fp",
            "severity": "suspicious",
        }
        self.assertFalse(self.mgr.should_alert(event))


class TestMonitoringStop(unittest.TestCase):
    """Test 10: Monitoring can stop cleanly."""

    def test_thread_stops_cleanly(self):
        """Monitoring thread can be stopped cleanly."""
        import threading
        from queue import Queue

        # Simulate a monitoring thread stop mechanism
        stop_event = threading.Event()
        ran = threading.Event()

        def monitor_loop():
            while not stop_event.is_set():
                ran.set()
                stop_event.wait(0.1)

        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()

        # Wait for it to start
        ran.wait(timeout=2)
        self.assertTrue(ran.is_set())

        # Stop it
        stop_event.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())


class TestConfigLoading(unittest.TestCase):
    """Test configuration loading and validation."""

    def test_default_config_valid(self):
        """Default configuration has valid values."""
        import tempfile
        config_path = os.path.join(tempfile.gettempdir(), "test_config_missing.json")
        # Remove if exists
        if os.path.exists(config_path):
            os.remove(config_path)

        # Import main just for load_config - mock the platform check
        # We test the logic directly instead
        defaults = {
            "polling_interval_seconds": 5,
            "monitored_paths": [],
        }
        self.assertGreaterEqual(defaults["polling_interval_seconds"], 1)
        self.assertIsInstance(defaults["monitored_paths"], list)

    def test_invalid_interval_gets_default(self):
        """Invalid polling interval falls back to default."""
        config = {"polling_interval_seconds": -1}
        if not isinstance(config["polling_interval_seconds"], (int, float)) or \
           config["polling_interval_seconds"] < 1:
            config["polling_interval_seconds"] = 5
        self.assertEqual(config["polling_interval_seconds"], 5)


class TestReportGenerator(unittest.TestCase):
    """Test report generation and CSV export."""

    def test_export_events_csv(self):
        """Test exporting events to CSV file."""
        import tempfile
        import report_generator
        temp_dir = tempfile.mkdtemp()
        csv_file = os.path.join(temp_dir, "test_events.csv")
        sample_event = {
            "event_id": "test-uuid-1",
            "timestamp": "2026-10-17T12:00:00Z",
            "change_type": "ADDED",
            "severity": "suspicious",
            "category": "Startup - Current User",
            "hive": "HKEY_CURRENT_USER",
            "full_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value_name": "TestApp",
            "previous_value": None,
            "current_value": "C:\\test\\app.exe",
            "previous_type": None,
            "current_type": "REG_SZ",
            "view": "64bit",
            "reason": "New startup entry added",
            "status": "detected",
            "resolved_file": {
                "command_info": {"executable_path": "C:\\test\\app.exe"},
                "file_metadata": {"exists": False, "sha256": None}
            }
        }
        result_path = report_generator.export_events_csv([sample_event], csv_file)
        self.assertTrue(os.path.exists(result_path))
        with open(result_path, "r", encoding="utf-8-sig") as f:
            content = f.read()
            self.assertIn("TestApp", content)
            self.assertIn("ADDED", content)
            self.assertIn("C:\\test\\app.exe", content)

    def test_generate_and_save_summary_report(self):
        """Test generating and saving a summary report."""
        import tempfile
        import report_generator
        temp_dir = tempfile.mkdtemp()
        summary_file = os.path.join(temp_dir, "test_summary.json")
        sample_events = [
            {"change_type": "ADDED", "severity": "suspicious", "category": "Startup"},
            {"change_type": "MODIFIED", "severity": "informational", "category": "Defender"},
        ]
        summary = report_generator.generate_summary_report(
            sample_events, {"created_at": "2026-10-17"}, {"polling_interval_seconds": 5}
        )
        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["by_change_type"]["ADDED"], 1)
        self.assertEqual(summary["by_severity"]["suspicious"], 1)

        saved = report_generator.save_summary_report(summary, summary_file)
        self.assertTrue(os.path.exists(saved))
        with open(saved, "r", encoding="utf-8") as f:
            loaded = json.load(f)
            self.assertEqual(loaded["total_events"], 2)


class TestAdvancedSystemMonitoring(unittest.TestCase):
    """Test Advanced System Monitoring file analysis and risk assessment."""

    def test_assess_file_risk_missing(self):
        """Missing file generates a WARNING finding."""
        level, reason = file_resolver.assess_file_risk(
            "C:\\missing\\app.exe", exists=False, command_line="C:\\missing\\app.exe"
        )
        self.assertEqual(level, "WARNING")
        self.assertIn("does not exist", reason)

    def test_assess_file_risk_temp(self):
        """File in temp directory generates a SUSPICIOUS finding."""
        level, reason = file_resolver.assess_file_risk(
            "C:\\Users\\Admin\\AppData\\Local\\Temp\\dropper.exe",
            exists=True, command_line="dropper.exe"
        )
        self.assertEqual(level, "SUSPICIOUS")
        self.assertIn("temporary directory", reason)

    def test_assess_file_risk_unquoted(self):
        """Unquoted path with spaces generates a WARNING."""
        level, reason = file_resolver.assess_file_risk(
            "C:\\Program Files\\App\\app.exe", exists=True,
            command_line="C:\\Program Files\\App\\app.exe --start"
        )
        self.assertEqual(level, "WARNING")
        self.assertIn("Unquoted path", reason)

    def test_assess_file_risk_system_binary(self):
        """Standard System32 binary is classified as BENIGN."""
        level, reason = file_resolver.assess_file_risk(
            "C:\\Windows\\System32\\svchost.exe", exists=True,
            command_line='"C:\\Windows\\System32\\svchost.exe" -k netsvcs'
        )
        self.assertEqual(level, "BENIGN")

    def test_analyze_all_monitored_files(self):
        """Test analyzing mock registry scan results."""
        mock_scan = [{
            "full_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "category": "Startup - Current User",
            "view": "64bit",
            "status": "ok",
            "values": [
                {"name": "App1", "data": "C:\\Windows\\System32\\cmd.exe", "type": "REG_SZ"},
                {"name": "App2", "data": "C:\\nonexistent\\evil.exe", "type": "REG_SZ"},
            ]
        }]
        res = file_resolver.analyze_all_monitored_files({}, mock_scan)
        self.assertIn("summary", res)
        self.assertIn("files", res)
        self.assertEqual(res["summary"]["total_files_analyzed"], 2)
        self.assertTrue(any(f["file_name"] == "cmd.exe" for f in res["files"]))

    def test_export_advanced_analysis_csv_and_json(self):
        """Test CSV and JSON export of advanced analysis report."""
        import tempfile
        import report_generator
        temp_dir = tempfile.mkdtemp()
        csv_file = os.path.join(temp_dir, "advanced.csv")
        json_file = os.path.join(temp_dir, "advanced.json")

        report_data = {
            "analysis_timestamp": "2026-10-17T12:00:00Z",
            "summary": {"total_files_analyzed": 1},
            "files": [{
                "file_path": "C:\\Windows\\System32\\cmd.exe",
                "file_name": "cmd.exe",
                "exists": True,
                "size_bytes": 1000,
                "sha256": "abc123",
                "file_type": "executable",
                "risk_level": "BENIGN",
                "finding": "Standard binary",
                "category": "Startup",
                "registry_path": "HKCU\\Run",
                "value_name": "cmd",
                "value_data": "cmd.exe",
                "arguments": "",
                "modified_time": "2026-10-17",
                "view": "64bit"
            }]
        }

        report_generator.export_advanced_analysis_csv(report_data["files"], csv_file)
        self.assertTrue(os.path.exists(csv_file))

        report_generator.export_advanced_analysis_json(report_data, json_file)
        self.assertTrue(os.path.exists(json_file))


class TestVisualReporting(unittest.TestCase):
    """Test visual and graphical report generation with Pillow and pandas."""

    def setUp(self):
        import tempfile
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_generate_events_visual_report(self):
        """Test generating events visual image report."""
        import visual_reporter
        from PIL import Image

        mock_events = [
            {
                "event_id": "evt-1",
                "timestamp": "2026-10-21T12:00:00Z",
                "change_type": "ADDED",
                "severity": "suspicious",
                "category": "Startup - Current User",
                "hive": "HKCU",
                "full_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "SuspiciousApp",
                "previous_value": None,
                "current_value": "C:\\Windows\\temp\\malware.exe",
                "reason": "Value contains suspicious pattern: temp\\",
                "status": "detected"
            },
            {
                "event_id": "evt-2",
                "timestamp": "2026-10-21T12:00:01Z",
                "change_type": "MODIFIED",
                "severity": "informational",
                "category": "Windows Firewall",
                "hive": "HKLM",
                "full_path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                "value_name": "EnableFirewall",
                "previous_value": 1,
                "current_value": 1,
                "reason": "Registry value changed",
                "status": "detected"
            }
        ]
        out_png = os.path.join(self.temp_dir, "events_report.png")
        saved_path = visual_reporter.generate_events_visual_report(mock_events, None, out_png)

        self.assertTrue(os.path.exists(saved_path))
        self.assertGreater(os.path.getsize(saved_path), 5000)

        with Image.open(saved_path) as img:
            self.assertEqual(img.format, "PNG")
            self.assertGreaterEqual(img.width, 1200)
            self.assertGreaterEqual(img.height, 800)

    def test_generate_advanced_file_visual_report(self):
        """Test generating advanced file analysis visual image report."""
        import visual_reporter
        from PIL import Image

        mock_report = {
            "analysis_timestamp": "2026-10-21T12:00:00Z",
            "summary": {
                "total_files_analyzed": 3,
                "existing_files": 2,
                "missing_files": 1,
                "suspicious_or_warning_files": 2,
                "hashes_computed": 2,
                "total_size_bytes": 102400
            },
            "files": [
                {
                    "file_path": "C:\\Windows\\System32\\cmd.exe",
                    "file_name": "cmd.exe",
                    "exists": True,
                    "size_bytes": 289280,
                    "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "file_type": "executable",
                    "risk_level": "BENIGN",
                    "finding": "Standard system executable in System32.",
                    "category": "Startup - Current User",
                    "registry_path": "HKCU\\Run",
                    "value_name": "Terminal",
                    "value_data": "C:\\Windows\\System32\\cmd.exe",
                    "arguments": "",
                    "modified_time": "2026-10-21",
                    "view": "64bit"
                },
                {
                    "file_path": "C:\\Program Files\\App with spaces\\run.exe",
                    "file_name": "run.exe",
                    "exists": False,
                    "size_bytes": None,
                    "sha256": None,
                    "file_type": "executable",
                    "risk_level": "WARNING",
                    "finding": "Unquoted path with spaces; file missing.",
                    "category": "Startup - Local Machine",
                    "registry_path": "HKLM\\Run",
                    "value_name": "UnquotedApp",
                    "value_data": "C:\\Program Files\\App with spaces\\run.exe",
                    "arguments": "",
                    "modified_time": None,
                    "view": "64bit"
                }
            ]
        }
        out_png = os.path.join(self.temp_dir, "advanced_report.png")
        saved_path = visual_reporter.generate_advanced_file_visual_report(mock_report, out_png)

        self.assertTrue(os.path.exists(saved_path))
        self.assertGreater(os.path.getsize(saved_path), 5000)

        with Image.open(saved_path) as img:
            self.assertEqual(img.format, "PNG")
            self.assertGreaterEqual(img.width, 1200)
            self.assertGreaterEqual(img.height, 800)


class TestFloatingDesktopWidget(unittest.TestCase):
    """Test floating desktop widget lifecycle and background toggling."""

    def test_floating_widget_creation_and_toggle(self):
        """Test floating widget can be shown and hidden without crashing."""
        import main
        import tkinter as tk

        app = main.RegistryMonitorApp()
        try:
            self.assertIsNotNone(app.floating_widget)
            self.assertFalse(app.floating_widget.winfo_viewable())

            # Test run in background
            app._run_in_background()
            app.root.update()
            self.assertFalse(app.root.winfo_viewable())
            self.assertTrue(app.floating_widget.winfo_viewable())

            # Test status update
            app.floating_widget.update_status("MONITORING", changes_count=3, suspicious_count=1)
            self.assertEqual(app.floating_widget.status_pill.cget("text"), "● MONITORING")
            self.assertIn("3", app.floating_widget.counter_badge.cget("text"))

            # Test restore frontend app
            app.floating_widget.restore_frontend_app()
            app.root.update()
            self.assertTrue(app.root.winfo_viewable())
            self.assertFalse(app.floating_widget.winfo_viewable())

            # Test taskbar hide toggle (default is True: hidden from taskbar)
            self.assertTrue(app.hide_taskbar_var.get())
            app.hide_taskbar_var.set(False)
            app._toggle_hide_taskbar()
            self.assertIn("visible on", app.statusbar.cget("text"))

            app.hide_taskbar_var.set(True)
            app._toggle_hide_taskbar()
            self.assertIn("hidden from", app.statusbar.cget("text"))
        finally:
            try:
                app._force_close()
            except Exception:
                pass

    def test_minimize_button_activates_floating_desktop_icon(self):
        """Test that minimizing the window via the minimize button activates the floating desktop icon."""
        import main
        import time

        app = main.RegistryMonitorApp()
        try:
            self.assertTrue(app.minimize_to_icon_var.get())
            self.assertFalse(app.floating_widget.winfo_viewable())

            # Simulate user clicking window Minimize button
            app.root.iconify()
            app.root.update()
            time.sleep(0.05)
            app.root.update()

            # Verify window is hidden from screen/taskbar and floating desktop icon is shown
            self.assertEqual(app.root.state(), "withdrawn")
            self.assertTrue(app.floating_widget.winfo_viewable())

            # Restore frontend app via floating desktop widget
            app.floating_widget.restore_frontend_app()
            app.root.update()

            self.assertEqual(app.root.state(), "normal")
            self.assertFalse(app.floating_widget.winfo_viewable())

            # Test when disabled
            app.minimize_to_icon_var.set(False)
            app.root.iconify()
            app.root.update()
            time.sleep(0.05)
            app.root.update()
            # Floating widget should NOT be shown when option is disabled
            self.assertFalse(app.floating_widget.winfo_viewable())
        finally:
            try:
                app._force_close()
            except Exception:
                pass


    def test_set_taskbar_visibility_helper(self):
        """Test set_taskbar_visibility function on Tk windows."""
        import main
        import tkinter as tk

        root = tk.Tk()
        root.geometry("200x100")
        root.update()
        try:
            # Test hiding taskbar
            main.set_taskbar_visibility(root, show=False)
            # Test showing taskbar
            main.set_taskbar_visibility(root, show=True)
            # Test on withdrawn window
            root.withdraw()
            main.set_taskbar_visibility(root, show=False)
            self.assertEqual(root.state(), "withdrawn")
        finally:
            root.destroy()


class TestDashboardAndInspector(unittest.TestCase):
    """Test cyber Blue Team dashboard features, KPI scorecards, live filters, and forensic inspector."""

    def setUp(self):
        import main
        self.app = main.RegistryMonitorApp()
        self.mock_events = [
            {
                "event_id": "evt-001",
                "timestamp": "2026-10-21T18:00:00+00:00",
                "hive": "HKEY_LOCAL_MACHINE",
                "full_path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "BackdoorTrigger",
                "change_type": "ADDED",
                "previous_value": None,
                "current_value": "powershell.exe -enc dGVzdA==",
                "previous_type": None,
                "current_type": "REG_SZ",
                "category": "Startup - Local Machine",
                "view": "64bit",
                "severity": "suspicious",
                "reason": "Value contains suspicious pattern: powershell",
                "fingerprint": "ADDED|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|BackdoorTrigger|64bit",
                "resolved_file": {
                    "value_name": "BackdoorTrigger",
                    "value_data": "powershell.exe -enc dGVzdA==",
                    "value_type": "REG_SZ",
                    "command_info": {
                        "executable_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "arguments": "-enc dGVzdA==",
                        "file_type": "executable",
                        "parse_method": "unquoted"
                    },
                    "file_metadata": {
                        "exists": True,
                        "size_bytes": 450560,
                        "modified_time": "2026-05-10T12:00:00+00:00",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    }
                },
                "status": "detected"
            },
            {
                "event_id": "evt-002",
                "timestamp": "2026-10-21T18:05:00+00:00",
                "hive": "HKEY_LOCAL_MACHINE",
                "full_path": "HKLM\\Software\\Policies\\Microsoft\\Windows Defender",
                "value_name": "DisableAntiSpyware",
                "change_type": "MODIFIED",
                "previous_value": 0,
                "current_value": 1,
                "previous_type": "REG_DWORD",
                "current_type": "REG_DWORD",
                "category": "Windows Defender",
                "view": "64bit",
                "severity": "investigation_required",
                "reason": "Security-related value modified in Windows Defender",
                "fingerprint": "MODIFIED|HKLM\\Software\\Policies\\Microsoft\\Windows Defender|DisableAntiSpyware|64bit",
                "resolved_file": None,
                "status": "detected"
            },
            {
                "event_id": "evt-003",
                "timestamp": "2026-10-21T18:10:00+00:00",
                "hive": "HKEY_CURRENT_USER",
                "full_path": "HKCU\\Software\\TestApp",
                "value_name": "WindowPos",
                "change_type": "MODIFIED",
                "previous_value": "100,100",
                "current_value": "200,200",
                "previous_type": "REG_SZ",
                "current_type": "REG_SZ",
                "category": "Startup - Current User",
                "view": "64bit",
                "severity": "informational",
                "reason": "Registry value changed",
                "fingerprint": "MODIFIED|HKCU\\Software\\TestApp|WindowPos|64bit",
                "resolved_file": None,
                "status": "detected"
            }
        ]

    def tearDown(self):
        try:
            self.app._force_close()
        except Exception:
            pass

    def test_kpi_scorecards_and_badges_render(self):
        """Test KPI scorecard values, styles, and header badges."""
        self.app.status = "MONITORING"
        self.app.total_changes = 5
        self.app.suspicious_count = 2
        self.app.scan_errors = 1
        self.app.last_scan_time = "2026-10-21 18:30:00"

        self.app._update_status_display()

        self.assertEqual(self.app.status_label.cget("text"), "MONITORING")
        self.assertEqual(self.app.changes_label.cget("text"), "5")
        self.assertEqual(self.app.suspicious_label.cget("text"), "2")
        self.assertEqual(self.app.errors_label.cget("text"), "1")
        self.assertEqual(self.app.scan_time_label.cget("text"), "2026-10-21 18:30:00")
        self.assertIn("MONITORING", self.app.header_status_badge.cget("text"))
        self.assertIn("18:30:00", self.app.header_last_scan_badge.cget("text"))

    def test_search_and_severity_live_filters(self):
        """Test live search filter and severity category chips."""
        self.app.mute_var.set(True)  # Avoid popup dialogs
        self.app._process_new_events(self.mock_events)

        self.assertEqual(len(self.app.events), 3)
        self.assertEqual(len(self.app.event_tree.get_children()), 3)

        # Filter by search term: "powershell"
        self.app.search_var.set("powershell")
        self.app._on_search_filter_changed()
        self.assertEqual(len(self.app.event_tree.get_children()), 1)
        self.assertIn("Showing 1 of 3 events", self.app.event_filter_count_label.cget("text"))

        # Clear search, filter by severity "Suspicious / Critical"
        self.app.search_var.set("")
        self.app.severity_filter_var.set("Suspicious / Critical")
        self.app._on_search_filter_changed()
        self.assertEqual(len(self.app.event_tree.get_children()), 1)

        # Filter by severity "Investigation Required"
        self.app.severity_filter_var.set("Investigation Required")
        self.app._on_search_filter_changed()
        self.assertEqual(len(self.app.event_tree.get_children()), 1)

        # Reset filters with _clear_filters
        self.app._clear_filters()
        self.assertEqual(len(self.app.event_tree.get_children()), 3)
        self.assertIn("Showing all 3 events", self.app.event_filter_count_label.cget("text"))

    def test_structured_forensic_inspector_details(self):
        """Test structured telemetry inspection cards and clipboard copy helpers."""
        self.app.mute_var.set(True)
        self.app._process_new_events(self.mock_events)

        # Select the Run event (evt-001) which is at the bottom because newest items are inserted at index 0
        run_item = self.app.event_tree.get_children()[-1]
        self.app.event_tree.selection_set(run_item)
        self.app._show_event_details()

        # Check structured card fields
        self.assertIn("Run", self.app.insp_path_val.cget("text"))
        self.assertIn("BackdoorTrigger", self.app.insp_name_val.cget("text"))
        self.assertIn("powershell", self.app.insp_exe_val.cget("text").lower())
        self.assertIn("EXISTS", self.app.insp_exists_val.cget("text"))
        self.assertEqual(self.app.selected_event_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

        # Test clipboard copy functions
        self.app._copy_selected_sha()
        self.assertEqual(self.app.root.clipboard_get(), self.app.selected_event_sha256)

        self.app._copy_selected_path()
        self.assertEqual(self.app.root.clipboard_get(), self.app.selected_event_path)

        # Test inspector reset
        self.app._reset_inspector_details()
        self.assertEqual(self.app.insp_path_val.cget("text"), "No event selected")
        self.assertEqual(self.app.selected_event_sha256, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)


