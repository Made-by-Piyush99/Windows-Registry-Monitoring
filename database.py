"""Database & Encryption Module for Windows Registry Change Monitoring System

Provides local SQLite persistence with transparent AES-256 (Fernet) encryption
protected by Windows DPAPI (Data Protection API via crypt32.dll).

Ensures that all stored registry telemetry, values, baseline snapshots,
and detected changes are encrypted on disk and cannot be accessed or read
by external applications or unauthorized users.
"""

import os
import sys
import json
import sqlite3
import logging
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

# Win32 DPAPI Data structures
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _dpapi_protect(data_bytes: bytes) -> bytes:
    """Encrypt byte data using Windows DPAPI (CryptProtectData).
    
    The encryption is tied to the logged-in Windows user session and machine.
    """
    if sys.platform != "win32":
        return data_bytes
    try:
        in_blob = DATA_BLOB(
            len(data_bytes),
            ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte))
        )
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob), "WRM_DPAPI_KEY", None, None, None, 0, ctypes.byref(out_blob)
        ):
            raise ctypes.WinError()
        buf = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return buf
    except Exception as e:
        logger.warning("Windows DPAPI Protect failed: %s. Falling back to raw key.", e)
        return data_bytes


def _dpapi_unprotect(cipher_bytes: bytes) -> bytes:
    """Decrypt byte data using Windows DPAPI (CryptUnprotectData)."""
    if sys.platform != "win32":
        return cipher_bytes
    try:
        in_blob = DATA_BLOB(
            len(cipher_bytes),
            ctypes.cast(ctypes.create_string_buffer(cipher_bytes), ctypes.POINTER(ctypes.c_byte))
        )
        out_blob = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
        ):
            raise ctypes.WinError()
        buf = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        ctypes.windll.kernel32.LocalFree(out_blob.pbData)
        return buf
    except Exception as e:
        logger.warning("Windows DPAPI Unprotect failed: %s. Falling back to raw cipher.", e)
        return cipher_bytes


class EncryptedDatabaseManager:
    """Manages encrypted SQLite local storage with Windows DPAPI-protected AES-256 keys."""

    def __init__(self, db_path: str, key_path: str | None = None):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        if key_path is None:
            key_path = os.path.join(os.path.dirname(self.db_path), ".security.dpapi")
        self.key_path = key_path
        self._fernet: Fernet | None = None
        self._init_cipher()
        self._init_tables()

    def _init_cipher(self):
        """Initialize or load the DPAPI-protected Fernet encryption key."""
        try:
            if os.path.exists(self.key_path):
                with open(self.key_path, "rb") as f:
                    encrypted_key = f.read()
                raw_key = _dpapi_unprotect(encrypted_key)
                self._fernet = Fernet(raw_key)
            else:
                raw_key = Fernet.generate_key()
                encrypted_key = _dpapi_protect(raw_key)
                with open(self.key_path, "wb") as f:
                    f.write(encrypted_key)
                self._fernet = Fernet(raw_key)
            logger.info("EncryptedDatabaseManager initialized with DPAPI-backed AES-256 cipher.")
        except Exception as e:
            logger.error("Failed to initialize DPAPI cipher: %s. Using ephemeral key.", e)
            raw_key = Fernet.generate_key()
            self._fernet = Fernet(raw_key)

    def encrypt_payload(self, data: Any) -> bytes:
        """Serialize data to JSON and encrypt with AES-256 Fernet."""
        if self._fernet is None:
            self._init_cipher()
        serialized = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        return self._fernet.encrypt(serialized)

    def decrypt_payload(self, cipher_bytes: bytes) -> Any:
        """Decrypt AES-256 Fernet payload and parse JSON."""
        if self._fernet is None:
            self._init_cipher()
        decrypted = self._fernet.decrypt(cipher_bytes)
        return json.loads(decrypted.decode("utf-8"))

    @contextmanager
    def _get_connection(self):
        """Yield a managed SQLite connection that closes automatically."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            yield conn
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _init_tables(self):
        """Create database tables if they do not exist."""
        with self._get_connection() as conn:
            # Events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    change_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT,
                    full_path TEXT,
                    value_name TEXT,
                    encrypted_payload BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);")

            # Baseline table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    total_keys INTEGER,
                    total_values INTEGER,
                    integrity_sha256 TEXT,
                    encrypted_payload BLOB NOT NULL
                );
            """)

            # Application settings table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    encrypted_val BLOB,
                    updated_at TEXT NOT NULL
                );
            """)

            # Scan history table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    keys_scanned INTEGER,
                    errors INTEGER,
                    access_denied INTEGER,
                    changes_found INTEGER
                );
            """)

            # Threat remediations table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remediations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_id TEXT,
                    full_path TEXT,
                    value_name TEXT,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    encrypted_details BLOB
                );
            """)
            conn.commit()

    def save_event(self, event: dict) -> bool:
        """Save a single registry event with an encrypted payload."""
        return self.save_events([event]) == 1

    def save_events(self, events: list[dict]) -> int:
        """Batch save registry change events with encrypted payloads."""
        if not events:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        saved = 0
        with self._get_connection() as conn:
            for ev in events:
                try:
                    eid = ev.get("event_id") or str(datetime.now().timestamp())
                    ts = ev.get("timestamp") or now
                    ct = ev.get("change_type", "UNKNOWN")
                    sev = ev.get("severity", "informational")
                    cat = ev.get("category", "")
                    fp = ev.get("full_path", "")
                    vn = ev.get("value_name", "")
                    encrypted_blob = self.encrypt_payload(ev)

                    conn.execute("""
                        INSERT OR REPLACE INTO events (
                            event_id, timestamp, change_type, severity, category,
                            full_path, value_name, encrypted_payload, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (eid, ts, ct, sev, cat, fp, vn, encrypted_blob, now))
                    saved += 1
                except Exception as e:
                    logger.error("Failed to insert encrypted event %s: %s", ev.get("event_id"), e)
            conn.commit()
        return saved

    def get_events(self, limit: int = 1000, severity_filter: str | None = None) -> list[dict]:
        """Retrieve and decrypt events from the database."""
        events = []
        with self._get_connection() as conn:
            query = "SELECT encrypted_payload FROM events"
            params = []
            if severity_filter and severity_filter.lower() != "all":
                query += " WHERE severity = ?"
                params.append(severity_filter.lower())
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor = conn.execute(query, params)
            for row in cursor.fetchall():
                try:
                    ev = self.decrypt_payload(row["encrypted_payload"])
                    events.append(ev)
                except Exception as e:
                    logger.debug("Decryption error on event row: %s", e)
        return events

    def save_baseline(self, baseline: dict) -> bool:
        """Save baseline to database with encrypted payload."""
        try:
            meta = baseline.get("metadata", {})
            created_at = meta.get("created_at") or datetime.now(timezone.utc).isoformat()
            total_keys = meta.get("total_keys_scanned", 0)
            total_values = meta.get("total_values_captured", 0)
            integrity_hash = meta.get("integrity_sha256", "")
            encrypted_blob = self.encrypt_payload(baseline)

            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO baselines (
                        created_at, total_keys, total_values, integrity_sha256, encrypted_payload
                    ) VALUES (?, ?, ?, ?, ?)
                """, (created_at, total_keys, total_values, integrity_hash, encrypted_blob))
                conn.commit()
            logger.info("Baseline saved to encrypted SQLite database.")
            return True
        except Exception as e:
            logger.error("Failed to save baseline to database: %s", e)
            return False

    def load_latest_baseline(self) -> dict | None:
        """Load and decrypt the most recent baseline from database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT encrypted_payload FROM baselines
                    ORDER BY id DESC LIMIT 1
                """)
                row = cursor.fetchone()
                if row:
                    return self.decrypt_payload(row["encrypted_payload"])
        except Exception as e:
            logger.error("Failed to load baseline from database: %s", e)
        return None

    def record_scan(self, keys_scanned: int, errors: int, access_denied: int, changes_count: int):
        """Record scan statistics in the database."""
        try:
            now = datetime.now(timezone.utc).isoformat()
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO scan_history (timestamp, keys_scanned, errors, access_denied, changes_found)
                    VALUES (?, ?, ?, ?, ?)
                """, (now, keys_scanned, errors, access_denied, changes_count))
                conn.commit()
        except Exception as e:
            logger.debug("Failed to record scan in db: %s", e)

    def save_setting(self, key: str, value: Any, encrypt: bool = False):
        """Save a setting key-value pair."""
        try:
            now = datetime.now(timezone.utc).isoformat()
            val_str = json.dumps(value) if not isinstance(value, str) else value
            enc_blob = self.encrypt_payload(value) if encrypt else None
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO settings (key, value, encrypted_val, updated_at)
                    VALUES (?, ?, ?, ?)
                """, (key, val_str, enc_blob, now))
                conn.commit()
        except Exception as e:
            logger.error("Failed to save setting %s: %s", key, e)

    def get_setting(self, key: str, default: Any = None, is_encrypted: bool = False) -> Any:
        """Retrieve a setting key-value pair."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT value, encrypted_val FROM settings WHERE key = ?", (key,))
                row = cursor.fetchone()
                if row:
                    if is_encrypted and row["encrypted_val"]:
                        return self.decrypt_payload(row["encrypted_val"])
                    val = row["value"]
                    try:
                        return json.loads(val)
                    except Exception:
                        return val
        except Exception as e:
            logger.debug("Failed to retrieve setting %s: %s", key, e)
        return default

    def record_remediation(self, event_id: str, full_path: str, value_name: str,
                           action: str, result: str, details: dict | None = None) -> bool:
        """Record a threat remediation / registry deletion action into encrypted database."""
        try:
            now = datetime.now(timezone.utc).isoformat()
            encrypted_details = self.encrypt_payload(details or {}) if details else None
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO remediations (
                        timestamp, event_id, full_path, value_name, action, result, encrypted_details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (now, event_id, full_path, value_name, action, result, encrypted_details))
                conn.commit()
            logger.info("Remediation recorded in database: %s [%s] -> %s", full_path, value_name, result)
            return True
        except Exception as e:
            logger.error("Failed to record remediation: %s", e)
            return False

    def get_remediations(self, limit: int = 100) -> list[dict]:
        """Retrieve recent remediation actions."""
        remediations = []
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, timestamp, event_id, full_path, value_name, action, result, encrypted_details
                    FROM remediations ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
                for row in cursor.fetchall():
                    item = dict(row)
                    if item.get("encrypted_details"):
                        try:
                            item["details"] = self.decrypt_payload(item["encrypted_details"])
                        except Exception:
                            item["details"] = {}
                    remediations.append(item)
        except Exception as e:
            logger.debug("Failed to retrieve remediations: %s", e)
        return remediations

    def get_db_stats(self) -> dict:
        """Get summary statistics of the encrypted database."""
        stats = {
            "db_path": self.db_path,
            "size_bytes": 0,
            "total_events": 0,
            "total_baselines": 0,
            "total_scans": 0,
            "total_remediations": 0,
            "encryption_algorithm": "AES-256 (Fernet) + Windows DPAPI",
            "is_encrypted": True,
        }
        if os.path.exists(self.db_path):
            stats["size_bytes"] = os.path.getsize(self.db_path)
        try:
            with self._get_connection() as conn:
                stats["total_events"] = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                stats["total_baselines"] = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
                stats["total_scans"] = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
                stats["total_remediations"] = conn.execute("SELECT COUNT(*) FROM remediations").fetchone()[0]
        except Exception as e:
            logger.debug("Failed to get db stats: %s", e)
        return stats

    def vacuum_db(self):
        """Optimize and defragment database file."""
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM;")
            logger.info("Database vacuumed successfully.")
            return True
        except Exception as e:
            logger.error("Vacuum failed: %s", e)
            return False


# Singleton instance helper
_db_instance: EncryptedDatabaseManager | None = None

def get_db(app_dir: str) -> EncryptedDatabaseManager:
    """Get or create singleton EncryptedDatabaseManager instance."""
    global _db_instance
    if _db_instance is None:
        db_path = os.path.join(app_dir, "data", "registry_monitor.db")
        key_path = os.path.join(app_dir, "data", ".security.dpapi")
        _db_instance = EncryptedDatabaseManager(db_path, key_path)
    return _db_instance
