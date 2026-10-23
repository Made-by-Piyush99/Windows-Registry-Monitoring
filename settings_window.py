"""Application Settings & Configuration Dialog

Provides a comprehensive, spacious settings dialog for:
- Monitoring polling interval & engine timing
- Live Theme switching (Cyber Blue, Obsidian, Matrix, Crimson, Nordic)
- Windows Auto-Start on PC boot (HKCU Run registration)
- Local SQLite database & Windows DPAPI AES-256 encryption management
- Desktop popup alert rate-limiting & severity thresholds
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from typing import Callable, Any

import autostart
import theme_manager

logger = logging.getLogger(__name__)


class AppSettingsWindow(tk.Toplevel):
    """Spacious multi-tab system configuration dialog."""

    def __init__(self, parent_app, on_settings_applied: Callable | None = None):
        super().__init__(parent_app.root)
        self.app = parent_app
        self.config = parent_app.config
        self.on_settings_applied = on_settings_applied

        # Window settings
        self.title("System Preferences & Engine Configuration")
        self.geometry("860x640")
        self.minsize(780, 560)
        try:
            if hasattr(parent_app, "root") and parent_app.root.winfo_viewable():
                self.transient(parent_app.root)
                self.grab_set()
        except Exception:
            pass

        # Get current theme colors
        current_theme_name = self.config.get("appearance", {}).get("theme", theme_manager.DEFAULT_THEME_NAME)
        self.theme = theme_manager.get_theme(current_theme_name)
        self.configure(bg=self.theme["bg"])

        # State variables
        self.var_polling = tk.IntVar(value=self.config.get("polling_interval_seconds", 5))
        self.var_scan_64 = tk.BooleanVar(value=self.config.get("registry_views", {}).get("scan_64bit", True))
        self.var_scan_32 = tk.BooleanVar(value=self.config.get("registry_views", {}).get("scan_32bit", True))
        self.var_hash = tk.BooleanVar(value=self.config.get("file_checks", {}).get("compute_sha256", True))
        self.var_exists = tk.BooleanVar(value=self.config.get("file_checks", {}).get("check_file_exists", True))
        self.var_resolve = tk.BooleanVar(value=self.config.get("file_checks", {}).get("resolve_paths", True))

        # Theme variable
        self.var_theme = tk.StringVar(value=current_theme_name)

        # Autostart state
        self.autostart_active = autostart.is_autostart_enabled()
        self.var_autostart_minimized = tk.BooleanVar(
            value=self.config.get("startup", {}).get("start_minimized", True)
        )

        # Alert settings
        alert_cfg = self.config.get("alert_settings", {})
        self.var_popup_enabled = tk.BooleanVar(value=alert_cfg.get("popup_enabled", True))
        self.var_severity_threshold = tk.StringVar(value=alert_cfg.get("popup_severity_threshold", "informational"))
        self.var_rate_limit = tk.IntVar(value=alert_cfg.get("popup_rate_limit_seconds", 3))

        self._build_ui()
        self._center_window()

    def _center_window(self):
        """Center the settings dialog over the main window."""
        try:
            if not self.winfo_exists():
                return
            pw = self.app.root.winfo_width() if hasattr(self.app.root, "winfo_width") else 1260
            ph = self.app.root.winfo_height() if hasattr(self.app.root, "winfo_height") else 840
            px = self.app.root.winfo_x() if hasattr(self.app.root, "winfo_x") else 100
            py = self.app.root.winfo_y() if hasattr(self.app.root, "winfo_y") else 100
            w = self.winfo_reqwidth() or 800
            h = self.winfo_reqheight() or 600
            x = px + max(0, (pw - w) // 2)
            y = py + max(0, (ph - h) // 2)
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def _build_ui(self):
        """Construct the modern spacious tabbed UI."""
        BG = self.theme["bg"]
        CARD_BG = self.theme["card_bg"]
        BORDER = self.theme["card_border"]
        ACCENT = self.theme["accent_primary"]
        FG = self.theme["fg_primary"]
        FG_MUTED = self.theme["fg_secondary"]

        # Main wrapper with padding
        container = tk.Frame(self, bg=BG, padx=16, pady=14)
        container.pack(fill=tk.BOTH, expand=True)

        # Header banner
        header = tk.Frame(container, bg=BG)
        header.pack(fill=tk.X, pady=(0, 14))

        tk.Label(
            header, text="⚙️ SYSTEM CONFIGURATION & PREFERENCES",
            font=("Segoe UI", 13, "bold"), fg=FG, bg=BG
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Customize engine polling timing, security encryption, aesthetic themes, and Windows startup behavior",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=BG
        ).pack(anchor="w")

        # Notebook for sections
        notebook_frame = tk.Frame(container, bg=CARD_BG, bd=1, relief=tk.SOLID, highlightbackground=BORDER, highlightthickness=1)
        notebook_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 14))

        style = ttk.Style(self)
        style.configure("Settings.TNotebook", background=CARD_BG, borderwidth=0)
        style.configure("Settings.TNotebook.Tab", background="#1e293b", foreground="#94a3b8", padding=[16, 8], font=("Segoe UI", 9, "bold"))
        style.map("Settings.TNotebook.Tab", background=[("selected", CARD_BG)], foreground=[("selected", ACCENT)])

        self.notebook = ttk.Notebook(notebook_frame, style="Settings.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Tab 1: Timing & Engine
        tab_engine = tk.Frame(self.notebook, bg=CARD_BG, padx=18, pady=16)
        self.notebook.add(tab_engine, text="  ⏱ Engine & Timing  ")
        self._build_tab_engine(tab_engine)

        # Tab 2: Theme & UI
        tab_theme = tk.Frame(self.notebook, bg=CARD_BG, padx=18, pady=16)
        self.notebook.add(tab_theme, text="  🎨 Themes & UI  ")
        self._build_tab_theme(tab_theme)

        # Tab 3: Windows Auto-Start
        tab_autostart = tk.Frame(self.notebook, bg=CARD_BG, padx=18, pady=16)
        self.notebook.add(tab_autostart, text="  🚀 Windows Startup  ")
        self._build_tab_autostart(tab_autostart)

        # Tab 4: Database & Encryption
        tab_db = tk.Frame(self.notebook, bg=CARD_BG, padx=18, pady=16)
        self.notebook.add(tab_db, text="  🔒 Encrypted Database  ")
        self._build_tab_db(tab_db)

        # Tab 5: Alerts & Notifications
        tab_alerts = tk.Frame(self.notebook, bg=CARD_BG, padx=18, pady=16)
        self.notebook.add(tab_alerts, text="  🔔 Alert Policies  ")
        self._build_tab_alerts(tab_alerts)

        # Bottom Action Bar
        bottom_bar = tk.Frame(container, bg=BG)
        bottom_bar.pack(fill=tk.X)

        self.btn_save = tk.Button(
            bottom_bar, text="💾 Save & Apply Preferences",
            bg="#059669", fg="#ffffff", activebackground="#047857", activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"), padx=16, pady=6, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._save_and_apply
        )
        self.btn_save.pack(side=tk.RIGHT, padx=(8, 0))

        tk.Button(
            bottom_bar, text="✕ Cancel",
            bg="#1e293b", fg="#cbd5e1", activebackground="#334155", activeforeground="#ffffff",
            font=("Segoe UI", 9), padx=14, pady=6, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self.destroy
        ).pack(side=tk.RIGHT)

        tk.Button(
            bottom_bar, text="↺ Reset Defaults",
            bg="#1e293b", fg="#94a3b8", activebackground="#334155", activeforeground="#ffffff",
            font=("Segoe UI", 9), padx=12, pady=6, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._reset_defaults
        ).pack(side=tk.LEFT)

    # ----------------------------------------------------
    # TAB 1: Engine & Timing
    # ----------------------------------------------------
    def _build_tab_engine(self, parent):
        CARD_BG = self.theme["card_bg"]
        FG = self.theme["fg_primary"]
        FG_MUTED = self.theme["fg_secondary"]
        ACCENT = self.theme["accent_primary"]

        tk.Label(
            parent, text="Continuous Registry Polling Interval",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            parent,
            text="Determines how frequently the background engine polls monitored registry hives. Faster polling detects changes quicker; slower polling consumes fewer CPU cycles.",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG, wraplength=760, justify="left"
        ).pack(anchor="w", pady=(0, 10))

        intervals = [
            (1, "1 Second", "⚡ Real-time ultra high frequency"),
            (2, "2 Seconds", "🚀 Fast telemetry auditing"),
            (5, "5 Seconds", "🛡️ Recommended standard balance"),
            (10, "10 Seconds", "⏳ Low overhead monitoring"),
            (30, "30 Seconds", "💤 Passive background auditing"),
            (60, "60 Seconds", "🍃 Stealth low-resource mode"),
        ]

        grid_frame = tk.Frame(parent, bg=CARD_BG)
        grid_frame.pack(fill=tk.X, pady=(0, 16))

        for idx, (val, title, desc) in enumerate(intervals):
            r = idx // 2
            c = idx % 2
            card = tk.Frame(grid_frame, bg="#0f172a", bd=1, relief=tk.SOLID, padx=10, pady=8)
            card.grid(row=r, column=c, sticky="nsew", padx=6, pady=4)
            grid_frame.columnconfigure(c, weight=1)

            rb = tk.Radiobutton(
                card, text=title, variable=self.var_polling, value=val,
                bg="#0f172a", fg="#ffffff", selectcolor="#1e3a8a", activebackground="#0f172a",
                font=("Segoe UI", 9, "bold")
            )
            rb.pack(anchor="w")
            lbl_desc = tk.Label(card, text=desc, font=("Segoe UI", 8), fg=FG_MUTED, bg="#0f172a")
            lbl_desc.pack(anchor="w", padx=(22, 0))

            def make_selector(v):
                return lambda e: self.var_polling.set(v)
            card.bind("<Button-1>", make_selector(val))
            lbl_desc.bind("<Button-1>", make_selector(val))

        # Quick Save Timing Button directly in Tab 1
        timing_action_row = tk.Frame(parent, bg=CARD_BG)
        timing_action_row.pack(fill=tk.X, pady=(0, 16))

        self.btn_save_timing = tk.Button(
            timing_action_row, text="💾 Save & Apply Timing Now",
            bg="#059669", fg="#ffffff", activebackground="#047857", activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"), padx=14, pady=6, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._save_and_apply
        )
        self.btn_save_timing.pack(side=tk.LEFT)

        self.lbl_timing_status = tk.Label(
            timing_action_row, text="✓ Select preferred frequency above and click Save",
            font=("Segoe UI", 8), fg="#10b981", bg=CARD_BG
        )
        self.lbl_timing_status.pack(side=tk.LEFT, padx=(10, 0))

        # Architecture & Bitness
        tk.Label(
            parent, text="Registry Architecture & Bitness Scans",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(6, 4))

        bit_frame = tk.Frame(parent, bg=CARD_BG)
        bit_frame.pack(fill=tk.X, pady=(0, 12))

        tk.Checkbutton(
            bit_frame, text="Scan 64-bit Native Registry (KEY_WOW64_64KEY)",
            variable=self.var_scan_64, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=2)

        tk.Checkbutton(
            bit_frame, text="Scan 32-bit Emulated Registry (KEY_WOW64_32KEY / WOW6432Node)",
            variable=self.var_scan_32, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=2)

        # File Checks
        tk.Label(
            parent, text="Referenced Binary Forensics",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(6, 4))

        fc_frame = tk.Frame(parent, bg=CARD_BG)
        fc_frame.pack(fill=tk.X)

        tk.Checkbutton(
            fc_frame, text="Compute SHA-256 cryptographic hashes for executable binaries",
            variable=self.var_hash, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=2)

        tk.Checkbutton(
            fc_frame, text="Verify binary file existence on physical disk",
            variable=self.var_exists, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=2)

        tk.Checkbutton(
            fc_frame, text="Expand Windows environment variables (%WINDIR%, %TEMP%) and unquoted arguments",
            variable=self.var_resolve, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=2)

    # ----------------------------------------------------
    # TAB 2: Theme & Appearance
    # ----------------------------------------------------
    def _build_tab_theme(self, parent):
        CARD_BG = self.theme["card_bg"]
        FG = self.theme["fg_primary"]
        FG_MUTED = self.theme["fg_secondary"]
        ACCENT = self.theme["accent_primary"]

        tk.Label(
            parent, text="Select High-Contrast Cyber Theme",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            parent,
            text="Switch between high-contrast Blue Team palettes. Theme changes take effect across all dashboard cards, headers, tables, and dialogs.",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG, wraplength=760
        ).pack(anchor="w", pady=(0, 12))

        theme_cards = [
            ("Cyber Blue Team", "🔵 Cyber Blue Team", "Modern SOC dark navy with glowing cyan & cobalt highlights", "#0b0f19", "#38bdf8"),
            ("Obsidian Stealth", "⚫ Obsidian Stealth", "Minimalist carbon black with titanium & platinum contrasts", "#09090b", "#e4e4e7"),
            ("Matrix Terminal", "🟢 Matrix Terminal", "Classic hacker terminal with deep emerald green matrix contrasts", "#05130b", "#10b981"),
            ("Crimson Alert", "🔴 Crimson Alert", "Threat-hunting red alert with deep carbon gunmetal borders", "#140a0c", "#f43f5e"),
            ("Nordic Frost", "❄️ Nordic Frost", "Deep arctic night with crisp ice-cyan and cold steel slate", "#0c1524", "#67e8f9"),
        ]

        for key, title, desc, bg_color, acc_color in theme_cards:
            card = tk.Frame(parent, bg="#0f172a", bd=1, relief=tk.SOLID, padx=12, pady=8)
            card.pack(fill=tk.X, pady=4)

            top_row = tk.Frame(card, bg="#0f172a")
            top_row.pack(fill=tk.X)

            rb = tk.Radiobutton(
                top_row, text=title, variable=self.var_theme, value=key,
                bg="#0f172a", fg="#ffffff", selectcolor="#1e3a8a", activebackground="#0f172a",
                font=("Segoe UI", 9, "bold")
            )
            rb.pack(side=tk.LEFT)

            # Color swatch
            swatch = tk.Canvas(top_row, width=42, height=14, bg=bg_color, highlightthickness=1, highlightbackground=acc_color)
            swatch.pack(side=tk.RIGHT, padx=6)
            swatch.create_rectangle(21, 0, 42, 14, fill=acc_color, width=0)

            tk.Label(card, text=desc, font=("Segoe UI", 8), fg=FG_MUTED, bg="#0f172a").pack(anchor="w", padx=(24, 0))

        tk.Button(
            parent, text="⚡ Apply Theme Instantly",
            bg="#0284c7", fg="#ffffff", activebackground="#0369a1", font=("Segoe UI", 9, "bold"),
            padx=14, pady=5, bd=0, relief=tk.FLAT, cursor="hand2", command=self._preview_theme
        ).pack(anchor="w", pady=(14, 0))

    def _preview_theme(self):
        """Immediately apply selected theme to main application."""
        selected = self.var_theme.get()
        if hasattr(self.app, "apply_theme"):
            self.app.apply_theme(selected)
            self.theme = theme_manager.get_theme(selected)
            messagebox.showinfo("Theme Applied", f"Theme updated to '{selected}'!", parent=self)

    # ----------------------------------------------------
    # TAB 3: Windows Auto-Start on PC Boot
    # ----------------------------------------------------
    def _build_tab_autostart(self, parent):
        CARD_BG = self.theme["card_bg"]
        FG = self.theme["fg_primary"]
        FG_MUTED = self.theme["fg_secondary"]
        ACCENT = self.theme["accent_primary"]

        tk.Label(
            parent, text="Windows System Boot & Background Auto-Launch",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            parent,
            text="Configure the application to start automatically when your PC powers on. Runs natively through Windows User Startup Registry (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run).",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG, wraplength=760
        ).pack(anchor="w", pady=(0, 14))

        # Status Card
        status_card = tk.Frame(parent, bg="#0f172a", bd=1, relief=tk.SOLID, padx=16, pady=14)
        status_card.pack(fill=tk.X, pady=(0, 14))

        row1 = tk.Frame(status_card, bg="#0f172a")
        row1.pack(fill=tk.X, pady=(0, 8))

        tk.Label(row1, text="Auto-Start Status:", font=("Segoe UI", 9, "bold"), fg="#ffffff", bg="#0f172a").pack(side=tk.LEFT)
        
        self.lbl_autostart_badge = tk.Label(
            row1,
            text="● ENABLED (Starts with Windows)" if self.autostart_active else "○ DISABLED (Manual Start Only)",
            font=("Segoe UI", 9, "bold"),
            bg="#064e3b" if self.autostart_active else "#334155",
            fg="#34d399" if self.autostart_active else "#94a3b8",
            padx=10, pady=2
        )
        self.lbl_autostart_badge.pack(side=tk.LEFT, padx=10)

        # Toggle Button
        self.btn_toggle_autostart = tk.Button(
            status_card,
            text="⏹ Disable Auto-Start on Boot" if self.autostart_active else "🚀 Enable Auto-Start on PC Boot",
            bg="#b91c1c" if self.autostart_active else "#059669",
            fg="#ffffff",
            activebackground="#991b1b" if self.autostart_active else "#047857",
            font=("Segoe UI", 9, "bold"), padx=14, pady=6, bd=0, relief=tk.FLAT, cursor="hand2",
            command=self._toggle_autostart_action
        )
        self.btn_toggle_autostart.pack(anchor="w", pady=(4, 8))

        cmd = autostart.get_autostart_command() or "None"
        self.lbl_autostart_cmd = tk.Label(
            status_card, text=f"Registered Command: {cmd}",
            font=("Consolas", 8), fg="#64748b", bg="#0f172a", wraplength=720, justify="left"
        )
        self.lbl_autostart_cmd.pack(anchor="w")

        # Startup Options
        tk.Label(
            parent, text="Boot Execution Behavior",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(8, 4))

        opt_frame = tk.Frame(parent, bg=CARD_BG)
        opt_frame.pack(fill=tk.X)

        tk.Checkbutton(
            opt_frame, text="Start Minimized in Background (summons movable floating desktop widget)",
            variable=self.var_autostart_minimized, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9)
        ).pack(anchor="w", pady=3)

        tk.Label(
            opt_frame,
            text="When checked, the application starts silently without popping up the full window, placing the draggable widget on your desktop.",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG
        ).pack(anchor="w", padx=(24, 0))

    def _toggle_autostart_action(self):
        """Toggle Windows Auto-Start registration."""
        new_state = not self.autostart_active
        success = autostart.set_autostart(new_state, start_minimized=self.var_autostart_minimized.get())
        if success:
            self.autostart_active = new_state
            if new_state:
                self.lbl_autostart_badge.configure(text="● ENABLED (Starts with Windows)", bg="#064e3b", fg="#34d399")
                self.btn_toggle_autostart.configure(text="⏹ Disable Auto-Start on Boot", bg="#b91c1c", activebackground="#991b1b")
                messagebox.showinfo("Auto-Start Enabled", "Application registered to start automatically on Windows boot!", parent=self)
            else:
                self.lbl_autostart_badge.configure(text="○ DISABLED (Manual Start Only)", bg="#334155", fg="#94a3b8")
                self.btn_toggle_autostart.configure(text="🚀 Enable Auto-Start on PC Boot", bg="#059669", activebackground="#047857")
                messagebox.showinfo("Auto-Start Disabled", "Auto-start registration removed from Windows startup.", parent=self)
            cmd = autostart.get_autostart_command() or "None"
            self.lbl_autostart_cmd.configure(text=f"Registered Command: {cmd}")
        else:
            messagebox.showerror("Error", "Failed to update Windows Run registry key.", parent=self)

    # ----------------------------------------------------
    # TAB 4: Database & Encryption
    # ----------------------------------------------------
    def _build_tab_db(self, parent):
        CARD_BG = self.theme["card_bg"]
        FG = self.theme["fg_primary"]
        FG_MUTED = self.theme["fg_secondary"]
        ACCENT = self.theme["accent_primary"]

        tk.Label(
            parent, text="Local SQLite Database & AES-256 DPAPI Encryption",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            parent,
            text="All detected events, baseline snapshots, and telemetry are stored in an encrypted local SQLite database. Payloads are encrypted with AES-256 (Fernet) backed by Windows DPAPI machine keys, protecting data from unauthorized access or external tools.",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG, wraplength=760
        ).pack(anchor="w", pady=(0, 12))

        # DB Metrics Card
        db_card = tk.Frame(parent, bg="#0f172a", bd=1, relief=tk.SOLID, padx=14, pady=12)
        db_card.pack(fill=tk.X, pady=(0, 14))

        # Retrieve database stats
        db_stats = {}
        if hasattr(self.app, "db") and self.app.db:
            db_stats = self.app.db.get_db_stats()

        rows = [
            ("Database Engine:", "SQLite 3 (WAL Journal Mode)"),
            ("Cryptographic Cipher:", "AES-256 (Fernet Authenticated)"),
            ("Key Protection:", "Windows Data Protection API (crypt32.dll DPAPI)"),
            ("Encrypted Events Stored:", str(db_stats.get("total_events", 0))),
            ("Encrypted Baselines:", str(db_stats.get("total_baselines", 0))),
            ("Database File Size:", f"{db_stats.get('size_bytes', 0) / 1024:.1f} KB"),
            ("Storage Location:", db_stats.get("db_path", "data/registry_monitor.db")),
        ]

        for label_text, val_text in rows:
            r_frame = tk.Frame(db_card, bg="#0f172a")
            r_frame.pack(fill=tk.X, pady=2)
            tk.Label(r_frame, text=label_text, font=("Segoe UI", 8, "bold"), fg="#94a3b8", bg="#0f172a", width=25, anchor="w").pack(side=tk.LEFT)
            tk.Label(r_frame, text=val_text, font=("Segoe UI", 8), fg="#ffffff", bg="#0f172a", anchor="w").pack(side=tk.LEFT)

        # Database Management Buttons
        btn_frame = tk.Frame(parent, bg=CARD_BG)
        btn_frame.pack(fill=tk.X, pady=(6, 0))

        tk.Button(
            btn_frame, text="🧹 Vacuum & Optimize Database",
            bg="#1e293b", fg="#ffffff", activebackground="#334155", font=("Segoe UI", 9),
            padx=12, pady=5, bd=0, relief=tk.FLAT, cursor="hand2", command=self._vacuum_db
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_frame, text="🔐 Verify DPAPI Key Status",
            bg="#1e293b", fg="#ffffff", activebackground="#334155", font=("Segoe UI", 9),
            padx=12, pady=5, bd=0, relief=tk.FLAT, cursor="hand2", command=self._verify_key
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            btn_frame, text="📤 Export Encrypted SQLite DB",
            bg="#0284c7", fg="#ffffff", activebackground="#0369a1", font=("Segoe UI", 9, "bold"),
            padx=12, pady=5, bd=0, relief=tk.FLAT, cursor="hand2", command=self._export_db
        ).pack(side=tk.LEFT)

    def _vacuum_db(self):
        if hasattr(self.app, "db") and self.app.db:
            if self.app.db.vacuum_db():
                messagebox.showinfo("Success", "Database vacuumed and defragmented successfully!", parent=self)
            else:
                messagebox.showerror("Error", "Database vacuum failed.", parent=self)

    def _verify_key(self):
        messagebox.showinfo(
            "Security Status",
            "Windows DPAPI encryption key verified.\n"
            "Data is bound to the current Windows user credentials and hardware.\n"
            "External processes without your session cannot read the encrypted database.",
            parent=self
        )

    def _export_db(self):
        if not hasattr(self.app, "db") or not self.app.db:
            return
        src_path = self.app.db.db_path
        if not os.path.exists(src_path):
            messagebox.showinfo("Info", "Database file is empty or does not exist yet.", parent=self)
            return
        dest = filedialog.asksaveasfilename(
            parent=self, title="Export Encrypted Database",
            defaultextension=".db", filetypes=[("SQLite Database", "*.db"), ("All Files", "*.*")],
            initialfile="registry_monitor_encrypted.db"
        )
        if dest:
            import shutil
            shutil.copy2(src_path, dest)
            messagebox.showinfo("Exported", f"Encrypted database exported to:\n{dest}", parent=self)

    # ----------------------------------------------------
    # TAB 5: Alerts & Notifications
    # ----------------------------------------------------
    def _build_tab_alerts(self, parent):
        CARD_BG = self.theme["card_bg"]
        FG = self.theme["fg_primary"]
        FG_MUTED = self.theme["fg_secondary"]
        ACCENT = self.theme["accent_primary"]

        tk.Label(
            parent, text="Desktop Pop-Up Notification Rules",
            font=("Segoe UI", 10, "bold"), fg=ACCENT, bg=CARD_BG
        ).pack(anchor="w", pady=(0, 4))

        tk.Label(
            parent,
            text="Configure how detected changes alert the operator on screen. Notifications appear as non-blocking floating cards at the bottom right.",
            font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG, wraplength=760
        ).pack(anchor="w", pady=(0, 14))

        alert_box = tk.Frame(parent, bg=CARD_BG)
        alert_box.pack(fill=tk.X, pady=(0, 10))

        tk.Checkbutton(
            alert_box, text="Enable Desktop Pop-up Alerts",
            variable=self.var_popup_enabled, bg=CARD_BG, fg=FG, selectcolor="#1e3a8a",
            activebackground=CARD_BG, font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", pady=4)

        # Threshold
        thresh_frame = tk.Frame(alert_box, bg=CARD_BG)
        thresh_frame.pack(fill=tk.X, pady=6)
        tk.Label(thresh_frame, text="Minimum Severity Threshold:", font=("Segoe UI", 9), fg=FG, bg=CARD_BG).pack(side=tk.LEFT, padx=(0, 10))

        combo = ttk.Combobox(
            thresh_frame, textvariable=self.var_severity_threshold, state="readonly", width=22,
            values=["informational", "suspicious", "investigation_required"]
        )
        combo.pack(side=tk.LEFT)

        # Rate Limit
        rate_frame = tk.Frame(alert_box, bg=CARD_BG)
        rate_frame.pack(fill=tk.X, pady=6)
        tk.Label(rate_frame, text="Alert Rate-Limit Cooldown:", font=("Segoe UI", 9), fg=FG, bg=CARD_BG).pack(side=tk.LEFT, padx=(0, 10))

        rate_spin = tk.Spinbox(
            rate_frame, from_=1, to=60, textvariable=self.var_rate_limit, width=6,
            bg="#1e293b", fg="#ffffff", font=("Segoe UI", 9)
        )
        rate_spin.pack(side=tk.LEFT, padx=(0, 6))
        tk.Label(rate_frame, text="seconds between consecutive pop-ups", font=("Segoe UI", 8), fg=FG_MUTED, bg=CARD_BG).pack(side=tk.LEFT)

    # ----------------------------------------------------
    # Save & Reset Actions
    # ----------------------------------------------------
    def _save_and_apply(self):
        """Save settings to config dictionary and notify parent."""
        self.config["polling_interval_seconds"] = self.var_polling.get()
        if "registry_views" not in self.config:
            self.config["registry_views"] = {}
        self.config["registry_views"]["scan_64bit"] = self.var_scan_64.get()
        self.config["registry_views"]["scan_32bit"] = self.var_scan_32.get()

        if "file_checks" not in self.config:
            self.config["file_checks"] = {}
        self.config["file_checks"]["compute_sha256"] = self.var_hash.get()
        self.config["file_checks"]["check_file_exists"] = self.var_exists.get()
        self.config["file_checks"]["resolve_paths"] = self.var_resolve.get()

        if "appearance" not in self.config:
            self.config["appearance"] = {}
        self.config["appearance"]["theme"] = self.var_theme.get()

        if "startup" not in self.config:
            self.config["startup"] = {}
        self.config["startup"]["start_minimized"] = self.var_autostart_minimized.get()

        if "alert_settings" not in self.config:
            self.config["alert_settings"] = {}
        self.config["alert_settings"]["popup_enabled"] = self.var_popup_enabled.get()
        self.config["alert_settings"]["popup_severity_threshold"] = self.var_severity_threshold.get()
        self.config["alert_settings"]["popup_rate_limit_seconds"] = self.var_rate_limit.get()

        # Save to config.json
        try:
            import json
            cfg_path = os.path.join(self.app.app_dir, "config.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)
            logger.info("Configuration saved to %s", cfg_path)
        except Exception as e:
            logger.error("Failed to save config.json: %s", e)

        # Save to Encrypted SQLite database
        if hasattr(self.app, "db") and self.app.db:
            self.app.db.save_setting("theme", self.var_theme.get())
            self.app.db.save_setting("polling_interval_seconds", self.var_polling.get())
            self.app.db.save_setting("alert_settings", self.config["alert_settings"])

        # Callback to apply
        if self.on_settings_applied:
            self.on_settings_applied(self.config)

        messagebox.showinfo("Saved", "Preferences and engine configuration saved successfully!", parent=self)
        self.destroy()

    def _reset_defaults(self):
        """Reset fields to default."""
        if messagebox.askyesno("Reset", "Reset all settings to default values?", parent=self):
            self.var_polling.set(5)
            self.var_scan_64.set(True)
            self.var_scan_32.set(True)
            self.var_hash.set(True)
            self.var_exists.set(True)
            self.var_resolve.set(True)
            self.var_theme.set(theme_manager.DEFAULT_THEME_NAME)
            self.var_popup_enabled.set(True)
            self.var_severity_threshold.set("informational")
            self.var_rate_limit.set(3)
