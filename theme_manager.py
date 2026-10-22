"""Theme Manager for Windows Registry Monitoring System

Provides customizable high-contrast cybersecurity dashboard themes:
1. Cyber Blue Team (Default - Modern SOC Navy & Cyan)
2. Obsidian Stealth (Minimalist Carbon & Titanium)
3. Matrix Terminal (Hacker Emerald & Forest)
4. Crimson Alert (Threat Hunter Dark Red)
5. Nordic Frost (Deep Arctic Ice Blue)
"""

from typing import Any

THEMES = {
    "Cyber Blue Team": {
        "name": "Cyber Blue Team",
        "description": "SOC Blue Team dark console with glowing cyan & cobalt accents",
        "bg": "#0b0f19",
        "card_bg": "#111827",
        "card_border": "#1f2937",
        "card_border_accent": "#334155",
        "accent_primary": "#38bdf8",
        "accent_secondary": "#2563eb",
        "fg_primary": "#f8fafc",
        "fg_secondary": "#94a3b8",
        "tree_bg": "#0f172a",
        "tree_fg": "#f8fafc",
        "tree_heading_bg": "#1e293b",
        "tree_heading_fg": "#f8fafc",
        "tree_select_bg": "#1e3a8a",
        "tree_select_fg": "#ffffff",
        "btn_normal_bg": "#1e293b",
        "btn_normal_fg": "#f8fafc",
        "btn_active_bg": "#334155",
        "entry_bg": "#1e293b",
        "entry_fg": "#ffffff",
        "entry_border": "#334155",
        "badge_border": "#0284c7",
    },
    "Obsidian Stealth": {
        "name": "Obsidian Stealth",
        "description": "Minimalist deep carbon black with titanium & platinum contrasts",
        "bg": "#09090b",
        "card_bg": "#18181b",
        "card_border": "#27272a",
        "card_border_accent": "#3f3f46",
        "accent_primary": "#e4e4e7",
        "accent_secondary": "#71717a",
        "fg_primary": "#fafafa",
        "fg_secondary": "#a1a1aa",
        "tree_bg": "#121215",
        "tree_fg": "#fafafa",
        "tree_heading_bg": "#202024",
        "tree_heading_fg": "#ffffff",
        "tree_select_bg": "#3f3f46",
        "tree_select_fg": "#ffffff",
        "btn_normal_bg": "#27272a",
        "btn_normal_fg": "#fafafa",
        "btn_active_bg": "#3f3f46",
        "entry_bg": "#18181b",
        "entry_fg": "#ffffff",
        "entry_border": "#3f3f46",
        "badge_border": "#71717a",
    },
    "Matrix Terminal": {
        "name": "Matrix Terminal",
        "description": "Classic hacker emerald terminal with deep jade contrasts",
        "bg": "#05130b",
        "card_bg": "#092215",
        "card_border": "#144229",
        "card_border_accent": "#166534",
        "accent_primary": "#10b981",
        "accent_secondary": "#059669",
        "fg_primary": "#ecfdf5",
        "fg_secondary": "#6ee7b7",
        "tree_bg": "#071c10",
        "tree_fg": "#ecfdf5",
        "tree_heading_bg": "#0d331f",
        "tree_heading_fg": "#a7f3d0",
        "tree_select_bg": "#065f46",
        "tree_select_fg": "#ffffff",
        "btn_normal_bg": "#0f3a23",
        "btn_normal_fg": "#ecfdf5",
        "btn_active_bg": "#155734",
        "entry_bg": "#092215",
        "entry_fg": "#10b981",
        "entry_border": "#144229",
        "badge_border": "#10b981",
    },
    "Crimson Alert": {
        "name": "Crimson Alert",
        "description": "High-alert threat-hunting red and deep carbon gunmetal",
        "bg": "#140a0c",
        "card_bg": "#201215",
        "card_border": "#3b1d24",
        "card_border_accent": "#4c1d24",
        "accent_primary": "#f43f5e",
        "accent_secondary": "#be123c",
        "fg_primary": "#fff1f2",
        "fg_secondary": "#fda4af",
        "tree_bg": "#1b0d10",
        "tree_fg": "#fff1f2",
        "tree_heading_bg": "#2c151a",
        "tree_heading_fg": "#fecdd3",
        "tree_select_bg": "#881337",
        "tree_select_fg": "#ffffff",
        "btn_normal_bg": "#33161c",
        "btn_normal_fg": "#fff1f2",
        "btn_active_bg": "#4c1d24",
        "entry_bg": "#201215",
        "entry_fg": "#f43f5e",
        "entry_border": "#3b1d24",
        "badge_border": "#f43f5e",
    },
    "Nordic Frost": {
        "name": "Nordic Frost",
        "description": "Deep arctic night with crisp ice-cyan and cold steel blue",
        "bg": "#0c1524",
        "card_bg": "#142238",
        "card_border": "#233754",
        "card_border_accent": "#334e75",
        "accent_primary": "#67e8f9",
        "accent_secondary": "#0284c7",
        "fg_primary": "#f0f9ff",
        "fg_secondary": "#7dd3fc",
        "tree_bg": "#0e1b2e",
        "tree_fg": "#f0f9ff",
        "tree_heading_bg": "#1b2d49",
        "tree_heading_fg": "#e0f2fe",
        "tree_select_bg": "#075985",
        "tree_select_fg": "#ffffff",
        "btn_normal_bg": "#1d3252",
        "btn_normal_fg": "#f0f9ff",
        "btn_active_bg": "#2b466f",
        "entry_bg": "#142238",
        "entry_fg": "#67e8f9",
        "entry_border": "#233754",
        "badge_border": "#67e8f9",
    },
}

DEFAULT_THEME_NAME = "Cyber Blue Team"


def get_theme(name: str | None = None) -> dict[str, Any]:
    """Retrieve theme dictionary by name, falling back to Cyber Blue Team."""
    if not name or name not in THEMES:
        return THEMES[DEFAULT_THEME_NAME]
    return THEMES[name]


def list_theme_names() -> list[str]:
    """List all available theme names."""
    return list(THEMES.keys())
