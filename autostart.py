"""Windows Auto-Start Manager

Configures automatic launch of the Windows Registry Monitoring System
on PC boot via Windows Run registry key (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run).
"""

import os
import sys
import logging
import winreg

logger = logging.getLogger(__name__)

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_VALUE_NAME = "WindowsRegistryMonitor"


def is_autostart_enabled() -> bool:
    """Check if the application is registered to start with Windows."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_VALUE_NAME)
            return bool(val)
    except FileNotFoundError:
        return False
    except OSError as e:
        logger.debug("Failed to query autostart key: %s", e)
        return False


def get_autostart_command() -> str | None:
    """Get the current registered command line string, if any."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            val, _ = winreg.QueryValueEx(key, APP_VALUE_NAME)
            return str(val)
    except Exception:
        return None


def set_autostart(enable: bool, target_path: str | None = None, start_minimized: bool = True) -> bool:
    """Enable or disable autostart on Windows boot.
    
    Args:
        enable: True to register, False to unregister.
        target_path: Path to executable. If None, resolves to sys.executable or dist exe.
        start_minimized: If True, adds --minimized flag to run silently.
    """
    try:
        if enable:
            if not target_path:
                if getattr(sys, "frozen", False):
                    target_path = sys.executable
                else:
                    # Point to dist\WindowsRegistryMonitor.exe if exists, else current python launcher
                    app_dir = os.path.dirname(os.path.abspath(__file__))
                    dist_exe = os.path.join(app_dir, "dist", "WindowsRegistryMonitor.exe")
                    if os.path.exists(dist_exe):
                        target_path = dist_exe
                    else:
                        target_path = sys.executable

            cmd_str = f'"{target_path}"'
            if start_minimized:
                cmd_str += " --minimized"

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, APP_VALUE_NAME, 0, winreg.REG_SZ, cmd_str)
            logger.info("Auto-start registered in HKCU Run: %s", cmd_str)
            return True
        else:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, APP_VALUE_NAME)
                    logger.info("Auto-start unregistered from HKCU Run.")
                except FileNotFoundError:
                    pass
            return True
    except Exception as e:
        logger.error("Failed to set autostart (enable=%s): %s", enable, e)
        return False
