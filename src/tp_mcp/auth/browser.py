"""Browser cookie extraction for TrainingPeaks authentication.

SECURITY NOTES:
- Domain is HARDCODED to .trainingpeaks.com - cannot be changed via parameters
- Cookie name is HARDCODED to Production_tpAuth - cannot be changed via parameters
- Cookie values must NEVER be included in error messages or logs
- Only return cookie value in BrowserCookieResult.cookie field, never in message
"""

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BrowserCookieResult:
    """Result of browser cookie extraction.

    SECURITY: Cookie value is stored in `cookie` field only.
    The `message` field must NEVER contain cookie values.
    The __repr__ is overridden to prevent accidental cookie exposure in logs.
    """

    success: bool
    cookie: str | None = field(default=None, repr=False)  # repr=False prevents logging
    message: str = ""
    browser: str | None = None

    def __repr__(self) -> str:
        """Safe repr that never exposes cookie value."""
        cookie_status = "present" if self.cookie else "None"
        return (
            f"BrowserCookieResult(success={self.success}, cookie=<{cookie_status}>, "
            f"message={self.message!r}, browser={self.browser!r})"
        )


SUPPORTED_BROWSERS = ["chrome", "firefox", "safari", "edge", "chromium", "brave", "opera"]

# User data dirs for Chromium-family browsers, relative to the platform base dir.
# browser_cookie3 only reads the "Default" profile; these let us find the others.
_CHROMIUM_DIRS = {
    "darwin": {
        "chrome": "Google/Chrome",
        "chromium": "Chromium",
        "brave": "BraveSoftware/Brave-Browser",
        "edge": "Microsoft Edge",
    },
    "linux": {
        "chrome": "google-chrome",
        "chromium": "chromium",
        "brave": "BraveSoftware/Brave-Browser",
        "edge": "microsoft-edge",
    },
    "win32": {
        "chrome": "Google/Chrome/User Data",
        "chromium": "Chromium/User Data",
        "brave": "BraveSoftware/Brave-Browser/User Data",
        "edge": "Microsoft/Edge/User Data",
    },
}


def _chromium_user_data_dir(browser: str) -> Path | None:
    """Return the user data dir for a Chromium-family browser, if known."""
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    platform_key = sys.platform if sys.platform in ("darwin", "win32") else "linux"
    rel = _CHROMIUM_DIRS[platform_key].get(browser)
    return base / rel if rel else None


def _profile_cookie_file(profile_dir: Path) -> Path | None:
    """Return the cookie DB inside a Chromium profile dir, if present."""
    for candidate in (profile_dir / "Network" / "Cookies", profile_dir / "Cookies"):
        if candidate.is_file():
            return candidate
    return None


def _chromium_profiles(browser: str) -> list[tuple[str, str]]:
    """List (directory name, display name) for each profile, Default first."""
    user_data = _chromium_user_data_dir(browser)
    if not user_data or not user_data.is_dir():
        return []

    display_names: dict[str, str] = {}
    try:
        local_state = json.loads((user_data / "Local State").read_text(encoding="utf-8"))
        for dir_name, info in local_state.get("profile", {}).get("info_cache", {}).items():
            display_names[dir_name] = info.get("name") or dir_name
    except (OSError, ValueError):
        pass

    dirs = {d.name for d in user_data.iterdir() if d.is_dir() and _profile_cookie_file(d)}
    ordered = sorted(dirs, key=lambda d: (d != "Default", d))
    return [(d, display_names.get(d, d)) for d in ordered]


def _resolve_profile(browser: str, profile: str) -> str | None:
    """Match a profile by directory name ("Profile 1") or display name ("Person 1")."""
    wanted = profile.strip().lower()
    for dir_name, display_name in _chromium_profiles(browser):
        if wanted in (dir_name.lower(), display_name.lower()):
            return dir_name
    return None


def extract_tp_cookie(browser: str | None = None, profile: str | None = None) -> BrowserCookieResult:
    """Extract TrainingPeaks cookie from browser.

    Args:
        browser: Browser name (chrome, firefox, safari, edge, chromium, brave, opera).
                 If None, tries all browsers in order.
        profile: Chromium-family profile, by directory ("Profile 1") or display
                 name ("Person 1"). If None, every profile is searched.

    Returns:
        BrowserCookieResult with cookie if found.
    """
    try:
        import browser_cookie3
    except ImportError:
        return BrowserCookieResult(
            success=False,
            message="browser-cookie3 not installed. Run: pip install tp-mcp[browser]",
        )

    # Map browser names to browser_cookie3 functions
    browser_funcs = {
        "chrome": browser_cookie3.chrome,
        "firefox": browser_cookie3.firefox,
        "safari": browser_cookie3.safari,
        "edge": browser_cookie3.edge,
        "chromium": browser_cookie3.chromium,
        "brave": browser_cookie3.brave,
        "opera": browser_cookie3.opera,
    }

    def try_browser(name: str) -> BrowserCookieResult:
        """Try to extract cookie from a specific browser."""
        func = browser_funcs.get(name)
        if not func:
            return BrowserCookieResult(success=False, message=f"Unknown browser: {name}")

        def find_cookie(cookie_file: str | None = None) -> str | None:
            cj = func(cookie_file=cookie_file, domain_name=".trainingpeaks.com")
            for cookie in cj:
                if cookie.name == "Production_tpAuth" and cookie.value:
                    return cookie.value
            return None

        try:
            profiles = _chromium_profiles(name) if name in _CHROMIUM_DIRS["darwin"] else []

            if profile:
                if not profiles:
                    return BrowserCookieResult(
                        success=False, message=f"Profile selection is not supported for {name}"
                    )
                dir_name = _resolve_profile(name, profile)
                if not dir_name:
                    available = ", ".join(f"{d} ({n})" for d, n in profiles)
                    return BrowserCookieResult(
                        success=False,
                        message=f"No {name} profile named '{profile}'. Available: {available}",
                    )
                profiles = [p for p in profiles if p[0] == dir_name]

            if not profiles:
                value = find_cookie()
                if value:
                    return BrowserCookieResult(
                        success=True, cookie=value, browser=name, message=f"Found cookie in {name}"
                    )
                return BrowserCookieResult(success=False, message=f"No TrainingPeaks cookie in {name}")

            user_data = _chromium_user_data_dir(name)
            for dir_name, display_name in profiles:
                cookie_file = _profile_cookie_file(user_data / dir_name)
                value = find_cookie(str(cookie_file))
                if value:
                    label = f"{name} ({display_name})"
                    return BrowserCookieResult(
                        success=True, cookie=value, browser=label, message=f"Found cookie in {label}"
                    )
            searched = ", ".join(n for _, n in profiles)
            return BrowserCookieResult(
                success=False, message=f"No TrainingPeaks cookie in {name} (profiles: {searched})"
            )
        except PermissionError:
            return BrowserCookieResult(
                success=False,
                message=f"Permission denied reading {name} cookies. Close {name} and try again.",
            )
        except Exception as e:
            # SECURITY: Sanitize error message - use only exception type, not full message
            # which could theoretically contain cookie data in edge cases
            error_type = type(e).__name__
            return BrowserCookieResult(success=False, message=f"Error reading {name}: {error_type}")

    # Try specific browser or all browsers
    if browser:
        browser = browser.lower()
        if browser not in browser_funcs:
            return BrowserCookieResult(
                success=False,
                message=f"Unknown browser: {browser}. Supported: {', '.join(SUPPORTED_BROWSERS)}",
            )
        return try_browser(browser)

    if profile:
        return BrowserCookieResult(
            success=False, message="A profile can only be used with a specific browser"
        )

    # Try all browsers in order
    errors = []
    for name in SUPPORTED_BROWSERS:
        result = try_browser(name)
        if result.success:
            return result
        errors.append(f"  {name}: {result.message}")

    return BrowserCookieResult(
        success=False,
        message="Could not find TrainingPeaks cookie in any browser.\n" + "\n".join(errors),
    )
