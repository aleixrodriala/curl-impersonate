"""Anonymous Google Play authentication for Android browser harvesting."""

from copy import deepcopy

import httpx
from gplaydl.auth import DEFAULT_DISPENSER_URL, fetch_token, save_auth
from gplaydl.profiles import FALLBACK_PROFILE


SUPPORTED_ARCHITECTURES = ("arm64", "x86_64")


def build_x86_64_profile() -> dict[str, str]:
    """Return an Android SDK device profile that requests x86_64 splits."""
    profile = deepcopy(FALLBACK_PROFILE)
    profile.update(
        {
            "UserReadableName": "Android SDK x86_64",
            "Build.HARDWARE": "ranchu",
            "Build.FINGERPRINT": (
                "google/sdk_gphone64_x86_64/emu64xa:15/"
                "AE3A.240806.042/12529570:user/release-keys"
            ),
            "Build.DEVICE": "emu64xa",
            "Build.VERSION.SDK_INT": "35",
            "Build.VERSION.RELEASE": "15",
            "Build.MODEL": "sdk_gphone64_x86_64",
            "Build.PRODUCT": "sdk_gphone64_x86_64",
            "Build.ID": "AE3A.240806.042",
            "Build.SUPPORTED_ABIS": "x86_64,x86",
            "Platforms": "x86_64,x86",
        }
    )
    return profile


def _fetch_x86_64_token(dispenser_url: str | None = None) -> dict | None:
    response = httpx.post(
        dispenser_url or DEFAULT_DISPENSER_URL,
        json=build_x86_64_profile(),
        headers={
            "User-Agent": "com.aurora.store-4.6.1-70",
            "Content-Type": "application/json",
        },
        timeout=15,
    )
    if response.status_code != 200:
        return None
    data = response.json()
    return data if data.get("authToken") else None


def authenticate_play(architecture: str, dispenser_url: str | None = None) -> None:
    """Fetch and cache a Play token without exposing it to stdout."""
    if architecture not in SUPPORTED_ARCHITECTURES:
        raise ValueError(f"Unsupported Play architecture: {architecture}")
    if architecture == "x86_64":
        data = _fetch_x86_64_token(dispenser_url)
    else:
        data = fetch_token(dispenser_url=dispenser_url, arch=architecture)
    if not data:
        raise RuntimeError("Anonymous Google Play authentication failed")
    save_auth(data, architecture)
