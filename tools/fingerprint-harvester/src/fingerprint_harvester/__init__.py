"""Capture and compare browser wire fingerprints."""

from .capabilities import analyze_capabilities
from .diffing import diff_profiles
from .normalize import build_profile, normalize_sample
from .models import ChromeRelease, ConsumerChromeRelease
from .readiness import evaluate_readiness
from .releases import fetch_consumer_release, fetch_release

__all__ = [
    "ChromeRelease",
    "ConsumerChromeRelease",
    "analyze_capabilities",
    "build_profile",
    "diff_profiles",
    "evaluate_readiness",
    "fetch_consumer_release",
    "fetch_release",
    "normalize_sample",
]
