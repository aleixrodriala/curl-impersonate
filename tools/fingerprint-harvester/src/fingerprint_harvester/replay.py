import json
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

from .bundle import load_json
from .diffing import diff_profiles
from .models import ProfileDifference
from .normalize import build_profile, fingerprint_comparison_view


class ReplayError(RuntimeError):
    pass


def _run_json(command: list[str], attempts: int = 1) -> dict[str, Any]:
    errors: list[str] = []
    for _ in range(attempts):
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if process.returncode != 0:
            errors.append(process.stderr.strip() or f"exit status {process.returncode}")
            continue
        try:
            payload = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON: {exc}")
            continue
        if isinstance(payload, dict):
            return payload
        errors.append("collector response was not a JSON object")
    raise ReplayError("curl collector request failed: " + "; ".join(errors))


def capture_curl_sample(
    curl_binary: Path,
    target: str,
    tls_url: str,
    http3_url: str,
) -> dict[str, Any]:
    base = [
        str(curl_binary),
        "--silent",
        "--show-error",
        "--compressed",
        "--impersonate",
        target,
    ]
    tls_http2 = _run_json([*base, "--http2", tls_url])
    http3 = _run_json([*base, "--http3-only", http3_url], attempts=3)
    return {
        "browser": {
            "mode": "native-replay",
            "platform": "curl-impersonate",
            "user_agent": tls_http2.get("user_agent", ""),
            "version": target,
        },
        "tls_http2": tls_http2,
        "http3": http3,
        "source_urls": {
            "tls_http2": tls_url,
            "http3": http3_url,
        },
    }


def capture_curl_samples(
    curl_binary: Path,
    target: str,
    sample_count: int,
    tls_url: str,
    http3_url: str,
) -> list[dict[str, Any]]:
    if sample_count < 3:
        raise ValueError("native replay requires at least three samples")
    if not curl_binary.is_file():
        raise FileNotFoundError(
            f"curl-impersonate binary does not exist: {curl_binary}"
        )
    return [
        capture_curl_sample(curl_binary, target, tls_url, http3_url)
        for _ in range(sample_count)
    ]


def compare_replay(
    chrome_bundle: Path,
    replay_samples: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[ProfileDifference]]:
    chrome_profile = load_json(chrome_bundle / "profile.json")
    expected = chrome_profile.get("fingerprint")
    if not isinstance(expected, dict):
        raise ValueError("consumer Chrome bundle has no canonical fingerprint")
    actual_profile = build_profile([deepcopy(sample) for sample in replay_samples])
    actual = actual_profile.get("fingerprint")
    assert isinstance(actual, dict)
    differences = diff_profiles(
        fingerprint_comparison_view(expected),
        fingerprint_comparison_view(actual),
    )
    return actual_profile, differences
