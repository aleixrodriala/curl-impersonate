import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .capabilities import analyze_capabilities
from .models import ChromeRelease
from .normalize import build_profile, normalize_sample, sanitize_sample
from .readiness import evaluate_readiness


def _write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_capture_bundle(
    output: Path,
    samples: list[dict[str, Any]],
    release: ChromeRelease | None = None,
    platform: str | None = None,
    distribution: str = "unverified",
) -> dict[str, Any]:
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite capture bundle: {output}")
    if not samples:
        raise ValueError("Cannot write an empty capture bundle")

    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".fingerprint-bundle-", dir=output.parent) as temp:
        bundle = Path(temp) / "bundle"
        sample_root = bundle / "samples"
        sample_root.mkdir(parents=True)

        sanitized_samples = [sanitize_sample(sample) for sample in samples]
        for index, sample in enumerate(sanitized_samples):
            sample_dir = sample_root / f"{index:03d}"
            sample_dir.mkdir()
            _write_json(sample_dir / "raw.json", sample)
            _write_json(sample_dir / "normalized.json", normalize_sample(sample))

        profile = build_profile(sanitized_samples)
        gaps = analyze_capabilities(profile)
        readiness = evaluate_readiness(profile, distribution)
        _write_json(bundle / "profile.json", profile)
        _write_json(
            bundle / "capabilities.json",
            {
                "representable": not gaps,
                "gaps": [gap.to_dict() for gap in gaps],
            },
        )
        _write_json(bundle / "readiness.json", readiness.to_dict())

        manifest: dict[str, Any] = {
            "schema_version": 2,
            "sample_count": len(samples),
            "redactions": [
                "public source IP",
                "TCP/IP metadata",
                "TLS client random",
                "TLS session id",
            ],
            "profile": "profile.json",
            "capabilities": "capabilities.json",
            "readiness": "readiness.json",
            "browser_distribution": distribution,
        }
        if release is not None:
            manifest["expected_release"] = release.to_dict()
        if platform is not None:
            manifest["platform"] = platform
        _write_json(bundle / "manifest.json", manifest)
        os.replace(bundle, output)
    return profile


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return payload


def load_bundle_samples(bundle: Path) -> list[dict[str, Any]]:
    sample_root = bundle / "samples"
    if not sample_root.is_dir():
        raise ValueError(f"Capture bundle has no samples directory: {bundle}")
    samples = [load_json(path / "raw.json") for path in sorted(sample_root.iterdir())]
    if not samples:
        raise ValueError(f"Capture bundle contains no samples: {bundle}")
    return samples
