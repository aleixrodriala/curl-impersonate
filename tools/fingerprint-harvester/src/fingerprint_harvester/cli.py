import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .chrome_runner import (
    DEFAULT_HTTP3_URL,
    DEFAULT_TLS_URL,
    ChromeRunner,
)
from .bundle import load_bundle_samples, load_json, write_capture_bundle
from .capabilities import analyze_capabilities
from .compiler import (
    candidate_from_bundle,
    extract_initializer,
    load_native_profile,
    render_c_initializer,
)
from .diffing import diff_profiles
from .normalize import (
    build_profile,
    fingerprint_comparison_view,
    fingerprint_transport_view,
)
from .readiness import evaluate_readiness
from .replay import capture_curl_samples, compare_replay
from .releases import (
    DEFAULT_RELEASE_FEED,
    DEFAULT_VERSION_HISTORY_API,
    download_chrome,
    fetch_consumer_release,
    fetch_release,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="curl-impersonate-harvest",
        description="Harvest and compare real Chrome wire fingerprints.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    release = subparsers.add_parser(
        "release", help="Show consumer Chrome Stable for one platform"
    )
    _add_consumer_release_arguments(release)

    cft_release = subparsers.add_parser(
        "cft-release", help="Show the latest Chrome-for-Testing baseline release"
    )
    _add_cft_release_arguments(cft_release)
    cft_release.add_argument("--platform", help="Only show one platform download")

    download = subparsers.add_parser(
        "cft-download", help="Download an exact Chrome-for-Testing build"
    )
    _add_cft_release_arguments(download)
    download.add_argument("--platform", required=True)
    download.add_argument("--output", type=Path, required=True)

    capture = subparsers.add_parser(
        "capture", help="Capture TLS, HTTP/2, and HTTP/3 in fresh browser profiles"
    )
    _add_consumer_release_arguments(capture)
    capture.add_argument("--output", type=Path, required=True)
    capture.add_argument("--samples", type=int, default=3)
    capture.add_argument("--chrome-binary", type=Path)
    capture.add_argument(
        "--browser-mode",
        choices=("headless", "headful"),
        default="headful",
    )
    capture.add_argument("--tls-url", default=DEFAULT_TLS_URL)
    capture.add_argument("--http3-url", default=DEFAULT_HTTP3_URL)
    capture.add_argument(
        "--no-release-check",
        action="store_true",
        help="Capture an installed browser without requiring the latest exact build",
    )
    capture.add_argument(
        "--allow-version-mismatch",
        action="store_true",
        help="Write the bundle even when Chrome does not match the expected build",
    )

    harvest = subparsers.add_parser(
        "harvest",
        help="Poll and capture installed consumer Chrome Stable once",
    )
    _add_consumer_release_arguments(harvest)
    harvest.add_argument("--workspace", type=Path, required=True)
    harvest.add_argument("--samples", type=int, default=5)
    harvest.add_argument(
        "--browser-mode",
        choices=("headless", "headful"),
        default="headful",
    )
    harvest.add_argument("--tls-url", default=DEFAULT_TLS_URL)
    harvest.add_argument("--http3-url", default=DEFAULT_HTTP3_URL)

    cft_harvest = subparsers.add_parser(
        "cft-harvest",
        help="Poll and capture a non-canonical Chrome-for-Testing baseline once",
    )
    _add_cft_release_arguments(cft_harvest)
    cft_harvest.add_argument("--platform", default="linux64")
    cft_harvest.add_argument("--workspace", type=Path, required=True)
    cft_harvest.add_argument("--samples", type=int, default=5)
    cft_harvest.add_argument(
        "--browser-mode",
        choices=("headless", "headful"),
        default="headful",
    )
    cft_harvest.add_argument("--tls-url", default=DEFAULT_TLS_URL)
    cft_harvest.add_argument("--http3-url", default=DEFAULT_HTTP3_URL)

    normalize = subparsers.add_parser(
        "normalize", help="Rebuild a canonical profile from a capture bundle"
    )
    normalize.add_argument("bundle", type=Path)
    normalize.add_argument("--output", type=Path)

    difference = subparsers.add_parser(
        "diff", help="Compare two profile JSON files or capture bundles"
    )
    difference.add_argument("before", type=Path)
    difference.add_argument("after", type=Path)
    difference.add_argument(
        "--transport-only",
        action="store_true",
        help="Ignore OS-specific User-Agent and header values",
    )

    capabilities = subparsers.add_parser(
        "capabilities", help="Report native curl-impersonate capability gaps"
    )
    capabilities.add_argument("profile", type=Path)

    readiness = subparsers.add_parser(
        "readiness", help="Report authoritative compilation readiness for a bundle"
    )
    readiness.add_argument("bundle", type=Path)

    candidate = subparsers.add_parser(
        "candidate", help="Compile a ready capture bundle into a native profile"
    )
    candidate.add_argument("bundle", type=Path)
    candidate.add_argument("--target", required=True)
    candidate.add_argument("--output", type=Path, required=True)

    render = subparsers.add_parser(
        "render", help="Render a declarative native profile as a C initializer"
    )
    render.add_argument("profile", type=Path)
    render.add_argument("--output", type=Path)
    render.add_argument(
        "--check-patch",
        type=Path,
        help="Require the generated initializer to match this existing patch",
    )

    replay = subparsers.add_parser(
        "replay", help="Replay a built native target through the same collectors"
    )
    replay.add_argument("chrome_bundle", type=Path)
    replay.add_argument("--curl-binary", type=Path, required=True)
    replay.add_argument("--target", required=True)
    replay.add_argument("--samples", type=int, default=3)
    replay.add_argument("--tls-url", default=DEFAULT_TLS_URL)
    replay.add_argument("--http3-url", default=DEFAULT_HTTP3_URL)
    replay.add_argument("--output", type=Path)
    return parser


def _add_cft_release_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--channel", default="Stable")
    parser.add_argument("--feed-url", default=DEFAULT_RELEASE_FEED)


def _add_consumer_release_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--platform", required=True)
    parser.add_argument("--channel", default="stable")
    parser.add_argument("--version-history-url", default=DEFAULT_VERSION_HISTORY_API)


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _load_profile(path: Path) -> dict[str, Any]:
    if path.is_dir():
        path = path / "profile.json"
    return load_json(path)


def _load_comparable_fingerprint(
    path: Path,
    transport_only: bool = False,
) -> dict[str, Any]:
    profile = _load_profile(path)
    fingerprint = profile.get("fingerprint", profile)
    if not isinstance(fingerprint, dict):
        raise ValueError(f"Profile has no fingerprint object: {path}")
    if transport_only:
        return fingerprint_transport_view(fingerprint)
    return fingerprint_comparison_view(fingerprint)


def _handle_release(args: argparse.Namespace) -> int:
    release = fetch_consumer_release(
        args.platform,
        args.channel,
        args.version_history_url,
    )
    _print_json(release.to_dict())
    return 0


def _handle_cft_release(args: argparse.Namespace) -> int:
    release = fetch_release(args.channel, args.feed_url)
    payload = release.to_dict()
    if args.platform:
        payload["downloads"] = [release.get_download(args.platform).to_dict()]
    _print_json(payload)
    return 0


def _handle_cft_download(args: argparse.Namespace) -> int:
    release = fetch_release(args.channel, args.feed_url)
    manifest = download_chrome(release, args.platform, args.output)
    _print_json(manifest)
    return 0


def _capture_samples(
    sample_count: int,
    chrome_binary: Path | None,
    browser_mode: str,
    tls_url: str,
    http3_url: str,
) -> list[dict[str, Any]]:
    if sample_count < 1:
        raise ValueError("--samples must be at least one")
    samples: list[dict[str, Any]] = []
    with ChromeRunner(
        chrome_binary=chrome_binary,
        headless=browser_mode == "headless",
    ) as runner:
        for index in range(sample_count):
            print(
                f"Capturing fresh Chrome profile {index + 1}/{sample_count}...",
                file=sys.stderr,
            )
            samples.append(runner.capture_sample(tls_url, http3_url))
    return samples


def _observed_version(
    samples: list[dict[str, Any]],
    expected_version: str | None,
    allow_mismatch: bool = False,
) -> str:
    versions = {
        sample.get("browser", {}).get("version")
        for sample in samples
        if isinstance(sample.get("browser"), dict)
    }
    versions.discard(None)
    if len(versions) != 1:
        raise ValueError(
            f"Capture samples used inconsistent browser versions: {versions}"
        )
    observed_version = next(iter(versions), "")
    if (
        expected_version is not None
        and observed_version != expected_version
        and not allow_mismatch
    ):
        raise ValueError(
            f"Captured Chrome {observed_version}, expected exact {expected_version}; "
            "download that build or pass --allow-version-mismatch"
        )
    return observed_version


def _capture_summary(
    output: Path,
    observed_version: str,
    profile: dict[str, Any],
    status: str,
    distribution: str = "consumer-chrome",
) -> tuple[dict[str, Any], bool]:
    report = evaluate_readiness(profile, distribution)
    return (
        {
            "status": status,
            "bundle": str(output.resolve()),
            "browser_version": observed_version,
            "fingerprint_digest": profile["fingerprint_digest"],
            "sample_count": profile["sample_count"],
            "variant_count": profile["variant_count"],
            "distribution": distribution,
            **report.to_dict(),
        },
        report.ready,
    )


def _handle_capture(args: argparse.Namespace) -> int:
    release = None
    if not args.no_release_check:
        release = fetch_consumer_release(
            args.platform,
            args.channel,
            args.version_history_url,
        )
    samples = _capture_samples(
        args.samples,
        args.chrome_binary,
        args.browser_mode,
        args.tls_url,
        args.http3_url,
    )
    observed_version = _observed_version(
        samples,
        release.version if release is not None else None,
        args.allow_version_mismatch,
    )
    distribution = (
        "consumer-chrome"
        if release is not None and observed_version == release.version
        else "unverified"
    )
    profile = write_capture_bundle(
        args.output,
        samples,
        release,
        args.platform,
        distribution,
    )
    summary, ready = _capture_summary(
        args.output,
        observed_version,
        profile,
        "captured",
        distribution,
    )
    if release is not None:
        summary["release"] = release.to_dict()
    _print_json(summary)
    return 0 if ready else 1


def _handle_harvest(args: argparse.Namespace) -> int:
    if args.samples < 3:
        raise ValueError("harvest requires --samples of at least three")
    release = fetch_consumer_release(
        args.platform,
        args.channel,
        args.version_history_url,
    )
    bundle = (
        args.workspace
        / "captures"
        / release.channel.lower()
        / release.version
        / args.platform
    )
    if bundle.exists():
        profile = _load_profile(bundle)
        manifest = load_json(bundle / "manifest.json")
        expected = manifest.get("expected_release")
        if not isinstance(expected, dict) or expected.get("version") != release.version:
            raise ValueError(f"Existing bundle has inconsistent release data: {bundle}")
        if manifest.get("platform") != args.platform:
            raise ValueError(
                f"Existing bundle has inconsistent platform data: {bundle}"
            )
        identities = profile.get("browser_identities", [])
        identity = identities[0] if isinstance(identities, list) and identities else {}
        observed_version = (
            identity.get("version", "") if isinstance(identity, dict) else ""
        )
        distribution = str(manifest.get("browser_distribution", "unverified"))
        summary, ready = _capture_summary(
            bundle,
            observed_version,
            profile,
            "already_harvested",
            distribution,
        )
        summary["release"] = release.to_dict()
        _print_json(summary)
        return 0 if ready else 1

    samples = _capture_samples(
        args.samples,
        None,
        args.browser_mode,
        args.tls_url,
        args.http3_url,
    )
    observed_version = _observed_version(samples, release.version)
    profile = write_capture_bundle(
        bundle,
        samples,
        release,
        args.platform,
        "consumer-chrome",
    )
    summary, ready = _capture_summary(
        bundle,
        observed_version,
        profile,
        "captured",
        "consumer-chrome",
    )
    summary["release"] = release.to_dict()
    _print_json(summary)
    return 0 if ready else 1


def _handle_cft_harvest(args: argparse.Namespace) -> int:
    if args.samples < 3:
        raise ValueError("cft-harvest requires --samples of at least three")
    release = fetch_release(args.channel, args.feed_url)
    bundle = (
        args.workspace
        / "captures"
        / "chrome-for-testing"
        / release.channel.lower()
        / release.version
        / args.platform
    )
    if bundle.exists():
        profile = _load_profile(bundle)
        manifest = load_json(bundle / "manifest.json")
        summary, _ = _capture_summary(
            bundle,
            release.version,
            profile,
            "already_harvested",
            str(manifest.get("browser_distribution", "chrome-for-testing")),
        )
        summary["release"] = release.to_dict()
        _print_json(summary)
        return 1

    download = download_chrome(
        release,
        args.platform,
        args.workspace / "browsers",
    )
    binary = download.get("binary")
    if not isinstance(binary, str):
        raise ValueError("Chrome download manifest has no binary path")
    samples = _capture_samples(
        args.samples,
        Path(binary),
        args.browser_mode,
        args.tls_url,
        args.http3_url,
    )
    observed_version = _observed_version(samples, release.version)
    profile = write_capture_bundle(
        bundle,
        samples,
        release,
        args.platform,
        "chrome-for-testing",
    )
    summary, _ = _capture_summary(
        bundle,
        observed_version,
        profile,
        "captured",
        "chrome-for-testing",
    )
    summary["release"] = release.to_dict()
    _print_json(summary)
    return 1


def _handle_normalize(args: argparse.Namespace) -> int:
    profile = build_profile(load_bundle_samples(args.bundle))
    if args.output:
        if args.output.exists():
            raise FileExistsError(f"Refusing to overwrite profile: {args.output}")
        args.output.write_text(
            json.dumps(profile, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        _print_json(profile)
    return 0


def _handle_diff(args: argparse.Namespace) -> int:
    differences = diff_profiles(
        _load_comparable_fingerprint(args.before, args.transport_only),
        _load_comparable_fingerprint(args.after, args.transport_only),
    )
    _print_json(
        {
            "changed": bool(differences),
            "difference_count": len(differences),
            "differences": [item.to_dict() for item in differences],
        }
    )
    return 1 if differences else 0


def _handle_capabilities(args: argparse.Namespace) -> int:
    gaps = analyze_capabilities(_load_profile(args.profile))
    _print_json(
        {
            "representable": not gaps,
            "gaps": [gap.to_dict() for gap in gaps],
        }
    )
    return 1 if gaps else 0


def _handle_readiness(args: argparse.Namespace) -> int:
    manifest = load_json(args.bundle / "manifest.json")
    report = evaluate_readiness(
        _load_profile(args.bundle),
        str(manifest.get("browser_distribution", "unverified")),
    )
    _print_json(report.to_dict())
    return 0 if report.ready else 1


def _handle_candidate(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise FileExistsError(f"Refusing to overwrite native profile: {args.output}")
    profile = candidate_from_bundle(args.bundle, args.target)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(profile, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _print_json(
        {
            "status": "candidate_created",
            "target": profile["target"],
            "output": str(args.output.resolve()),
        }
    )
    return 0


def _handle_render(args: argparse.Namespace) -> int:
    profile = load_native_profile(args.profile)
    rendered = render_c_initializer(profile)
    if args.check_patch:
        existing = extract_initializer(
            args.check_patch.read_text(encoding="utf-8"),
            str(profile["target"]),
        )
        matches = rendered == existing
        _print_json(
            {
                "matches": matches,
                "patch": str(args.check_patch.resolve()),
                "profile": str(args.profile.resolve()),
                "target": profile["target"],
            }
        )
        return 0 if matches else 1
    if args.output:
        if args.output.exists():
            raise FileExistsError(f"Refusing to overwrite generated C: {args.output}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


def _handle_replay(args: argparse.Namespace) -> int:
    samples = capture_curl_samples(
        args.curl_binary,
        args.target,
        args.samples,
        args.tls_url,
        args.http3_url,
    )
    replay_profile, differences = compare_replay(args.chrome_bundle, samples)
    if args.output:
        write_capture_bundle(
            args.output,
            samples,
            distribution="curl-impersonate-candidate",
        )
    _print_json(
        {
            "matches": not differences,
            "target": args.target,
            "fingerprint_digest": replay_profile["fingerprint_digest"],
            "difference_count": len(differences),
            "differences": [difference.to_dict() for difference in differences],
        }
    )
    return 0 if not differences else 1


HANDLERS = {
    "release": _handle_release,
    "cft-release": _handle_cft_release,
    "cft-download": _handle_cft_download,
    "capture": _handle_capture,
    "harvest": _handle_harvest,
    "cft-harvest": _handle_cft_harvest,
    "normalize": _handle_normalize,
    "diff": _handle_diff,
    "capabilities": _handle_capabilities,
    "readiness": _handle_readiness,
    "candidate": _handle_candidate,
    "render": _handle_render,
    "replay": _handle_replay,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return HANDLERS[args.command](args)
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"fingerprint-harvester: {exc}", file=sys.stderr)
        return 2
