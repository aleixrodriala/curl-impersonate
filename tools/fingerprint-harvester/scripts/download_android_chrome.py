#!/usr/bin/env python3
"""Download Google-signed Android Chrome packages for fingerprint capture."""

import argparse
import json
from pathlib import Path

from gplaydl.api import get_delivery, get_details, purchase
from gplaydl.auth import load_cached_auth
from gplaydl.download import DownloadSpec, download_batch

from fingerprint_harvester.android_apkmirror import (
    download_latest_x86_64_chrome,
)
from fingerprint_harvester.android_play import SUPPORTED_ARCHITECTURES


CHROME_PACKAGE = "com.android.chrome"
TRICHROME_PACKAGE = "com.google.android.trichromelibrary"


def _delivery_specs(
    package: str,
    version_code: int,
    auth: dict,
    output: Path,
    prefix: str,
    include_splits: bool,
) -> list[DownloadSpec]:
    delivery = get_delivery(package, version_code, auth)
    specs = [
        DownloadSpec(
            url=delivery.download_url,
            dest=output / f"{prefix}-base.apk",
            cookies=delivery.cookies,
            label=f"{prefix}-base.apk",
        )
    ]
    if include_splits:
        specs.extend(
            DownloadSpec(
                url=split.url,
                dest=output / f"{prefix}-{split.name}.apk",
                label=f"{prefix}-{split.name}.apk",
            )
            for split in delivery.splits
        )
    return specs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", choices=SUPPORTED_ARCHITECTURES, required=True)
    parser.add_argument("--chrome-binary", type=Path)
    parser.add_argument("--headless-browser", action="store_true")
    args = parser.parse_args()

    if args.arch == "x86_64":
        if args.chrome_binary is None:
            raise ValueError("x86_64 downloads require --chrome-binary")
        args.output.mkdir(parents=True, exist_ok=True)
        metadata = download_latest_x86_64_chrome(
            args.output,
            args.chrome_binary.expanduser().resolve(),
            headless=args.headless_browser,
        )
        (args.output / "metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(metadata, sort_keys=True))
        return 0

    auth = load_cached_auth(args.arch)
    if not auth or not auth.get("authToken"):
        raise RuntimeError(f"Google Play authentication is unavailable for {args.arch}")
    details = get_details(CHROME_PACKAGE, auth)
    purchase(CHROME_PACKAGE, details.version_code, auth)

    args.output.mkdir(parents=True, exist_ok=True)
    specs = _delivery_specs(
        TRICHROME_PACKAGE,
        details.version_code,
        auth,
        args.output,
        "trichrome",
        include_splits=False,
    )
    specs.extend(
        _delivery_specs(
            CHROME_PACKAGE,
            details.version_code,
            auth,
            args.output,
            "chrome",
            include_splits=True,
        )
    )
    download_batch(specs)

    metadata = {
        "package": CHROME_PACKAGE,
        "architecture": args.arch,
        "version": details.version_string,
        "version_code": details.version_code,
    }
    (args.output / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
