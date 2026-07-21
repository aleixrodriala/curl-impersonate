import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import quote
from urllib.request import urlopen
from zipfile import ZipFile

from .models import ChromeDownload, ChromeRelease, ConsumerChromeRelease


DEFAULT_RELEASE_FEED = (
    "https://googlechromelabs.github.io/chrome-for-testing/"
    "last-known-good-versions-with-downloads.json"
)

DEFAULT_VERSION_HISTORY_API = "https://versionhistory.googleapis.com/v1/chrome"

CONSUMER_PLATFORMS = {
    "android",
    "linux",
    "win64",
    "mac",
    "mac_arm64",
}

CHROME_BINARY_PATHS = {
    "linux64": "chrome-linux64/chrome",
    "mac-arm64": (
        "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/"
        "Google Chrome for Testing"
    ),
    "mac-x64": (
        "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/"
        "Google Chrome for Testing"
    ),
    "win32": "chrome-win32/chrome.exe",
    "win64": "chrome-win64/chrome.exe",
}


def parse_release_feed(payload: dict[str, object], channel: str) -> ChromeRelease:
    channels = payload.get("channels")
    if not isinstance(channels, dict):
        raise ValueError("Chrome release feed has no channels object")

    raw_release = channels.get(channel)
    if not isinstance(raw_release, dict):
        available = ", ".join(sorted(str(item) for item in channels))
        raise ValueError(f"Unknown Chrome channel {channel!r}; available: {available}")

    version = raw_release.get("version")
    revision = raw_release.get("revision")
    raw_downloads = raw_release.get("downloads")
    chrome_downloads = (
        raw_downloads.get("chrome") if isinstance(raw_downloads, dict) else None
    )
    if not isinstance(version, str) or not isinstance(revision, str):
        raise ValueError(f"Chrome {channel} release is missing version or revision")
    if not isinstance(chrome_downloads, list):
        raise ValueError(f"Chrome {channel} release is missing browser downloads")

    downloads: list[ChromeDownload] = []
    for item in chrome_downloads:
        if not isinstance(item, dict):
            continue
        platform = item.get("platform")
        url = item.get("url")
        if isinstance(platform, str) and isinstance(url, str):
            downloads.append(ChromeDownload(platform=platform, url=url))
    if not downloads:
        raise ValueError(f"Chrome {channel} release has no valid browser downloads")

    return ChromeRelease(
        channel=channel,
        version=version,
        revision=revision,
        downloads=tuple(downloads),
    )


def _fetch_json(url: str) -> dict[str, object]:
    with urlopen(url, timeout=30) as response:  # noqa: S310
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("Chrome release feed did not return a JSON object")
    return payload


def fetch_release(
    channel: str = "Stable",
    feed_url: str = DEFAULT_RELEASE_FEED,
    fetch_json: Callable[[str], dict[str, object]] = _fetch_json,
) -> ChromeRelease:
    return parse_release_feed(fetch_json(feed_url), channel)


def parse_version_history(
    payload: dict[str, object],
    platform: str,
    channel: str,
) -> ConsumerChromeRelease:
    versions = payload.get("versions")
    if not isinstance(versions, list) or not versions:
        raise ValueError(
            f"Chrome VersionHistory returned no {channel} versions for {platform}"
        )
    latest = versions[0]
    version = latest.get("version") if isinstance(latest, dict) else None
    if not isinstance(version, str) or not version:
        raise ValueError("Chrome VersionHistory response has no version")
    return ConsumerChromeRelease(
        channel=channel,
        version=version,
        platform=platform,
    )


def fetch_consumer_release(
    platform: str,
    channel: str = "stable",
    api_root: str = DEFAULT_VERSION_HISTORY_API,
    fetch_json: Callable[[str], dict[str, object]] = _fetch_json,
) -> ConsumerChromeRelease:
    if platform not in CONSUMER_PLATFORMS:
        available = ", ".join(sorted(CONSUMER_PLATFORMS))
        raise ValueError(
            f"Unsupported consumer Chrome platform {platform!r}; available: {available}"
        )
    normalized_channel = channel.lower()
    url = (
        f"{api_root.rstrip('/')}/platforms/{quote(platform)}/channels/"
        f"{quote(normalized_channel)}/versions?page_size=1&order_by=version%20desc"
    )
    return parse_version_history(
        fetch_json(url),
        platform=platform,
        channel=normalized_channel,
    )


def _safe_extract(archive: ZipFile, destination: Path) -> None:
    root = destination.resolve()
    for item in archive.infolist():
        target = (destination / item.filename).resolve()
        if target != root and root not in target.parents:
            raise ValueError(f"Unsafe path in Chrome archive: {item.filename}")
    archive.extractall(destination)
    for item in archive.infolist():
        mode = (item.external_attr >> 16) & 0o777
        target = destination / item.filename
        if mode and target.exists():
            target.chmod(mode)


def _download_file(url: str, destination: Path) -> str:
    digest = hashlib.sha256()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with urlopen(url, timeout=60) as response:  # noqa: S310
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    temporary.write(chunk)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    os.replace(temporary_path, destination)
    return digest.hexdigest()


def download_chrome(
    release: ChromeRelease,
    platform: str,
    output_dir: Path,
) -> dict[str, object]:
    if platform not in CHROME_BINARY_PATHS:
        available = ", ".join(sorted(CHROME_BINARY_PATHS))
        raise ValueError(
            f"Unsupported Chrome platform {platform!r}; available: {available}"
        )

    download = release.get_download(platform)
    release_dir = output_dir / release.version / platform
    archive_path = output_dir / release.version / f"chrome-{platform}.zip"
    manifest_path = release_dir / "harvest-download.json"
    binary_path = release_dir / CHROME_BINARY_PATHS[platform]

    if manifest_path.exists() and binary_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("version") == release.version:
            return manifest
        raise ValueError(f"Existing Chrome manifest is inconsistent: {manifest_path}")

    if release_dir.exists():
        raise FileExistsError(
            f"Refusing to overwrite incomplete Chrome download: {release_dir}"
        )

    sha256 = _download_file(download.url, archive_path)
    release_dir.mkdir(parents=True)
    try:
        with ZipFile(archive_path) as archive:
            _safe_extract(archive, release_dir)
        if not binary_path.exists():
            raise FileNotFoundError(f"Chrome archive did not contain {binary_path}")

        manifest: dict[str, object] = {
            "channel": release.channel,
            "version": release.version,
            "revision": release.revision,
            "platform": platform,
            "url": download.url,
            "sha256": sha256,
            "archive": str(archive_path.resolve()),
            "binary": str(binary_path.resolve()),
        }
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return manifest
    except Exception:
        # Keep the archive for diagnosis, but mark the extracted directory as unusable.
        failure_path = release_dir / "HARVEST_DOWNLOAD_FAILED"
        failure_path.write_text(
            "Chrome extraction failed; do not reuse this directory.\n"
        )
        raise
