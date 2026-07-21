import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from urllib.parse import urlparse
from zipfile import BadZipFile, ZipFile

import httpx

from .releases import fetch_consumer_versions


APKMIRROR_ROOT = "https://www.apkmirror.com"
CHROME_CERTIFICATE_SHA256 = (
    "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"
)
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024
MAX_EXTRACTED_BYTES = 800 * 1024 * 1024


class AndroidPackageUnavailable(RuntimeError):
    pass


def chrome_release_url(version: str) -> str:
    slug = version.replace(".", "-")
    return f"{APKMIRROR_ROOT}/apk/google-inc/chrome/google-chrome-{slug}-release/"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_archive_member(archive: ZipFile, member: str, destination: Path) -> None:
    info = archive.getinfo(member)
    if info.file_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"Android package member is too large: {member}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="wb",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with archive.open(info) as source:
                shutil.copyfileobj(source, temporary, length=1024 * 1024)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    os.replace(temporary_path, destination)


def extract_chrome_apkm(
    archive_path: Path,
    output: Path,
    expected_version: str,
    expected_version_code: int,
) -> dict[str, object]:
    try:
        archive = ZipFile(archive_path)
    except BadZipFile as exc:
        raise ValueError(
            "Downloaded Android Chrome bundle is not an APKM archive"
        ) from exc

    with archive:
        members = archive.namelist()
        extracted_size = sum(archive.getinfo(name).file_size for name in members)
        if extracted_size > MAX_EXTRACTED_BYTES:
            raise ValueError("Downloaded Android Chrome bundle is unexpectedly large")
        if "info.json" not in members or "base.apk" not in members:
            raise ValueError("Android Chrome bundle is missing info.json or base.apk")
        info = json.loads(archive.read("info.json"))
        if not isinstance(info, dict):
            raise ValueError("Android Chrome bundle metadata is not an object")
        if info.get("pname") != "com.android.chrome":
            raise ValueError("Android Chrome bundle has an unexpected package name")
        if info.get("release_version") != expected_version:
            raise ValueError("Android Chrome bundle has an unexpected version")
        if str(info.get("versioncode")) != str(expected_version_code):
            raise ValueError("Android Chrome bundle has an unexpected version code")
        arches = info.get("arches")
        if not isinstance(arches, list) or "x86_64" not in arches:
            raise ValueError("Android Chrome bundle does not declare x86_64 support")

        selected = ["base.apk"]
        selected.extend(
            name
            for name in members
            if name == "split_config.en.apk"
            or (name.startswith("split_") and not name.startswith("split_config."))
        )
        selected = list(dict.fromkeys(selected))
        for name in selected:
            if name == "base.apk":
                destination = output / "chrome-base.apk"
            else:
                destination = output / f"chrome-{name.removeprefix('split_')}"
            if destination.exists():
                raise FileExistsError(f"Refusing to overwrite {destination}")
            _copy_archive_member(archive, name, destination)

    base_apk = output / "chrome-base.apk"
    with ZipFile(base_apk) as base:
        try:
            native_library = base.getinfo("lib/x86_64/libchrome.so")
        except KeyError as exc:
            raise AndroidPackageUnavailable(
                "The newest x86_64 Chrome bundle still requires Trichrome"
            ) from exc
        if native_library.file_size == 0:
            raise AndroidPackageUnavailable(
                "The x86_64 Chrome native library is only a placeholder"
            )

    return {
        "package": "com.android.chrome",
        "architecture": "x86_64",
        "version": expected_version,
        "version_code": expected_version_code,
        "source": "apkmirror-google-signed",
        "archive_sha256": _sha256_file(archive_path),
        "expected_certificate_sha256": CHROME_CERTIFICATE_SHA256,
        "standalone_native_library": "lib/x86_64/libchrome.so",
    }


def _wait_for_variants(page: object, timeout_ms: int = 30_000) -> bool:
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if page.locator(".variants-table .table-row").count():
            return True
        if "Page Not Found" in page.title():
            return False
        page.wait_for_timeout(250)
    title = page.title()
    raise AndroidPackageUnavailable(
        f"APKMirror did not expose the Chrome variants table; page title: {title!r}"
    )


def _x86_64_variant(page: object) -> tuple[str, int] | None:
    rows = page.locator(".variants-table .table-row")
    matches: list[tuple[int, str, int]] = []
    for index in range(rows.count()):
        row = rows.nth(index)
        text = " ".join(row.inner_text().split())
        if "x86_64" not in text:
            continue
        link = row.locator('a[href*="android-apk-download/"]').first
        if not link.count():
            continue
        codes = re.findall(r"\b\d{9,12}\b", text)
        if not codes:
            continue
        architecture_rank = 0 if "x86 + x86_64" not in text else 1
        matches.append(
            (
                architecture_rank,
                link.evaluate("element => element.href"),
                int(codes[0]),
            )
        )
    if not matches:
        return None
    _, url, version_code = min(matches)
    return url, version_code


def _download_signed_target(page: object, context: object, destination: Path) -> None:
    download_page = page.locator('a[href*="/download/?key="]').first
    download_page.wait_for(state="attached", timeout=30_000)
    page.goto(
        download_page.evaluate("element => element.href"),
        wait_until="domcontentloaded",
        timeout=60_000,
    )
    final_link = page.locator('a[href*="download.php"]').first
    final_link.wait_for(state="attached", timeout=30_000)

    state: dict[str, object] = {}
    session = context.new_cdp_session(page)
    session.on("Browser.downloadWillBegin", lambda params: state.update(params))
    session.send(
        "Browser.setDownloadBehavior",
        {"behavior": "cancel", "eventsEnabled": True},
    )
    final_link.evaluate("element => element.click()")
    deadline = time.monotonic() + 30
    while "url" not in state and time.monotonic() < deadline:
        page.wait_for_timeout(100)
    session.detach()
    url = state.get("url")
    if not isinstance(url, str):
        raise AndroidPackageUnavailable("APKMirror did not begin the package download")
    hostname = (urlparse(url).hostname or "").lower()
    if not hostname.endswith(".r2.cloudflarestorage.com"):
        raise ValueError(f"APKMirror redirected to an unexpected host: {hostname}")

    user_agent = page.evaluate("navigator.userAgent")
    written = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(
        mode="wb",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
        try:
            with httpx.stream(
                "GET",
                url,
                headers={"User-Agent": user_agent},
                follow_redirects=True,
                timeout=300,
            ) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes(1024 * 1024):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise ValueError(
                            "Android Chrome download is unexpectedly large"
                        )
                    temporary.write(chunk)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    os.replace(temporary_path, destination)
    if written == 0:
        destination.unlink(missing_ok=True)
        raise ValueError("Android Chrome download was empty")


def download_latest_x86_64_chrome(
    output: Path,
    chrome_binary: Path,
    headless: bool = False,
    version_limit: int = 20,
) -> dict[str, object]:
    if not chrome_binary.is_file():
        raise FileNotFoundError(f"Chrome binary does not exist: {chrome_binary}")
    versions = fetch_consumer_versions("android", page_size=version_limit)

    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:
        raise RuntimeError("Playwright is required to download Android Chrome") from exc

    with TemporaryDirectory(prefix="android-chrome-download-") as temporary:
        archive_path = Path(temporary) / "chrome.apkm"
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                executable_path=str(chrome_binary),
                headless=headless,
            )
            try:
                context = browser.new_context(accept_downloads=False)
                page = context.new_page()
                page.set_default_timeout(30_000)
                for version in versions:
                    page.goto(
                        chrome_release_url(version),
                        wait_until="domcontentloaded",
                        timeout=60_000,
                    )
                    if not _wait_for_variants(page):
                        continue
                    variant = _x86_64_variant(page)
                    if variant is None:
                        continue
                    variant_url, version_code = variant
                    page.goto(
                        variant_url,
                        wait_until="domcontentloaded",
                        timeout=60_000,
                    )
                    _download_signed_target(page, context, archive_path)
                    return extract_chrome_apkm(
                        archive_path,
                        output,
                        expected_version=version,
                        expected_version_code=version_code,
                    )
            finally:
                browser.close()
    raise AndroidPackageUnavailable(
        f"No standalone x86_64 Chrome bundle found in {version_limit} releases"
    )
