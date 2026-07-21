import re
import shutil
import socket
import subprocess
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .chrome_runner import (
    DEFAULT_HTTP3_URL,
    DEFAULT_TLS_URL,
    ChromeRunnerError,
    _read_json_body,
)


class AndroidChromeRunnerError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class AndroidChromeRunner:
    def __init__(
        self,
        adb: Path | None = None,
        package: str = "com.android.chrome",
        connect_timeout_ms: int = 30_000,
    ) -> None:
        self.requested_adb = adb
        self.package = package
        self.connect_timeout_ms = connect_timeout_ms
        self.adb = ""
        self.package_version = ""
        self._playwright_manager: Any = None
        self._playwright: Any = None

    def _adb(self, *arguments: str, timeout: int = 30) -> str:
        completed = subprocess.run(
            [self.adb, *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return completed.stdout.strip()

    def __enter__(self) -> "AndroidChromeRunner":
        requested = str(self.requested_adb) if self.requested_adb else "adb"
        adb = shutil.which(requested)
        if adb is None:
            raise AndroidChromeRunnerError(f"ADB was not found: {requested}")
        self.adb = str(Path(adb).resolve())
        devices = [
            line.split()[0]
            for line in self._adb("devices").splitlines()[1:]
            if line.endswith("\tdevice")
        ]
        if len(devices) != 1:
            raise AndroidChromeRunnerError(
                f"Expected exactly one ready Android device, found {devices}"
            )
        package_info = self._adb("shell", "dumpsys", "package", self.package)
        match = re.search(r"\bversionName=([^\s]+)", package_info)
        if match is None:
            raise AndroidChromeRunnerError(
                f"Consumer Chrome package is not installed: {self.package}"
            )
        self.package_version = match.group(1)
        try:
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as exc:
            raise AndroidChromeRunnerError(
                "Playwright is required; install the harvester environment"
            ) from exc
        self._playwright_manager = sync_playwright()
        self._playwright = self._playwright_manager.start()
        self._enable_test_launch()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._playwright is not None:
            self._playwright.stop()
        if self.adb:
            with suppress(Exception):
                self._adb("forward", "--remove-all")
            with suppress(Exception):
                self._adb("shell", "am", "force-stop", self.package)
            with suppress(Exception):
                self._adb("shell", "am", "clear-debug-app")
        self._playwright = None
        self._playwright_manager = None

    def _enable_test_launch(self) -> None:
        self._adb("shell", "am", "set-debug-app", "--persistent", self.package)
        command_line = (
            "chrome --disable-fre --no-default-browser-check "
            "--no-first-run --disable-first-run-experience\n"
        )
        with NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as file:
            command_line_path = Path(file.name)
            file.write(command_line)
        try:
            self._adb(
                "push",
                str(command_line_path),
                "/data/local/tmp/chrome-command-line",
            )
        finally:
            command_line_path.unlink(missing_ok=True)

    def _open_url(self, url: str) -> None:
        self._adb(
            "shell",
            "am",
            "start",
            "-W",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            url,
            self.package,
            timeout=60,
        )

    def _wait_for_debug_socket(self, timeout: int = 30) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            sockets = self._adb("shell", "cat", "/proc/net/unix")
            if "@chrome_devtools_remote" in sockets:
                return
            time.sleep(0.2)
        raise AndroidChromeRunnerError(
            f"Android Chrome did not expose CDP within {timeout} seconds"
        )

    @staticmethod
    def _wait_for_page(context: Any, url: str, timeout: int = 20) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            page = next(
                (
                    candidate
                    for candidate in reversed(context.pages)
                    if candidate.url.rstrip("/") == url.rstrip("/")
                ),
                None,
            )
            if page is not None:
                return page
            time.sleep(0.1)
        observed = [page.url for page in context.pages]
        raise AndroidChromeRunnerError(
            f"Android Chrome did not open {url}; observed {observed}"
        )

    def capture_sample(
        self,
        tls_url: str = DEFAULT_TLS_URL,
        http3_url: str = DEFAULT_HTTP3_URL,
    ) -> dict[str, Any]:
        if self._playwright is None:
            raise AndroidChromeRunnerError(
                "AndroidChromeRunner must be used as a context manager"
            )
        self._adb("shell", "am", "force-stop", self.package)
        self._adb("shell", "pm", "clear", self.package)
        self._enable_test_launch()
        self._open_url(tls_url)
        self._wait_for_debug_socket()
        port = _free_port()
        self._adb(
            "forward",
            f"tcp:{port}",
            "localabstract:chrome_devtools_remote",
        )
        browser = None
        try:
            browser = self._playwright.chromium.connect_over_cdp(
                f"http://127.0.0.1:{port}",
                is_local=True,
                no_defaults=True,
                timeout=self.connect_timeout_ms,
            )
            if not browser.contexts or not browser.contexts[0].pages:
                raise AndroidChromeRunnerError("Android Chrome exposed no CDP page")
            context = browser.contexts[0]
            page = self._wait_for_page(context, tls_url)
            tls_payload = _read_json_body(page)
            browser_data = {
                "version": browser.version,
                "package_version": self.package_version,
                "user_agent": page.evaluate("navigator.userAgent"),
                "user_agent_data": page.evaluate(
                    "navigator.userAgentData && navigator.userAgentData.toJSON()"
                ),
                "platform": page.evaluate("navigator.platform"),
                "language": page.evaluate("navigator.language"),
                "mode": "headful",
            }

            http3_payload = None
            for _ in range(6):
                self._open_url(http3_url)
                http3_page = self._wait_for_page(context, http3_url)
                try:
                    candidate = _read_json_body(http3_page)
                except ChromeRunnerError:
                    continue
                if candidate.get("protocol") == "http3":
                    http3_payload = candidate
                    break
            if http3_payload is None:
                raise AndroidChromeRunnerError(
                    "Android Chrome did not negotiate HTTP/3 after six tries"
                )

            return {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "browser": browser_data,
                "tls_http2": tls_payload,
                "http3": http3_payload,
                "launch": {
                    "mode": "headful",
                    "automation": "adb-cdp-attach",
                    "package": self.package,
                    "collector_navigation": "android-view-intent",
                },
                "source_urls": {
                    "tls_http2": tls_url,
                    "http3": http3_url,
                },
            }
        finally:
            if browser is not None:
                with suppress(Exception):
                    browser.close()
            with suppress(Exception):
                self._adb("forward", "--remove", f"tcp:{port}")
            with suppress(Exception):
                self._adb("shell", "am", "force-stop", self.package)
