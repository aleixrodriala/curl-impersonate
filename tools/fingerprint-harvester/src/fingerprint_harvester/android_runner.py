import re
import shutil
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


class AndroidChromeRunner:
    def __init__(
        self,
        adb: Path | None = None,
        serial: str | None = None,
        user_id: int = 0,
        package: str = "com.android.chrome",
        reset_profile: bool = True,
        connect_timeout_ms: int = 30_000,
    ) -> None:
        self.requested_adb = adb
        self.serial = serial
        self.user_id = user_id
        self.package = package
        self.reset_profile = reset_profile
        self.connect_timeout_ms = connect_timeout_ms
        self.adb = ""
        self.package_version = ""
        self._forwarded_ports: set[int] = set()
        self._playwright_manager: Any = None
        self._playwright: Any = None

    def _adb(self, *arguments: str, timeout: int = 30) -> str:
        command = [self.adb]
        if self.serial:
            command.extend(("-s", self.serial))
        command.extend(arguments)
        completed = subprocess.run(
            command,
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
        if self.serial and self.serial not in devices:
            raise AndroidChromeRunnerError(
                f"Requested Android device is not ready: {self.serial}"
            )
        if not self.serial and len(devices) != 1:
            raise AndroidChromeRunnerError(
                f"Expected exactly one ready Android device, found {devices}"
            )
        if not self.serial:
            self.serial = devices[0]
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
        if self.reset_profile:
            self._enable_test_launch()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._playwright is not None:
            self._playwright.stop()
        if self.adb:
            for port in self._forwarded_ports:
                with suppress(Exception):
                    self._adb("forward", "--remove", f"tcp:{port}")
            if self.reset_profile:
                with suppress(Exception):
                    self._adb(
                        "shell",
                        "am",
                        "force-stop",
                        "--user",
                        str(self.user_id),
                        self.package,
                    )
                with suppress(Exception):
                    self._adb("shell", "am", "clear-debug-app")
        self._playwright = None
        self._playwright_manager = None

    def _enable_test_launch(self) -> None:
        self._adb(
            "shell",
            "settings",
            "put",
            "global",
            "adb_enabled",
            "1",
        )
        self._adb("shell", "am", "set-debug-app", "--persistent", self.package)
        command_line = (
            "chrome --disable-fre --enable-remote-debugging "
            "--no-default-browser-check "
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
            "--user",
            str(self.user_id),
            "-W",
            "-a",
            "android.intent.action.VIEW",
            "-d",
            url,
            "-n",
            f"{self.package}/com.google.android.apps.chrome.Main",
            timeout=60,
        )

    def _wait_for_debug_socket(self, timeout: int = 30) -> None:
        deadline = time.monotonic() + timeout
        sockets = ""
        while time.monotonic() < deadline:
            sockets = self._adb("shell", "cat", "/proc/net/unix")
            if "@chrome_devtools_remote" in sockets:
                return
            time.sleep(0.2)
        diagnostics = []
        commands = (
            (
                "adb_enabled",
                ("shell", "settings", "get", "global", "adb_enabled"),
            ),
            (
                "development_settings_enabled",
                (
                    "shell",
                    "settings",
                    "get",
                    "global",
                    "development_settings_enabled",
                ),
            ),
            ("debug_app", ("shell", "settings", "get", "global", "debug_app")),
            (
                "command_line",
                ("shell", "cat", "/data/local/tmp/chrome-command-line"),
            ),
            ("chrome_pid", ("shell", "pidof", self.package)),
            ("activity", ("shell", "dumpsys", "activity", "top")),
            (
                "logcat",
                ("logcat", "-d", "-t", "200", "chromium:V", "*:S"),
            ),
        )
        for label, arguments in commands:
            try:
                value = self._adb(*arguments, timeout=10)
            except (subprocess.SubprocessError, OSError) as exc:
                value = f"<unavailable: {exc}>"
            diagnostics.append(f"{label}: {value}")
        devtools_sockets = [
            line for line in sockets.splitlines() if "devtools" in line.lower()
        ]
        diagnostics.append(
            "devtools_sockets: " + ("\n".join(devtools_sockets) or "<none>")
        )
        raise AndroidChromeRunnerError(
            f"Android Chrome did not expose CDP within {timeout} seconds\n"
            + "\n".join(diagnostics)
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

    @staticmethod
    def _navigate_as_typed(context: Any, page: Any, url: str) -> None:
        session = context.new_cdp_session(page)
        try:
            session.send(
                "Page.navigate",
                {"url": url, "transitionType": "typed"},
            )
        finally:
            session.detach()

    def capture_sample(
        self,
        tls_url: str = DEFAULT_TLS_URL,
        http3_url: str = DEFAULT_HTTP3_URL,
    ) -> dict[str, Any]:
        if self._playwright is None:
            raise AndroidChromeRunnerError(
                "AndroidChromeRunner must be used as a context manager"
            )
        if self.reset_profile:
            self._adb(
                "shell",
                "am",
                "force-stop",
                "--user",
                str(self.user_id),
                self.package,
            )
            self._adb(
                "shell",
                "pm",
                "clear",
                "--user",
                str(self.user_id),
                self.package,
            )
            self._enable_test_launch()
            self._open_url("about:blank")
        self._wait_for_debug_socket()
        port = int(
            self._adb(
                "forward",
                "tcp:0",
                "localabstract:chrome_devtools_remote",
            )
        )
        self._forwarded_ports.add(port)
        browser = None
        capture_pages: list[Any] = []
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
            if self.reset_profile:
                page = context.pages[-1]
            else:
                page = context.new_page()
                capture_pages.append(page)
            self._navigate_as_typed(context, page, tls_url)
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
                http3_page = context.new_page()
                capture_pages.append(http3_page)
                self._navigate_as_typed(context, http3_page, http3_url)
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
                    "collector_navigation": (
                        "android-view-intent-and-cdp-typed-navigation"
                        if self.reset_profile
                        else "cdp-typed-navigation"
                    ),
                    "profile_reset": self.reset_profile,
                },
                "source_urls": {
                    "tls_http2": tls_url,
                    "http3": http3_url,
                },
            }
        finally:
            for page in capture_pages:
                with suppress(Exception):
                    page.close()
            if browser is not None:
                with suppress(Exception):
                    browser.close()
            with suppress(Exception):
                self._adb("forward", "--remove", f"tcp:{port}")
            self._forwarded_ports.discard(port)
            if self.reset_profile:
                with suppress(Exception):
                    self._adb(
                        "shell",
                        "am",
                        "force-stop",
                        "--user",
                        str(self.user_id),
                        self.package,
                    )
