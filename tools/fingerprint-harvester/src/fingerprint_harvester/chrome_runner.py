import json
import os
import shutil
import signal
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any


DEFAULT_TLS_URL = "https://tls.peet.ws/api/all"
DEFAULT_HTTP3_URL = "https://fp.impersonate.pro/api/http3"


class ChromeRunnerError(RuntimeError):
    pass


def find_chrome_binary(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return _validate_binary(explicit)

    candidates: list[Path] = []
    if sys.platform.startswith("linux"):
        for name in ("google-chrome", "google-chrome-stable"):
            path = shutil.which(name)
            if path:
                candidates.append(Path(path))
    elif sys.platform == "darwin":
        candidates.extend(
            [
                Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                Path.home()
                / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ]
        )
    elif sys.platform == "win32":
        for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            root = os.environ.get(variable)
            if root:
                candidates.append(Path(root) / "Google/Chrome/Application/chrome.exe")

    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    raise ChromeRunnerError(
        "Consumer Google Chrome was not found; pass --chrome-binary explicitly"
    )


def _validate_binary(binary: Path) -> Path:
    binary = binary.expanduser().resolve()
    if not binary.is_file():
        raise ChromeRunnerError(f"Chrome binary does not exist: {binary}")
    if not os.access(binary, os.X_OK):
        raise ChromeRunnerError(f"Chrome binary is not executable: {binary}")
    return binary


def _wait_for_port_file(
    port_file: Path,
    process: subprocess.Popen[bytes],
    timeout: int,
) -> int:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ChromeRunnerError(
                f"Chrome exited before exposing CDP with status {process.returncode}"
            )
        try:
            lines = port_file.read_text(encoding="utf-8").splitlines()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            lines = []
        if lines:
            try:
                return int(lines[0])
            except ValueError:
                pass
        time.sleep(0.05)
    raise ChromeRunnerError(f"Chrome did not expose CDP within {timeout} seconds")


def _read_json_body(page: Any, attempts: int = 30) -> dict[str, Any]:
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            payload = json.loads(page.locator("body").inner_text(timeout=2_000))
            if isinstance(payload, dict):
                return payload
            last_error = ValueError("collector response was not a JSON object")
        except (json.JSONDecodeError, TimeoutError, ValueError) as exc:
            last_error = exc
        page.wait_for_timeout(100)
    raise ChromeRunnerError(f"Collector did not return complete JSON: {last_error}")


class ChromeRunner:
    def __init__(
        self,
        chrome_binary: Path | None = None,
        headless: bool = True,
        launch_timeout: int = 30,
        connect_timeout_ms: int = 30_000,
    ) -> None:
        self.requested_binary = chrome_binary
        self.headless = headless
        self.launch_timeout = launch_timeout
        self.connect_timeout_ms = connect_timeout_ms
        self.binary: Path | None = None
        self._playwright_manager: Any = None
        self._playwright: Any = None

    def __enter__(self) -> "ChromeRunner":
        self.binary = find_chrome_binary(self.requested_binary)
        if (
            not self.headless
            and sys.platform.startswith("linux")
            and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        ):
            raise ChromeRunnerError(
                "Headful Chrome requires DISPLAY or WAYLAND_DISPLAY on Linux"
            )
        if sys.platform.startswith("linux") and os.geteuid() == 0:
            raise ChromeRunnerError(
                "Run the harvester as a non-root user so Chrome keeps its sandbox"
            )
        try:
            from playwright.sync_api import sync_playwright
        except ModuleNotFoundError as exc:
            raise ChromeRunnerError(
                "Playwright is required; install with `uv sync --extra harvester`"
            ) from exc
        self._playwright_manager = sync_playwright()
        self._playwright = self._playwright_manager.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._playwright is not None:
            self._playwright.stop()
        self._playwright = None
        self._playwright_manager = None

    def _launch_arguments(self, profile: Path, initial_url: str) -> list[str]:
        if self.binary is None:
            raise ChromeRunnerError("ChromeRunner must be used as a context manager")
        arguments = [
            str(self.binary),
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        if self.headless:
            arguments.extend(["--headless=new", "--window-size=1920,1080"])
        arguments.append(initial_url)
        return arguments

    def _launch(
        self,
        profile: Path,
        initial_url: str,
    ) -> subprocess.Popen[bytes]:
        with suppress(FileNotFoundError):
            (profile / "DevToolsActivePort").unlink()
        options: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        return subprocess.Popen(
            self._launch_arguments(profile, initial_url),
            **options,
        )

    def _stop_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                capture_output=True,
            )
        else:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)

    def _open_url_from_command_line(self, profile: Path, url: str) -> None:
        options: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        launcher = subprocess.Popen(self._launch_arguments(profile, url), **options)
        try:
            launcher.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._stop_process(launcher)

    @staticmethod
    def _wait_for_page(context: Any, url: str, timeout: int = 10) -> Any:
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
            context.pages[0].wait_for_timeout(100)
        raise ChromeRunnerError(f"Chrome did not open collector URL within {timeout}s")

    def capture_sample(
        self,
        tls_url: str = DEFAULT_TLS_URL,
        http3_url: str = DEFAULT_HTTP3_URL,
    ) -> dict[str, Any]:
        if self._playwright is None or self.binary is None:
            raise ChromeRunnerError("ChromeRunner must be used as a context manager")
        with TemporaryDirectory(prefix="curl-cffi-fingerprint-") as temporary:
            profile = Path(temporary) / "profile"
            process = self._launch(profile, tls_url)
            browser = None
            try:
                port = _wait_for_port_file(
                    profile / "DevToolsActivePort",
                    process,
                    self.launch_timeout,
                )
                browser = self._playwright.chromium.connect_over_cdp(
                    f"http://127.0.0.1:{port}",
                    is_local=True,
                    no_defaults=True,
                    timeout=self.connect_timeout_ms,
                )
                if not browser.contexts or not browser.contexts[0].pages:
                    raise ChromeRunnerError("Chrome exposed no default page over CDP")
                context = browser.contexts[0]
                page = self._wait_for_page(context, tls_url)
                tls_payload = _read_json_body(page)
                browser_data = {
                    "version": browser.version,
                    "user_agent": page.evaluate("navigator.userAgent"),
                    "user_agent_data": page.evaluate(
                        "navigator.userAgentData && navigator.userAgentData.toJSON()"
                    ),
                    "platform": page.evaluate("navigator.platform"),
                    "language": page.evaluate("navigator.language"),
                    "mode": "headless" if self.headless else "headful",
                }

                page.goto("chrome://version", wait_until="domcontentloaded")
                version_text = page.locator("body").inner_text(timeout=5_000)

                http3_payload = None
                for _ in range(6):
                    self._open_url_from_command_line(profile, http3_url)
                    http3_page = self._wait_for_page(context, http3_url)
                    candidate = _read_json_body(http3_page)
                    if candidate.get("protocol") == "http3":
                        http3_payload = candidate
                        break
                    http3_page.close()
                if http3_payload is None:
                    raise ChromeRunnerError(
                        "HTTP/3 was not negotiated after six command-line launches"
                    )

                return {
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                    "browser": browser_data,
                    "tls_http2": tls_payload,
                    "http3": http3_payload,
                    "chrome_version_page": version_text,
                    "launch": {
                        "mode": browser_data["mode"],
                        "arguments": [
                            argument
                            if not argument.startswith("--user-data-dir=")
                            else "--user-data-dir=REDACTED"
                            for argument in self._launch_arguments(profile, tls_url)[1:]
                        ],
                        "collector_navigation": "command-line",
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
                self._stop_process(process)
