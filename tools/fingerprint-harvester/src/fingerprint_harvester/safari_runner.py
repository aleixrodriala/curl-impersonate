import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .chrome_runner import DEFAULT_HTTP3_URL, DEFAULT_TLS_URL


class SafariRunnerError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _safari_version(driver: Path) -> tuple[str, str]:
    completed = subprocess.run(
        [str(driver), "--version"],
        check=True,
        capture_output=True,
        text=True,
    )
    output = (completed.stdout or completed.stderr).strip()
    match = re.search(r"Safari\s+([0-9.]+)\s+\(([^)]+)\)", output)
    if match is None:
        raise SafariRunnerError(f"Could not parse SafariDriver version: {output}")
    return match.group(1), match.group(2)


class _WebDriverClient:
    def __init__(self, port: int) -> None:
        self.root = f"http://127.0.0.1:{port}"

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        timeout: int = 90,
    ) -> Any:
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.root}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=timeout) as response:  # noqa: S310
                result = json.load(response)
        except HTTPError as exc:
            details = exc.read().decode(errors="replace")
            raise SafariRunnerError(
                f"SafariDriver {method} {path} failed: {exc.code} {details}"
            ) from exc
        if not isinstance(result, dict):
            raise SafariRunnerError("SafariDriver returned a non-object response")
        value = result.get("value")
        if isinstance(value, dict) and value.get("error"):
            raise SafariRunnerError(
                f"SafariDriver {value.get('error')}: {value.get('message', '')}"
            )
        return value

    def wait_until_ready(
        self,
        process: subprocess.Popen[bytes],
        timeout: int = 30,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise SafariRunnerError(
                    f"SafariDriver exited with status {process.returncode}"
                )
            try:
                self.request("GET", "/status", timeout=2)
                return
            except (SafariRunnerError, URLError, TimeoutError):
                time.sleep(0.2)
        raise SafariRunnerError(f"SafariDriver was not ready within {timeout} seconds")

    def create_session(
        self, capabilities: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        value = self.request(
            "POST",
            "/session",
            {"capabilities": {"alwaysMatch": capabilities}},
        )
        if not isinstance(value, dict):
            raise SafariRunnerError("SafariDriver session response is invalid")
        session_id = value.get("sessionId")
        negotiated = value.get("capabilities")
        if not isinstance(session_id, str) or not isinstance(negotiated, dict):
            raise SafariRunnerError("SafariDriver did not return session capabilities")
        self.request(
            "POST",
            f"/session/{session_id}/timeouts",
            {"pageLoad": 60_000, "script": 10_000},
        )
        return session_id, negotiated

    def navigate(self, session_id: str, url: str) -> None:
        self.request("POST", f"/session/{session_id}/url", {"url": url})

    def execute(self, session_id: str, script: str) -> Any:
        return self.request(
            "POST",
            f"/session/{session_id}/execute/sync",
            {"script": script, "args": []},
        )

    def close_session(self, session_id: str) -> None:
        self.request("DELETE", f"/session/{session_id}", timeout=15)


def _read_json_body(
    client: _WebDriverClient,
    session_id: str,
    attempts: int = 30,
) -> dict[str, Any]:
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            body = client.execute(
                session_id,
                "return document.body ? document.body.innerText : '';",
            )
            payload = json.loads(str(body))
            if isinstance(payload, dict):
                return payload
            last_error = ValueError("collector response was not a JSON object")
        except (json.JSONDecodeError, SafariRunnerError, ValueError) as exc:
            last_error = exc
        time.sleep(0.2)
    raise SafariRunnerError(f"Collector did not return complete JSON: {last_error}")


class SafariRunner:
    def __init__(
        self,
        platform: str = "macos",
        driver: Path = Path("/usr/bin/safaridriver"),
        ios_version: str | None = None,
        ios_device_name: str | None = None,
        ios_device_udid: str | None = None,
        ios_device_type: str = "iPhone",
    ) -> None:
        if platform not in {"macos", "ios"}:
            raise ValueError("Safari platform must be 'macos' or 'ios'")
        self.platform = platform
        self.driver = driver
        self.ios_version = ios_version
        self.ios_device_name = ios_device_name
        self.ios_device_udid = ios_device_udid
        self.ios_device_type = ios_device_type
        self.version = ""
        self.build = ""
        self._process: subprocess.Popen[bytes] | None = None
        self._client: _WebDriverClient | None = None
        self._log_handle: BinaryIO | None = None
        self._log_path: Path | None = None

    def __enter__(self) -> "SafariRunner":
        if sys.platform != "darwin":
            raise SafariRunnerError("Real Safari capture requires macOS")
        if not self.driver.is_file() or not os.access(self.driver, os.X_OK):
            raise SafariRunnerError(f"SafariDriver is not executable: {self.driver}")
        self.version, self.build = _safari_version(self.driver)
        port = _free_port()
        log_directory = (
            Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
            / "fingerprint-harvester"
            / "safaridriver"
        )
        log_directory.mkdir(parents=True, exist_ok=True)
        self._log_path = log_directory / f"safaridriver-{os.getpid()}-{port}.log"
        self._log_handle = self._log_path.open("wb")
        self._process = subprocess.Popen(
            [str(self.driver), "--diagnose", "--port", str(port)],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self._client = _WebDriverClient(port)
        self._client.wait_until_ready(self._process)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            with suppress(subprocess.TimeoutExpired):
                self._process.wait(timeout=10)
            if self._process.poll() is None:
                self._process.kill()
        if self._log_handle is not None:
            self._log_handle.close()
        self._client = None
        self._process = None
        self._log_handle = None

    def _driver_log_tail(self) -> str:
        if self._log_handle is not None:
            self._log_handle.flush()
        if self._log_path is None or not self._log_path.is_file():
            return ""
        return self._log_path.read_text(errors="replace")[-4000:]

    def _capabilities(self) -> dict[str, Any]:
        capabilities: dict[str, Any] = {"browserName": "safari"}
        if self.platform == "ios":
            capabilities.update(
                {
                    "platformName": "ios",
                    "safari:useSimulator": True,
                    "safari:deviceType": self.ios_device_type,
                }
            )
            if self.ios_version:
                capabilities["safari:platformVersion"] = self.ios_version
            if self.ios_device_name:
                capabilities["safari:deviceName"] = self.ios_device_name
            if self.ios_device_udid:
                capabilities["safari:deviceUDID"] = self.ios_device_udid
        return capabilities

    def capture_sample(
        self,
        tls_url: str = DEFAULT_TLS_URL,
        http3_url: str = DEFAULT_HTTP3_URL,
    ) -> dict[str, Any]:
        if self._client is None:
            raise SafariRunnerError("SafariRunner must be used as a context manager")
        try:
            session_id, capabilities = self._client.create_session(self._capabilities())
        except Exception as exc:
            diagnostics = self._driver_log_tail()
            process_status = (
                self._process.poll() if self._process is not None else "not started"
            )
            suffix = (
                f"\nSafariDriver diagnostics:\n{diagnostics}" if diagnostics else ""
            )
            raise SafariRunnerError(
                f"{exc}\nSafariDriver process status: {process_status}{suffix}"
            ) from exc
        try:
            self._client.navigate(session_id, tls_url)
            tls_payload = _read_json_body(self._client, session_id)
            browser_data = self._client.execute(
                session_id,
                "return {userAgent: navigator.userAgent, platform: navigator.platform, "
                "language: navigator.language};",
            )
            if not isinstance(browser_data, dict):
                raise SafariRunnerError("Safari returned invalid browser identity data")

            http3_payload = None
            for _ in range(6):
                self._client.navigate(session_id, http3_url)
                candidate = _read_json_body(self._client, session_id)
                if candidate.get("protocol") == "http3":
                    http3_payload = candidate
                    break
            platform_version = capabilities.get("safari:platformVersion")
            observed_version = (
                str(platform_version)
                if self.platform == "ios" and platform_version
                else self.version
            )
            return {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "browser": {
                    "version": observed_version,
                    "browser_version": capabilities.get("browserVersion", self.version),
                    "build": self.build,
                    "user_agent": browser_data.get("userAgent"),
                    "user_agent_data": None,
                    "platform": browser_data.get("platform"),
                    "language": browser_data.get("language"),
                    "mode": "headful",
                },
                "tls_http2": tls_payload,
                "http3": http3_payload,
                "launch": {
                    "mode": "headful",
                    "automation": "safaridriver",
                    "capabilities": capabilities,
                    "collector_navigation": "webdriver",
                },
                "source_urls": {
                    "tls_http2": tls_url,
                    "http3": http3_url,
                },
            }
        finally:
            with suppress(Exception):
                self._client.close_session(session_id)
