import shlex
import subprocess
from pathlib import Path

import pytest


FEATURES = ["zlib", "zstd", "brotli", "nghttp2", "BoringSSL", "libidn2"]


@pytest.mark.parametrize("missing", FEATURES + [None])
def test_checkbuild_requires_every_feature(tmp_path, missing):
    binary = tmp_path / "curl-impersonate"
    features = " ".join(feature for feature in FEATURES if feature != missing)
    binary.write_text(f"#!/bin/sh\nprintf '%s\\n' '{features}'\n")
    binary.chmod(0o755)
    result = subprocess.run(
        ["make", "checkbuild", f"CURL_BIN={binary}"],
        cwd=Path(__file__).parents[3],
        text=True,
        capture_output=True,
    )
    assert (result.returncode == 0) == (missing is None)
    assert ("Build OK" in result.stdout) == (missing is None)
    if missing is not None:
        assert "Missing required feature" in result.stderr


def test_checkbuild_propagates_binary_failure(tmp_path):
    binary = tmp_path / "curl-impersonate"
    binary.write_text(
        "#!/bin/sh\nprintf '%s\\n' '" + " ".join(FEATURES) + "'\nexit 1\n"
    )
    binary.chmod(0o755)
    result = subprocess.run(
        ["make", "checkbuild", f"CURL_BIN={binary}"],
        cwd=Path(__file__).parents[3],
        text=True,
        capture_output=True,
    )
    assert result.returncode != 0
    assert "Build OK" not in result.stdout


@pytest.mark.parametrize("exit_code", [0, 1])
def test_checkbuild_uses_runner_and_propagates_status(tmp_path, exit_code):
    binary = tmp_path / "curl impersonate"
    binary.write_text(
        '#!/bin/sh\n[ "$1" = -V ] || exit 2\n'
        "printf '%s\\n' '" + " ".join(FEATURES) + f"'\nexit {exit_code}\n"
    )
    binary.chmod(0o755)
    runner = tmp_path / "test runner"
    runner.write_text('#!/bin/sh\n[ "$1" = --test-flag ] || exit 2\nshift\nexec "$@"\n')
    runner.chmod(0o755)
    result = subprocess.run(
        [
            "make",
            "checkbuild",
            f"CURL_BIN={binary}",
            f"CURL_RUNNER={shlex.quote(str(runner))} --test-flag",
        ],
        cwd=Path(__file__).parents[3],
        text=True,
        capture_output=True,
    )
    assert (result.returncode == 0) == (exit_code == 0)
    assert ("Build OK" in result.stdout) == (exit_code == 0)
