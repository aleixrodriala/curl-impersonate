import json
import os
import subprocess
from copy import deepcopy
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

from fingerprint_harvester.bundle import load_json, write_capture_bundle
from fingerprint_harvester.capabilities import analyze_capabilities
from fingerprint_harvester.chrome_runner import (
    ChromeRunner,
    ChromeRunnerError,
    _read_json_body,
    _wait_for_port_file,
    find_chrome_binary,
)
from fingerprint_harvester.cli import _capture_summary, main
from fingerprint_harvester.compiler import (
    candidate_from_bundle,
    extract_initializer,
    load_native_profile,
    render_c_initializer,
)
from fingerprint_harvester.diffing import diff_profiles
from fingerprint_harvester.normalize import (
    build_profile,
    fingerprint_transport_view,
    normalize_sample,
    sanitize_sample,
)
from fingerprint_harvester.models import ConsumerChromeRelease
from fingerprint_harvester.releases import (
    _safe_extract,
    parse_release_feed,
    parse_version_history,
)
from fingerprint_harvester.replay import compare_replay


def make_trackme(
    signature_algorithms=None,
    extra_extensions=None,
    extension_order=None,
):
    signature_algorithms = signature_algorithms or [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
    ]
    extensions = {
        0: {"name": "server_name (0)", "server_name": "tls.peet.ws"},
        5: {"name": "status_request (5)"},
        10: {
            "name": "supported_groups (10)",
            "supported_groups": [
                "TLS_GREASE (0x1a1a)",
                "X25519MLKEM768 (4588)",
                "X25519 (29)",
                "P-256 (23)",
            ],
        },
        13: {
            "name": "signature_algorithms (13)",
            "signature_algorithms": signature_algorithms,
        },
        16: {
            "name": "application_layer_protocol_negotiation (16)",
            "protocols": ["h2", "http/1.1"],
        },
        18: {"name": "signed_certificate_timestamp (18)"},
        27: {
            "name": "compress_certificate (27)",
            "algorithms": ["brotli (2)"],
        },
        51: {
            "name": "key_share (51)",
            "shared_keys": [
                {"TLS_GREASE (0x1a1a)": "00"},
                {"X25519MLKEM768 (4588)": "dynamic-key"},
                {"X25519 (29)": "dynamic-key"},
            ],
        },
    }
    for extension_id, extension in extra_extensions or []:
        extensions[extension_id] = extension
    extension_order = extension_order or [16, 51, 10, 0, 27, 13, 5, 18]
    extension_order.extend(
        extension_id
        for extension_id, _ in extra_extensions or []
        if extension_id not in extension_order
    )
    ordered_extensions = [{"name": "TLS_GREASE (0xaaaa)"}]
    ordered_extensions.extend(extensions[item] for item in extension_order)
    ordered_extensions.append({"name": "TLS_GREASE (0xbaba)"})
    return {
        "ip": "192.0.2.1:12345",
        "http_version": "h2",
        "user_agent": "Chrome test",
        "tls": {
            "ciphers": ["TLS_GREASE (0xaaaa)", "TLS_AES_128_GCM_SHA256"],
            "extensions": ordered_extensions,
            "ja4": "test-ja4",
            "peetprint": "test-peetprint",
            "peetprint_hash": "test-peetprint-hash",
            "client_random": "secret-random",
            "session_id": "secret-session",
        },
        "http2": {
            "akamai_fingerprint": ("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"),
            "akamai_fingerprint_hash": "h2-hash",
            "sent_frames": [
                {
                    "frame_type": "SETTINGS",
                    "settings": [
                        "HEADER_TABLE_SIZE = 65536",
                        "ENABLE_PUSH = 0",
                    ],
                },
                {"frame_type": "WINDOW_UPDATE", "increment": 15663105},
                {
                    "frame_type": "HEADERS",
                    "headers": [
                        ":method: GET",
                        ":authority: tls.peet.ws",
                        ":scheme: https",
                        ":path: /api/all",
                        "user-agent: Chrome test",
                        "accept: text/html",
                    ],
                    "priority": {
                        "weight": 256,
                        "depends_on": 0,
                        "exclusive": 1,
                    },
                },
            ],
        },
        "tcpip": {"ip": {"src_ip": "192.0.2.1"}},
    }


def make_http3(
    signature_algorithms=None,
    extra_extensions=None,
    extension_order=None,
    parameter_order=None,
):
    signature_algorithms = signature_algorithms or [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
    ]
    extensions = {
        0: {"id": 0, "name": "server_name", "data": "example.test"},
        5: {"id": 5, "name": "status_request", "data": {}},
        10: {
            "id": 10,
            "name": "supported_groups",
            "data": {
                "groups": [
                    {"name": "X25519MLKEM768", "value": 4588},
                    {"name": "X25519", "value": 29},
                ]
            },
        },
        13: {
            "id": 13,
            "name": "signature_algorithms",
            "data": {
                "algorithms": [
                    {"name": name, "value": index}
                    for index, name in enumerate(signature_algorithms)
                ]
            },
        },
        16: {"id": 16, "name": "alpn", "data": ["h3"]},
        18: {"id": 18, "name": "signed_certificate_timestamp", "data": {}},
        27: {
            "id": 27,
            "name": "compress_certificate",
            "data": {"algorithms": [{"name": "brotli", "value": 2}]},
        },
        51: {
            "id": 51,
            "name": "key_share",
            "data": {
                "shares": [
                    {
                        "group": {"name": "X25519MLKEM768", "value": 4588},
                        "key_length": 1216,
                    },
                    {
                        "group": {"name": "X25519", "value": 29},
                        "key_length": 32,
                    },
                ]
            },
        },
    }
    parameters = {
        1: {"id": 1, "name": "max_idle_timeout", "value": 30000},
        3: {"id": 3, "name": "max_udp_payload_size", "value": 1472},
        15: {"id": 15, "name": "initial_source_connection_id", "value": "abc"},
        17: {
            "id": 17,
            "name": "version_information",
            "value": {"chosen_version": 1, "available_versions": [1, "GREASE"]},
        },
        12584: {
            "id": 12584,
            "name": "google_connection_options",
            "value": "0x4f524947",
        },
    }
    parameter_order = parameter_order or [3, 15, 1, 17, 12584]
    extensions[57] = {
        "id": 57,
        "name": "quic_transport_parameters",
        "data": [parameters[item] for item in parameter_order],
    }
    for extension_id, extension in extra_extensions or []:
        extensions[extension_id] = extension
    extension_order = extension_order or [16, 51, 10, 0, 57, 27, 13, 5, 18]
    extension_order.extend(
        extension_id
        for extension_id, _ in extra_extensions or []
        if extension_id not in extension_order
    )
    return {
        "protocol": "http3",
        "http3": {
            "perk_text_normalized": (
                "1:65536;6:262144;7:100|m,a,s,p|1:30000;3:1472;15:AUTO;12584:0x4f524947"
            ),
            "perk_hash_normalized": "perk-hash",
            "settings": [
                {"id": 1, "name": "SETTINGS_QPACK_MAX_TABLE_CAPACITY", "value": 65536},
                {"id": 19018, "name": "GREASE", "value": 7},
            ],
            "headers": [
                {"name": ":method", "value": "GET"},
                {"name": ":authority", "value": "example.test"},
                {"name": ":scheme", "value": "https"},
                {"name": ":path", "value": "/api/http3"},
                {"name": "cache-control", "value": "max-age=0"},
                {"name": "user-agent", "value": "Chrome test"},
            ],
        },
        "tls": {
            "ja3n": {"text": "test-ja3n", "hash": "test-ja3n-hash"},
            "extensions": [extensions[item] for item in extension_order],
        },
    }


def make_sample(
    signature_algorithms=None,
    extra_extensions=None,
    tls_order=None,
    http3_order=None,
    parameter_order=None,
):
    http3_extra = []
    trackme_extra = []
    for extension_id, data in extra_extensions or []:
        trackme_extra.append(
            (
                extension_id,
                {"name": f"Unknown extension {extension_id}", "data": data},
            )
        )
        http3_extra.append(
            (
                extension_id,
                {
                    "id": extension_id,
                    "name": "Unknown",
                    "data": {"raw": data},
                },
            )
        )
    return {
        "browser": {
            "version": "151.0.0.0",
            "user_agent": "Chrome test",
            "platform": "Win32",
            "mode": "headful",
        },
        "tls_http2": make_trackme(
            signature_algorithms=signature_algorithms,
            extra_extensions=trackme_extra,
            extension_order=tls_order,
        ),
        "http3": make_http3(
            signature_algorithms=signature_algorithms,
            extra_extensions=http3_extra,
            extension_order=http3_order,
            parameter_order=parameter_order,
        ),
        "chrome_version_page": "Google Chrome 151\nVariations 1234",
    }


def test_parse_release_feed():
    release = parse_release_feed(
        {
            "channels": {
                "Stable": {
                    "version": "151.0.1.2",
                    "revision": "1234",
                    "downloads": {
                        "chrome": [
                            {"platform": "linux64", "url": "https://example/chrome.zip"}
                        ]
                    },
                }
            }
        },
        "Stable",
    )

    assert release.version == "151.0.1.2"
    assert release.get_download("linux64").url == "https://example/chrome.zip"


def test_parse_consumer_version_history_is_platform_specific():
    release = parse_version_history(
        {"versions": [{"version": "151.0.7922.34"}]},
        platform="win64",
        channel="stable",
    )

    assert release.to_dict() == {
        "browser_distribution": "consumer-chrome",
        "channel": "stable",
        "platform": "win64",
        "version": "151.0.7922.34",
    }


def test_chrome_binary_validation_and_launch_arguments(tmp_path):
    binary = tmp_path / "chrome"
    binary.write_bytes(b"browser")
    binary.chmod(0o755)
    runner = ChromeRunner(binary, headless=True)
    runner.binary = find_chrome_binary(binary)

    arguments = runner._launch_arguments(tmp_path / "profile", "https://example")

    assert arguments[0] == str(binary)
    assert "--headless=new" in arguments
    assert not any("automation" in argument.lower() for argument in arguments)


def test_chrome_binary_must_be_executable(tmp_path):
    binary = tmp_path / "chrome"
    binary.write_bytes(b"browser")
    binary.chmod(0o644)

    with pytest.raises(ChromeRunnerError, match="not executable"):
        find_chrome_binary(binary)


def test_wait_for_chrome_port_file(tmp_path):
    port_file = tmp_path / "DevToolsActivePort"
    port_file.write_text("43210\n/devtools/browser/id\n", encoding="utf-8")

    class RunningProcess:
        returncode = None

        @staticmethod
        def poll():
            return None

    assert _wait_for_port_file(port_file, RunningProcess(), 1) == 43210


def test_read_json_body_retries_partial_response():
    class Locator:
        responses = iter(['{"partial":', '{"complete": true}'])

        def inner_text(self, timeout):
            return next(self.responses)

    class Page:
        locator_instance = Locator()
        waits = 0

        def locator(self, selector):
            assert selector == "body"
            return self.locator_instance

        def wait_for_timeout(self, timeout):
            assert timeout == 100
            self.waits += 1

    page = Page()

    assert _read_json_body(page) == {"complete": True}
    assert page.waits == 1


def test_normalize_sample_strips_dynamic_values_and_reload_header():
    normalized = normalize_sample(make_sample())
    tcp_extensions = normalized["tls_http2"]["tls"]["extensions"]
    key_share = next(item for item in tcp_extensions if item["id"] == 51)
    h3_headers = normalized["http3"]["http3"]["headers"]

    assert key_share["groups"] == ["GREASE", "X25519MLKEM768", "X25519"]
    assert "cache-control" not in h3_headers["order"]
    assert h3_headers["order"][:4] == [":method", ":authority", ":scheme", ":path"]


def test_normalize_trackme_unescapes_quoted_client_hints():
    sample = make_sample()
    headers = sample["tls_http2"]["http2"]["sent_frames"][2]["headers"]
    headers.append('sec-ch-ua: \\"Chromium\\";v=\\"151\\')

    values = normalize_sample(sample)["tls_http2"]["http2"]["headers"]["values"]

    assert values[-1]["value"] == '"Chromium";v="151"'


def test_build_profile_detects_permuted_orders_without_creating_variants():
    first = make_sample(
        tls_order=[16, 51, 10, 0, 27, 13],
        http3_order=[16, 51, 10, 0, 57, 27, 13],
        parameter_order=[3, 15, 1, 12584],
    )
    second = make_sample(
        tls_order=[10, 13, 27, 0, 51, 16],
        http3_order=[13, 27, 57, 0, 10, 51, 16],
        parameter_order=[12584, 1, 15, 3],
    )

    profile = build_profile([first, second])

    assert profile["variant_count"] == 1
    assert (
        profile["fingerprint"]["tls_http2"]["tls"]["extension_order"]["mode"]
        == "permuted"
    )
    h3_extensions = profile["fingerprint"]["http3"]["tls"]["extensions"]
    transport = next(item for item in h3_extensions if item["id"] == 57)
    assert transport["parameter_order"]["mode"] == "permuted"


def test_permuted_order_samples_do_not_change_fingerprint_digest():
    first = build_profile(
        [
            make_sample(tls_order=[16, 51, 10, 0, 27, 13]),
            make_sample(tls_order=[10, 13, 27, 0, 51, 16]),
        ]
    )
    second = build_profile(
        [
            make_sample(tls_order=[0, 27, 13, 51, 16, 10]),
            make_sample(tls_order=[51, 16, 0, 10, 13, 27]),
        ]
    )

    assert first["fingerprint_digest"] == second["fingerprint_digest"]


def test_fixed_order_change_changes_fingerprint_digest():
    first_sample = make_sample(tls_order=[16, 51, 10, 0, 27, 13])
    second_sample = make_sample(tls_order=[10, 13, 27, 0, 51, 16])
    first = build_profile([first_sample, deepcopy(first_sample)])
    second = build_profile([second_sample, deepcopy(second_sample)])

    assert first["fingerprint_digest"] != second["fingerprint_digest"]


def test_headless_capture_requires_headful_confirmation(tmp_path):
    samples = [make_sample(), make_sample(), make_sample()]
    for sample in samples:
        sample["browser"]["mode"] = "headless"
    profile = build_profile(samples)

    summary, ready = _capture_summary(
        tmp_path / "capture",
        "151.0.0.0",
        profile,
        "captured",
    )

    assert ready is False
    assert "headless capture must be confirmed" in summary["readiness_blockers"][0]


def test_grease_version_order_does_not_create_a_variant():
    first = make_sample()
    second = deepcopy(first)
    transport = next(
        extension
        for extension in second["http3"]["tls"]["extensions"]
        if extension["id"] == 57
    )
    version_information = next(item for item in transport["data"] if item["id"] == 17)
    version_information["value"]["available_versions"] = ["GREASE", 1]

    assert build_profile([first, second])["variant_count"] == 1


def test_capability_report_fails_closed_for_chrome_151_extensions():
    sample = make_sample(extra_extensions=[(4832, "0000"), (51764, "0000")])
    profile = build_profile([sample, deepcopy(sample), deepcopy(sample)])

    gaps = analyze_capabilities(profile)

    assert {gap.feature for gap in gaps} == {
        "TLS extension 4832",
        "TLS extension 51764",
    }


def test_mldsa_algorithms_are_supported():
    sample = make_sample(
        signature_algorithms=[
            "0x904",
            "0x905",
            "0x906",
            "ecdsa_secp256r1_sha256",
        ]
    )

    assert (
        analyze_capabilities(
            build_profile([sample, deepcopy(sample), deepcopy(sample)])
        )
        == []
    )


def test_capability_report_supports_protocol_specific_native_tls_behavior(tmp_path):
    sample = make_sample()
    sample["http3"]["tls"]["extensions"] = [
        extension
        for extension in sample["http3"]["tls"]["extensions"]
        if extension["id"] not in {5, 18}
    ]
    signature = next(
        extension
        for extension in sample["http3"]["tls"]["extensions"]
        if extension["id"] == 13
    )
    signature["data"]["algorithms"].append({"name": "rsa_pkcs1_sha1", "value": 513})
    profile = build_profile([sample, deepcopy(sample), deepcopy(sample)])

    assert analyze_capabilities(profile) == []
    bundle = tmp_path / "capture"
    write_capture_bundle(
        bundle,
        [sample, deepcopy(sample), deepcopy(sample)],
        ConsumerChromeRelease("stable", "151.0.0.0", "win64"),
        "win64",
        "consumer-chrome",
    )
    candidate = candidate_from_bundle(bundle, "chrome151")
    assert candidate["options"]["http3_disable_tls_status_request"] is True
    assert candidate["options"]["http3_disable_tls_signed_cert_timestamps"] is True
    assert candidate["options"]["http3_signature_algorithms"][-1] == "rsa_pkcs1_sha1"


def test_capability_report_rejects_http3_only_permutation():
    first = make_sample()
    second = make_sample(
        http3_order=[13, 27, 57, 0, 10, 51, 16, 5, 18],
    )
    profile = build_profile([first, second, deepcopy(first)])

    gaps = analyze_capabilities(profile)

    assert any(gap.feature == "HTTP/3 TLS extension permutation" for gap in gaps)


def test_diff_profiles_reports_nested_algorithm_change():
    previous = build_profile([make_sample()])
    current = build_profile(
        [
            make_sample(
                signature_algorithms=[
                    "0x904",
                    "ecdsa_secp256r1_sha256",
                    "rsa_pss_rsae_sha256",
                ]
            )
        ]
    )

    differences = diff_profiles(previous["fingerprint"], current["fingerprint"])

    assert any("algorithms" in item.path for item in differences)


def test_transport_view_ignores_platform_header_values():
    windows = build_profile([make_sample()])["fingerprint"]
    macos = deepcopy(windows)
    macos["tls_http2"]["user_agent"] = "Mac Chrome"
    macos["tls_http2"]["http2"]["headers"]["values"][0]["value"] = "Mac Chrome"
    macos["http3"]["http3"]["headers"]["values"][0]["value"] = "Mac Chrome"

    assert fingerprint_transport_view(windows) == fingerprint_transport_view(macos)


def test_sanitize_sample_removes_network_and_tls_identifiers():
    sample = make_sample()
    sanitized = sanitize_sample(sample)

    assert "ip" not in sanitized["tls_http2"]
    assert "tcpip" not in sanitized["tls_http2"]
    assert "client_random" not in sanitized["tls_http2"]["tls"]
    assert "session_id" not in sanitized["tls_http2"]["tls"]
    assert "ip" in sample["tls_http2"]


def test_write_capture_bundle_is_atomic_and_refuses_overwrite(tmp_path):
    output = tmp_path / "capture"
    write_capture_bundle(output, [make_sample()])

    manifest = load_json(output / "manifest.json")
    readiness = load_json(output / "readiness.json")
    raw = load_json(output / "samples" / "000" / "raw.json")
    assert manifest["schema_version"] == 2
    assert readiness["ready"] is False
    assert "consumer Google Chrome Stable" in readiness["readiness_blockers"][0]
    assert manifest["sample_count"] == 1
    assert "ip" not in raw["tls_http2"]

    with pytest.raises(FileExistsError):
        write_capture_bundle(output, [deepcopy(make_sample())])


def test_cft_harvest_polls_and_captures_each_release_once(
    tmp_path,
    monkeypatch,
    capsys,
):
    release = parse_release_feed(
        {
            "channels": {
                "Stable": {
                    "version": "151.0.0.0",
                    "revision": "1234",
                    "downloads": {
                        "chrome": [
                            {
                                "platform": "linux64",
                                "url": "https://example/chrome.zip",
                            }
                        ]
                    },
                }
            }
        },
        "Stable",
    )
    capture_calls = []
    monkeypatch.setattr(
        "fingerprint_harvester.cli.fetch_release",
        lambda channel, feed_url: release,
    )
    monkeypatch.setattr(
        "fingerprint_harvester.cli.download_chrome",
        lambda release, platform, output: {"binary": str(tmp_path / "chrome")},
    )

    def capture_samples(*arguments):
        capture_calls.append(arguments)
        return [make_sample(), make_sample(), make_sample()]

    monkeypatch.setattr(
        "fingerprint_harvester.cli._capture_samples",
        capture_samples,
    )
    arguments = [
        "cft-harvest",
        "--workspace",
        str(tmp_path / "harvester"),
        "--samples",
        "3",
    ]

    assert main(arguments) == 1
    first = capsys.readouterr().out
    assert '"status": "captured"' in first
    assert '"distribution": "chrome-for-testing"' in first
    manifest = load_json(
        tmp_path
        / "harvester"
        / "captures"
        / "chrome-for-testing"
        / "stable"
        / "151.0.0.0"
        / "linux64"
        / "manifest.json"
    )
    assert manifest["platform"] == "linux64"
    assert main(arguments) == 1
    second = capsys.readouterr().out
    assert '"status": "already_harvested"' in second
    assert len(capture_calls) == 1


def test_consumer_harvest_is_ready_and_idempotent(tmp_path, monkeypatch, capsys):
    release = ConsumerChromeRelease(
        channel="stable",
        version="151.0.0.0",
        platform="win64",
    )
    capture_calls = []
    monkeypatch.setattr(
        "fingerprint_harvester.cli.fetch_consumer_release",
        lambda platform, channel, api_root: release,
    )

    def capture_samples(*arguments):
        capture_calls.append(arguments)
        return [make_sample(), make_sample(), make_sample()]

    monkeypatch.setattr(
        "fingerprint_harvester.cli._capture_samples",
        capture_samples,
    )
    arguments = [
        "harvest",
        "--platform",
        "win64",
        "--workspace",
        str(tmp_path / "harvester"),
        "--samples",
        "3",
    ]

    assert main(arguments) == 0
    first = capsys.readouterr().out
    assert '"ready": true' in first
    bundle = tmp_path / "harvester" / "captures" / "stable" / "151.0.0.0" / "win64"
    assert load_json(bundle / "readiness.json")["ready"] is True
    assert main(arguments) == 0
    assert '"status": "already_harvested"' in capsys.readouterr().out
    assert len(capture_calls) == 1


def test_consumer_harvest_uses_observed_version_during_staged_rollout(
    tmp_path,
    monkeypatch,
    capsys,
):
    release = ConsumerChromeRelease(
        channel="stable",
        version="151.0.0.0",
        platform="linux",
    )
    monkeypatch.setattr(
        "fingerprint_harvester.cli.fetch_consumer_release",
        lambda platform, channel, api_root: release,
    )
    samples = [make_sample(), make_sample(), make_sample()]
    for sample in samples:
        sample["browser"]["version"] = "150.0.0.0"
    monkeypatch.setattr(
        "fingerprint_harvester.cli._capture_samples",
        lambda *arguments: samples,
    )

    result = main(
        [
            "harvest",
            "--platform",
            "linux",
            "--workspace",
            str(tmp_path / "harvester"),
            "--samples",
            "3",
            "--allow-version-mismatch",
        ]
    )

    assert result == 0
    assert '"browser_version": "150.0.0.0"' in capsys.readouterr().out
    bundle = tmp_path / "harvester" / "captures" / "stable" / "150.0.0.0" / "linux"
    assert load_json(bundle / "manifest.json")["browser_distribution"] == (
        "consumer-chrome"
    )
    assert load_json(bundle / "readiness.json")["ready"] is True


def test_safe_extract_preserves_executable_mode(tmp_path):
    archive_path = tmp_path / "chrome.zip"
    destination = tmp_path / "extracted"
    destination.mkdir()
    chrome = ZipInfo("chrome-linux64/chrome")
    chrome.external_attr = 0o100755 << 16
    with ZipFile(archive_path, "w") as archive:
        archive.writestr(chrome, b"browser")

    with ZipFile(archive_path) as archive:
        _safe_extract(archive, destination)

    assert os.access(destination / "chrome-linux64" / "chrome", os.X_OK)


def test_chrome146_declarative_profile_matches_existing_patch():
    repository = Path(__file__).parents[3]
    profile = load_native_profile(repository / "profiles/chrome/chrome146.json")
    rendered = render_c_initializer(profile)
    existing = extract_initializer(
        (repository / "patches/curl.patch").read_text(encoding="utf-8"),
        "chrome146",
    )

    assert rendered == existing


def test_cmake_injects_generated_profile_before_array_terminator(tmp_path):
    repository = Path(__file__).parents[3]
    curl_source = tmp_path / "curl"
    impersonate_source = curl_source / "lib" / "impersonate.c"
    generated = tmp_path / "generated"
    impersonate_source.parent.mkdir(parents=True)
    generated.mkdir()
    impersonate_source.write_text(
        "const struct impersonate_opts impersonations[] = {\n"
        '  { .target = "existing" }\n'
        "};\n\n"
        "const size_t num_impersonations = 1;\n",
        encoding="utf-8",
    )
    initializer = '  {\n    .target = "chrome151",\n  },\n'
    (generated / "chrome151.inc").write_text(initializer, encoding="utf-8")

    subprocess.run(
        [
            "cmake",
            f"-DCURL_SOURCE_DIR={curl_source}",
            f"-DGENERATED_PROFILE_DIR={generated}",
            "-P",
            str(repository / "cmake/InjectImpersonationProfiles.cmake"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    updated = impersonate_source.read_text(encoding="utf-8")
    assert updated.count('.target = "chrome151"') == 1
    assert updated.index(initializer) < updated.index("const size_t num_impersonations")


def test_cmake_rejects_duplicate_generated_targets(tmp_path):
    repository = Path(__file__).parents[3]
    curl_source = tmp_path / "curl"
    impersonate_source = curl_source / "lib" / "impersonate.c"
    generated = tmp_path / "generated"
    impersonate_source.parent.mkdir(parents=True)
    generated.mkdir()
    impersonate_source.write_text(
        "const struct impersonate_opts impersonations[] = {\n"
        "};\n\n"
        "const size_t num_impersonations = 0;\n",
        encoding="utf-8",
    )
    initializer = '  {\n    .target = "chrome151",\n  },\n'
    (generated / "first.inc").write_text(initializer, encoding="utf-8")
    (generated / "second.inc").write_text(initializer, encoding="utf-8")

    result = subprocess.run(
        [
            "cmake",
            f"-DCURL_SOURCE_DIR={curl_source}",
            f"-DGENERATED_PROFILE_DIR={generated}",
            "-P",
            str(repository / "cmake/InjectImpersonationProfiles.cmake"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "declared by more than one file" in result.stderr


def test_ready_bundle_compiles_to_native_candidate(tmp_path):
    release = ConsumerChromeRelease(
        channel="stable",
        version="151.0.0.0",
        platform="win64",
    )
    bundle = tmp_path / "capture"
    samples = [make_sample(), make_sample(), make_sample()]
    for sample in samples:
        sample["tls_http2"]["tls"]["ciphers"].append(
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        )
    write_capture_bundle(
        bundle,
        samples,
        release,
        "win64",
        "consumer-chrome",
    )

    candidate = candidate_from_bundle(bundle, "chrome151")

    assert candidate["target"] == "chrome151"
    assert candidate["browser"]["version"] == "151.0.0.0"
    assert candidate["options"]["http2_settings"].startswith("1:65536;2:0")
    assert candidate["options"]["ciphers"][0] == "TLS_AES_128_GCM_SHA256"
    assert candidate["options"]["ciphers"][-1] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert candidate["options"]["http3_disable_tls_status_request"] is False
    assert candidate["options"]["http3_disable_tls_signed_cert_timestamps"] is False
    assert isinstance(candidate["options"]["http3_tls_extension_order"], str)
    assert '.target = "chrome151",' in render_c_initializer(candidate)


def test_fixed_quic_transport_parameter_order_is_preserved(tmp_path):
    bundle = tmp_path / "capture"
    samples = [make_sample(parameter_order=[12584, 17, 15, 3, 1]) for _ in range(3)]
    write_capture_bundle(
        bundle,
        samples,
        ConsumerChromeRelease("stable", "151.0.0.0", "linux"),
        "linux",
        "consumer-chrome",
    )

    candidate = candidate_from_bundle(bundle, "chrome151")

    assert candidate["options"]["quic_transport_parameters"].startswith(
        "12584:0x4f524947;17:1@1,GREASE;15:;3:1472;1:30000"
    )


def test_permuted_http3_order_compiles_without_fixed_override(tmp_path):
    bundle = tmp_path / "capture"
    samples = [
        make_sample(
            tls_order=[16, 51, 10, 0, 27, 13, 5, 18],
            http3_order=[16, 51, 10, 0, 57, 27, 13, 5, 18],
            parameter_order=[3, 15, 1, 12584],
        ),
        make_sample(
            tls_order=[10, 13, 27, 0, 51, 16, 18, 5],
            http3_order=[13, 27, 57, 0, 10, 51, 16, 18, 5],
            parameter_order=[12584, 1, 15, 3],
        ),
        make_sample(
            tls_order=[0, 18, 27, 5, 13, 51, 16, 10],
            http3_order=[0, 18, 27, 5, 13, 57, 51, 16, 10],
            parameter_order=[15, 3, 12584, 1],
        ),
    ]
    write_capture_bundle(
        bundle,
        samples,
        ConsumerChromeRelease("stable", "151.0.0.0", "linux"),
        "linux",
        "consumer-chrome",
    )

    candidate = candidate_from_bundle(bundle, "chrome151")

    assert candidate["options"]["tls_permute_extensions"] is True
    assert candidate["options"]["http3_tls_extension_order"] is None


def test_unready_bundle_cannot_compile_native_candidate(tmp_path):
    bundle = tmp_path / "capture"
    write_capture_bundle(bundle, [make_sample()])

    with pytest.raises(ValueError, match="not compilation-ready"):
        candidate_from_bundle(bundle, "chrome151")


def test_candidate_rechecks_stale_persisted_readiness(tmp_path):
    bundle = tmp_path / "capture"
    samples = [make_sample(), make_sample(), make_sample()]
    write_capture_bundle(
        bundle,
        samples,
        ConsumerChromeRelease("stable", "151.0.0.0", "win64"),
        "win64",
        "consumer-chrome",
    )
    assert load_json(bundle / "readiness.json")["ready"] is True
    profile = load_json(bundle / "profile.json")
    profile["fingerprint"]["tls_http2"]["tls"]["extensions"] = [
        extension
        for extension in profile["fingerprint"]["tls_http2"]["tls"]["extensions"]
        if extension["id"] != 5
    ]
    (bundle / "profile.json").write_text(
        json.dumps(profile, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="not compilation-ready"):
        candidate_from_bundle(bundle, "chrome151")


def test_native_replay_comparison_matches_same_wire_profile(tmp_path):
    samples = [make_sample(), make_sample(), make_sample()]
    bundle = tmp_path / "chrome"
    write_capture_bundle(
        bundle,
        samples,
        ConsumerChromeRelease("stable", "151.0.0.0", "win64"),
        "win64",
        "consumer-chrome",
    )

    replay_profile, differences = compare_replay(bundle, samples)

    assert replay_profile["variant_count"] == 1
    assert differences == []


def test_native_replay_comparison_reports_header_mismatch(tmp_path):
    chrome_samples = [make_sample(), make_sample(), make_sample()]
    replay_samples = deepcopy(chrome_samples)
    for sample in replay_samples:
        sample["tls_http2"]["http2"]["sent_frames"][2]["headers"][-2] = (
            "user-agent: wrong"
        )
    bundle = tmp_path / "chrome"
    write_capture_bundle(
        bundle,
        chrome_samples,
        ConsumerChromeRelease("stable", "151.0.0.0", "win64"),
        "win64",
        "consumer-chrome",
    )

    _, differences = compare_replay(bundle, replay_samples)

    assert any("headers.values" in difference.path for difference in differences)
