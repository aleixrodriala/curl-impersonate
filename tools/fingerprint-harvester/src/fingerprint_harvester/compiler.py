import json
import re
from pathlib import Path
from typing import Any

from .bundle import load_json
from .capabilities import SIGNATURE_CODEPOINT_NAMES
from .readiness import evaluate_readiness


TARGET_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")

BROWSER_NAMES = {
    "consumer-chrome": "chrome",
    "consumer-chrome-android": "chrome",
    "consumer-safari": "safari",
    "consumer-safari-ios": "safari",
}

HTTP_VERSION_CONSTANTS = {
    "1.1": "CURL_HTTP_VERSION_1_1",
    "2": "CURL_HTTP_VERSION_2_0",
    "3": "CURL_HTTP_VERSION_3",
}

SSL_MIN_CONSTANTS = {
    "1.0": "CURL_SSLVERSION_TLSv1_0",
    "1.1": "CURL_SSLVERSION_TLSv1_1",
    "1.2": "CURL_SSLVERSION_TLSv1_2",
    "1.3": "CURL_SSLVERSION_TLSv1_3",
}

SSL_MAX_CONSTANTS = {
    "default": "CURL_SSLVERSION_MAX_DEFAULT",
    "1.0": "CURL_SSLVERSION_MAX_TLSv1_0",
    "1.1": "CURL_SSLVERSION_MAX_TLSv1_1",
    "1.2": "CURL_SSLVERSION_MAX_TLSv1_2",
    "1.3": "CURL_SSLVERSION_MAX_TLSv1_3",
}

OPTION_ORDER = (
    "http_version",
    "ssl_version",
    "ciphers",
    "curves",
    "http3_curves",
    "signature_algorithms",
    "http3_signature_algorithms",
    "npn",
    "alpn",
    "alps",
    "tls_permute_extensions",
    "tls_session_ticket",
    "ws_disable_session_ticket",
    "cert_compression",
    "ws_cert_compression",
    "http_headers",
    "http3_headers",
    "ws_headers",
    "http2_pseudo_headers_order",
    "http2_settings",
    "http_header_order",
    "http3_http_header_order",
    "ws_http_header_order",
    "http2_window_update",
    "http2_streams",
    "http2_stream_weight",
    "http2_stream_exclusive",
    "http2_no_priority",
    "http3_settings",
    "http3_pseudo_headers_order",
    "quic_transport_parameters",
    "http3_tls_extension_order",
    "ech",
    "tls_extension_order",
    "tls_use_new_alps_codepoint",
    "tls_signed_cert_timestamps",
    "http3_disable_tls_signed_cert_timestamps",
    "http3_disable_tls_status_request",
    "tls_delegated_credentials",
    "tls_record_size_limit",
    "tls_key_shares_limit",
    "tls_grease",
    "proxy_credential_no_reuse",
    "split_cookies",
    "form_boundary",
)

FIELD_NAMES = {
    "http_version": "httpversion",
    "signature_algorithms": "sig_hash_algs",
    "http3_signature_algorithms": "http3_sig_hash_algs",
}

LIST_STRING_FIELDS = {
    "ciphers",
    "signature_algorithms",
    "http3_signature_algorithms",
}

HEADER_FIELDS = {"http_headers", "http3_headers", "ws_headers"}

NATIVE_CIPHER_NAMES = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "ECDHE-ECDSA-AES128-GCM-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "ECDHE-ECDSA-AES256-GCM-SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": ("ECDHE-ECDSA-CHACHA20-POLY1305"),
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": ("ECDHE-RSA-CHACHA20-POLY1305"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHE-RSA-AES128-SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": "ECDHE-RSA-AES256-SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256": "AES128-GCM-SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384": "AES256-GCM-SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
}

CANONICAL_HEADER_NAMES = {
    "accept": "Accept",
    "accept-encoding": "Accept-Encoding",
    "accept-language": "Accept-Language",
    "priority": "Priority",
    "sec-fetch-dest": "Sec-Fetch-Dest",
    "sec-fetch-mode": "Sec-Fetch-Mode",
    "sec-fetch-site": "Sec-Fetch-Site",
    "sec-fetch-user": "Sec-Fetch-User",
    "upgrade-insecure-requests": "Upgrade-Insecure-Requests",
    "user-agent": "User-Agent",
}


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _require_string(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    return value


def validate_native_profile(profile: dict[str, Any]) -> None:
    if profile.get("schema_version") != 1:
        raise ValueError("native profile schema_version must be 1")
    target = profile.get("target")
    if not isinstance(target, str) or TARGET_PATTERN.fullmatch(target) is None:
        raise ValueError("native profile target must be a lowercase identifier")
    alias = profile.get("alias")
    if alias is not None and (
        not isinstance(alias, str) or TARGET_PATTERN.fullmatch(alias) is None
    ):
        raise ValueError("native profile alias must be a lowercase identifier")
    browser = profile.get("browser")
    if not isinstance(browser, dict):
        raise ValueError("native profile browser provenance is required")
    for field in ("name", "version", "os"):
        _require_string(browser.get(field), f"browser.{field}")
    provenance = profile.get("provenance")
    if not isinstance(provenance, dict):
        raise ValueError("native profile provenance is required")
    options = profile.get("options")
    if not isinstance(options, dict):
        raise ValueError("native profile options must be an object")
    unknown = set(options) - set(OPTION_ORDER)
    if unknown:
        raise ValueError(f"unknown native profile options: {sorted(unknown)}")
    if options.get("http_version") not in HTTP_VERSION_CONSTANTS:
        raise ValueError("options.http_version is unsupported")
    ssl_version = options.get("ssl_version")
    if not isinstance(ssl_version, dict):
        raise ValueError("options.ssl_version must be an object")
    if ssl_version.get("min") not in SSL_MIN_CONSTANTS:
        raise ValueError("options.ssl_version.min is unsupported")
    if ssl_version.get("max") not in SSL_MAX_CONSTANTS:
        raise ValueError("options.ssl_version.max is unsupported")
    for field in LIST_STRING_FIELDS | HEADER_FIELDS:
        value = options.get(field)
        if value is not None and (
            not isinstance(value, list)
            or any(not isinstance(item, str) for item in value)
        ):
            raise ValueError(f"options.{field} must be a list of strings")


def load_native_profile(path: Path) -> dict[str, Any]:
    profile = load_json(path)
    validate_native_profile(profile)
    return profile


def _render_joined(field: str, values: list[str]) -> list[str]:
    c_field = FIELD_NAMES.get(field, field)
    lines = [f"    .{c_field} ="]
    for index, value in enumerate(values):
        suffix = ":" if index < len(values) - 1 else ""
        comma = "," if index == len(values) - 1 else ""
        lines.append(f"      {_c_string(value + suffix)}{comma}")
    return lines


def _render_headers(field: str, values: list[str]) -> list[str]:
    lines = [f"    .{field} = {{"]
    for index, value in enumerate(values):
        comma = "," if index < len(values) - 1 else ""
        lines.append(f"      {_c_string(value)}{comma}")
    lines.append("    },")
    return lines


def _render_option(field: str, value: object) -> list[str]:
    c_field = FIELD_NAMES.get(field, field)
    if field == "http_version":
        return [f"    .{c_field} = {HTTP_VERSION_CONSTANTS[str(value)]},"]
    if field == "ssl_version":
        assert isinstance(value, dict)
        minimum = SSL_MIN_CONSTANTS[str(value["min"])]
        maximum = SSL_MAX_CONSTANTS[str(value["max"])]
        return [f"    .{c_field} = {minimum} | {maximum},"]
    if field in LIST_STRING_FIELDS:
        assert isinstance(value, list)
        return _render_joined(field, value)
    if field in HEADER_FIELDS:
        assert isinstance(value, list)
        return _render_headers(field, value)
    if value is None:
        return [f"    .{c_field} = NULL,"]
    if isinstance(value, bool):
        return [f"    .{c_field} = {'true' if value else 'false'},"]
    if isinstance(value, int):
        return [f"    .{c_field} = {value},"]
    if isinstance(value, str):
        return [f"    .{c_field} = {_c_string(value)},"]
    raise ValueError(f"cannot render options.{field}: {value!r}")


def render_c_initializer(profile: dict[str, Any]) -> str:
    validate_native_profile(profile)
    target = str(profile["target"])
    alias = str(profile.get("alias", target))
    options = profile["options"]
    lines = [
        "  {",
        f"    .target = {_c_string(target)},",
        f"    .alias = {_c_string(alias)},",
    ]
    for field in OPTION_ORDER:
        if field in options:
            lines.extend(_render_option(field, options[field]))
    lines.append("  },")
    return "\n".join(lines) + "\n"


def _find_extension(extensions: object, extension_id: int) -> dict[str, Any] | None:
    if not isinstance(extensions, list):
        return None
    return next(
        (
            item
            for item in extensions
            if isinstance(item, dict) and item.get("id") == extension_id
        ),
        None,
    )


def _extension_present(extensions: object, extension_id: int) -> bool:
    return _find_extension(extensions, extension_id) is not None


def _extension_values(
    extensions: object,
    extension_id: int,
    field: str,
) -> list[str]:
    extension = _find_extension(extensions, extension_id)
    values = extension.get(field, []) if extension is not None else []
    return [str(item) for item in values if item != "GREASE"]


def _minimum_tls_version(extensions: object) -> str:
    supported = _extension_values(extensions, 43, "versions")
    versions = {
        "TLS 1.0": "1.0",
        "TLS 1.1": "1.1",
        "TLS 1.2": "1.2",
        "TLS 1.3": "1.3",
    }
    available = [versions[item] for item in supported if item in versions]
    return (
        min(available, key=lambda item: tuple(map(int, item.split("."))))
        if available
        else "1.2"
    )


def _headers_as_lines(headers: object) -> list[str]:
    if not isinstance(headers, dict):
        return []
    values = headers.get("values")
    if not isinstance(values, list):
        return []
    return [
        f"{CANONICAL_HEADER_NAMES.get(str(item['name']), item['name'])}: "
        f"{item['value']}"
        for item in values
        if isinstance(item, dict) and "name" in item and "value" in item
    ]


HTTP2_SETTING_IDS = {
    "HEADER_TABLE_SIZE": 1,
    "ENABLE_PUSH": 2,
    "MAX_CONCURRENT_STREAMS": 3,
    "INITIAL_WINDOW_SIZE": 4,
    "MAX_FRAME_SIZE": 5,
    "MAX_HEADER_LIST_SIZE": 6,
    "ENABLE_CONNECT_PROTOCOL": 8,
    "NO_RFC7540_PRIORITIES": 9,
}


def _http2_settings(settings: object) -> str:
    if not isinstance(settings, list):
        return ""
    serialized = []
    for setting in settings:
        if not isinstance(setting, dict):
            continue
        setting_id = HTTP2_SETTING_IDS.get(str(setting.get("name")))
        if setting_id is None:
            raise ValueError(f"unknown HTTP/2 setting {setting.get('name')}")
        serialized.append(f"{setting_id}:{setting.get('value')}")
    return ";".join(serialized)


def _http3_settings(settings: object) -> str:
    if not isinstance(settings, list):
        return ""
    serialized = []
    for setting in settings:
        if not isinstance(setting, dict):
            continue
        if setting.get("id") == "GREASE":
            serialized.append("GREASE")
        else:
            serialized.append(f"{setting.get('id')}:{setting.get('value')}")
    return ";".join(serialized)


def _transport_parameter_value(parameter: dict[str, Any]) -> str:
    parameter_id = parameter.get("id")
    value = parameter.get("value")
    if parameter_id == 15:
        return ""
    if parameter_id == 17 and isinstance(value, dict):
        chosen = value.get("chosen_version")
        available = ",".join(str(item) for item in value.get("available_versions", []))
        return f"{chosen}@{available}"
    return str(value)


def _transport_parameters(extension: dict[str, Any] | None) -> str:
    if extension is None:
        return ""
    parameters = extension.get("parameters")
    if not isinstance(parameters, list):
        return ""
    parameter_order = extension.get("parameter_order")
    if isinstance(parameter_order, dict) and parameter_order.get("mode") == "fixed":
        observed = _fixed_order(parameter_order, "QUIC transport-parameter order")
        parameters_by_id = {
            parameter.get("id"): parameter
            for parameter in parameters
            if isinstance(parameter, dict)
        }
        parameters = [
            parameters_by_id[parameter_id]
            for parameter_id in observed
            if parameter_id in parameters_by_id
        ]
    serialized = []
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        if parameter.get("id") == "GREASE":
            serialized.append("GREASE")
        else:
            serialized.append(
                f"{parameter.get('id')}:{_transport_parameter_value(parameter)}"
            )
    return ";".join(serialized)


def _fixed_order(value: object, field: str) -> list[object]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} has no order evidence")
    observed = value.get("observed")
    if not isinstance(observed, list) or not observed:
        raise ValueError(f"{field} has no observed order")
    first = observed[0]
    if not isinstance(first, list):
        raise ValueError(f"{field} observation is invalid")
    return first


def _native_cipher_name(cipher: object) -> str:
    value = str(cipher)
    return NATIVE_CIPHER_NAMES.get(value, value)


def _native_signature_names(values: list[str]) -> list[str]:
    return [SIGNATURE_CODEPOINT_NAMES.get(value, value) for value in values]


def candidate_from_bundle(bundle: Path, target: str) -> dict[str, Any]:
    manifest = load_json(bundle / "manifest.json")
    readiness = load_json(bundle / "readiness.json")
    profile = load_json(bundle / "profile.json")
    current_readiness = evaluate_readiness(
        profile,
        str(manifest.get("browser_distribution", "unverified")),
    )
    if readiness.get("ready") is not True or not current_readiness.ready:
        raise ValueError("capture bundle is not compilation-ready")
    fingerprint = profile.get("fingerprint")
    if not isinstance(fingerprint, dict):
        raise ValueError("capture bundle has no canonical fingerprint")
    identities = profile.get("browser_identities")
    identity = identities[0] if isinstance(identities, list) and identities else None
    if not isinstance(identity, dict):
        raise ValueError("capture bundle has no browser identity")

    tcp = fingerprint.get("tls_http2")
    h3 = fingerprint.get("http3")
    if not isinstance(tcp, dict):
        raise ValueError("capture bundle has no TLS/HTTP2 fingerprint")
    tcp_tls = tcp.get("tls")
    http2 = tcp.get("http2")
    if not all(isinstance(item, dict) for item in (tcp_tls, http2)):
        raise ValueError("capture bundle has incomplete TLS/HTTP2 sections")
    assert isinstance(tcp_tls, dict)
    assert isinstance(http2, dict)

    tcp_extensions = tcp_tls.get("extensions")
    tcp_order = tcp_tls.get("extension_order")
    priority = http2.get("priority")
    priority = priority if isinstance(priority, dict) else {}
    tcp_order_mode = tcp_order.get("mode") if isinstance(tcp_order, dict) else None

    options: dict[str, Any] = {
        "http_version": "2",
        "ssl_version": {
            "min": _minimum_tls_version(tcp_extensions),
            "max": "default",
        },
        "ciphers": [
            _native_cipher_name(cipher)
            for cipher in tcp_tls.get("ciphers", [])
            if cipher != "GREASE"
        ],
        "curves": ":".join(_extension_values(tcp_extensions, 10, "groups")),
        "signature_algorithms": _native_signature_names(
            _extension_values(tcp_extensions, 13, "algorithms")
        ),
        "npn": False,
        "alpn": _extension_present(tcp_extensions, 16),
        "alps": any(
            _extension_present(tcp_extensions, extension_id)
            for extension_id in (17513, 17613)
        ),
        "tls_permute_extensions": tcp_order_mode == "permuted",
        "tls_session_ticket": _extension_present(tcp_extensions, 35),
        "cert_compression": (
            _extension_values(tcp_extensions, 27, "algorithms") or [None]
        )[0],
        "http_headers": _headers_as_lines(http2.get("headers")),
        "http2_pseudo_headers_order": str(http2.get("pseudo_header_order", "")).replace(
            ",", ""
        ),
        "http2_settings": _http2_settings(http2.get("settings")),
        "http2_window_update": http2.get("window_update", 0),
        "http2_stream_weight": priority.get("weight", 0),
        "http2_stream_exclusive": priority.get("exclusive", 0),
        "ech": "true" if _extension_present(tcp_extensions, 65037) else "false",
        "tls_extension_order": (
            None
            if tcp_order_mode == "permuted"
            else "-".join(
                str(item)
                for item in _fixed_order(tcp_order, "TLS extension order")
                if item != "GREASE"
            )
        ),
        "tls_use_new_alps_codepoint": _extension_present(tcp_extensions, 17613),
        "tls_signed_cert_timestamps": _extension_present(tcp_extensions, 18),
        "tls_grease": any(
            item == "GREASE" for item in _fixed_order(tcp_order, "TLS extension order")
        ),
        "split_cookies": True,
        "form_boundary": "webkit",
    }
    if options["cert_compression"] is None:
        options.pop("cert_compression")
    if not priority:
        options["http2_no_priority"] = True
    if isinstance(h3, dict):
        h3_tls = h3.get("tls")
        http3 = h3.get("http3")
        if not isinstance(h3_tls, dict) or not isinstance(http3, dict):
            raise ValueError("capture bundle has incomplete HTTP/3 sections")
        h3_extensions = h3_tls.get("extensions")
        h3_order = h3_tls.get("extension_order")
        transport = _find_extension(h3_extensions, 57)
        options.update(
            {
                "http3_signature_algorithms": _native_signature_names(
                    _extension_values(h3_extensions, 13, "algorithms")
                ),
                "http3_settings": _http3_settings(http3.get("settings")),
                "http3_pseudo_headers_order": str(
                    http3.get("pseudo_header_order", "")
                ).replace(",", ""),
                "quic_transport_parameters": _transport_parameters(transport),
                "http3_tls_extension_order": (
                    None
                    if isinstance(h3_order, dict) and h3_order.get("mode") == "permuted"
                    else "-".join(
                        str(item)
                        for item in _fixed_order(h3_order, "HTTP/3 TLS extension order")
                        if item != "GREASE"
                    )
                ),
                "http3_disable_tls_signed_cert_timestamps": not _extension_present(
                    h3_extensions, 18
                ),
                "http3_disable_tls_status_request": not _extension_present(
                    h3_extensions, 5
                ),
            }
        )

    release = manifest.get("expected_release")
    release = release if isinstance(release, dict) else {}
    distribution = str(manifest.get("browser_distribution", "unverified"))
    native_profile = {
        "schema_version": 1,
        "target": target,
        "alias": target,
        "browser": {
            "name": BROWSER_NAMES.get(distribution, "unknown"),
            "version": str(identity.get("version", release.get("version", ""))),
            "os": str(manifest.get("platform", identity.get("platform", ""))),
        },
        "provenance": {
            "browser_distribution": distribution,
            "capture_bundle": str(bundle),
            "fingerprint_digest": profile.get("fingerprint_digest"),
            "sample_count": profile.get("sample_count"),
        },
        "options": options,
    }
    validate_native_profile(native_profile)
    return native_profile


def extract_initializer(patch_text: str, target: str) -> str:
    lines = patch_text.splitlines()
    marker = f'+    .target = "{target}",'
    try:
        target_index = lines.index(marker)
    except ValueError as exc:
        raise ValueError(f"patch has no initializer for {target}") from exc
    start = target_index - 1
    if start < 0 or lines[start] != "+  {":
        raise ValueError(f"patch initializer for {target} has an unexpected start")
    for end in range(target_index + 1, len(lines)):
        if lines[end] == "+  },":
            return "\n".join(line[1:] for line in lines[start : end + 1]) + "\n"
    raise ValueError(f"patch initializer for {target} has no end")
