from typing import Any

from .models import CapabilityGap


SUPPORTED_TLS_EXTENSIONS = {
    0,
    5,
    10,
    11,
    13,
    16,
    18,
    21,
    23,
    27,
    28,
    34,
    35,
    43,
    45,
    51,
    57,
    17513,
    17613,
    65037,
    65281,
}

SUPPORTED_SIGNATURE_ALGORITHMS = {
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ed25519",
    "ed448",
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "rsa_pkcs1_sha1",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "rsa_pss_pss_sha256",
    "rsa_pss_pss_sha384",
    "rsa_pss_pss_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
}

SIGNATURE_CODEPOINT_NAMES = {
    "0x904": "mldsa44",
    "0x905": "mldsa65",
    "0x906": "mldsa87",
}

SUPPORTED_GROUPS = {
    "GREASE",
    "X25519MLKEM768",
    "X25519",
    "P-256",
    "P-384",
    "P-521",
}

SUPPORTED_CERT_COMPRESSION = {"brotli"}

SUPPORTED_CIPHERS = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
}

SUPPORTED_HTTP2_SETTINGS = {
    "HEADER_TABLE_SIZE",
    "ENABLE_PUSH",
    "MAX_CONCURRENT_STREAMS",
    "INITIAL_WINDOW_SIZE",
    "MAX_FRAME_SIZE",
    "MAX_HEADER_LIST_SIZE",
    "ENABLE_CONNECT_PROTOCOL",
    "NO_RFC7540_PRIORITIES",
}

SUPPORTED_QUIC_TRANSPORT_PARAMETERS = {
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    32,
    12583,
    12584,
    18258,
}


def _gap(path: str, feature: str, reason: str) -> CapabilityGap:
    return CapabilityGap(path=path, feature=feature, reason=reason)


def _require_mapping(
    value: object,
    path: str,
    feature: str,
) -> tuple[dict[str, Any], list[CapabilityGap]]:
    if isinstance(value, dict):
        return value, []
    return {}, [_gap(path, feature, "normalized profile field is missing")]


def _order_gaps(value: object, path: str, feature: str) -> list[CapabilityGap]:
    if not isinstance(value, dict) or value.get("mode") not in {
        "fixed",
        "permuted",
    }:
        return [
            _gap(
                path,
                feature,
                "order must be stable as fixed or permuted across multiple samples",
            )
        ]
    return []


def _extension_gaps(
    extensions: object,
    path: str,
) -> list[CapabilityGap]:
    if not isinstance(extensions, list):
        return [
            CapabilityGap(
                path=path,
                feature="TLS extension set",
                reason="Profile has no normalized extension list",
            )
        ]

    gaps: list[CapabilityGap] = []
    for index, extension in enumerate(extensions):
        if not isinstance(extension, dict):
            continue
        extension_id = extension.get("id")
        if extension_id == "GREASE":
            continue
        if (
            not isinstance(extension_id, int)
            or extension_id not in SUPPORTED_TLS_EXTENSIONS
        ):
            gaps.append(
                CapabilityGap(
                    path=f"{path}[{index}]",
                    feature=f"TLS extension {extension_id}",
                    reason=(
                        "curl-impersonate has no declared option for emitting this "
                        "extension"
                    ),
                )
            )
        if extension_id == 13:
            for algorithm in extension.get("algorithms", []):
                name = SIGNATURE_CODEPOINT_NAMES.get(str(algorithm), str(algorithm))
                if name not in SUPPORTED_SIGNATURE_ALGORITHMS:
                    gaps.append(
                        CapabilityGap(
                            path=f"{path}[{index}].algorithms",
                            feature=f"TLS signature algorithm {algorithm}",
                            reason=(
                                "BoringSSL support has not been declared by the "
                                "compiler"
                            ),
                        )
                    )
        if extension_id == 10:
            for group in extension.get("groups", []):
                if group not in SUPPORTED_GROUPS:
                    gaps.append(
                        _gap(
                            f"{path}[{index}].groups",
                            f"TLS group {group}",
                            "BoringSSL group support has not been declared",
                        )
                    )
        if extension_id == 27:
            for algorithm in extension.get("algorithms", []):
                if algorithm not in SUPPORTED_CERT_COMPRESSION:
                    gaps.append(
                        _gap(
                            f"{path}[{index}].algorithms",
                            f"certificate compression {algorithm}",
                            "native profile compiler cannot emit this algorithm",
                        )
                    )
    return gaps


def _http2_gaps(http2: dict[str, Any], path: str) -> list[CapabilityGap]:
    gaps: list[CapabilityGap] = []
    settings = http2.get("settings")
    if not isinstance(settings, list) or not settings:
        gaps.append(_gap(f"{path}.settings", "HTTP/2 SETTINGS", "field is empty"))
    else:
        for index, setting in enumerate(settings):
            name = setting.get("name") if isinstance(setting, dict) else None
            if name not in SUPPORTED_HTTP2_SETTINGS:
                gaps.append(
                    _gap(
                        f"{path}.settings[{index}]",
                        f"HTTP/2 setting {name}",
                        "native setting identifier has not been declared",
                    )
                )
    if not isinstance(http2.get("window_update"), int):
        gaps.append(
            _gap(
                f"{path}.window_update",
                "HTTP/2 connection window",
                "field is missing or is not an integer",
            )
        )
    pseudo_order = http2.get("pseudo_header_order")
    if not isinstance(pseudo_order, str) or set(pseudo_order.replace(",", "")) != set(
        "masp"
    ):
        gaps.append(
            _gap(
                f"{path}.pseudo_header_order",
                "HTTP pseudo-header order",
                "order must contain method, authority, scheme, and path once",
            )
        )
    headers = http2.get("headers")
    if not isinstance(headers, dict) or not isinstance(headers.get("order"), list):
        gaps.append(
            _gap(
                f"{path}.headers",
                "HTTP/2 navigation headers",
                "normalized header order is missing",
            )
        )
    return gaps


def _http3_gaps(http3: dict[str, Any], quic_tls: dict[str, Any]) -> list[CapabilityGap]:
    path = "fingerprint.http3.http3"
    gaps: list[CapabilityGap] = []
    settings = http3.get("settings")
    if not isinstance(settings, list) or not settings:
        gaps.append(_gap(f"{path}.settings", "HTTP/3 SETTINGS", "field is empty"))
    elif any(
        not isinstance(setting, dict) or not isinstance(setting.get("id"), (int, str))
        for setting in settings
    ):
        gaps.append(
            _gap(
                f"{path}.settings",
                "HTTP/3 SETTINGS",
                "a setting has no serializable identifier",
            )
        )
    pseudo_order = http3.get("pseudo_header_order")
    if not isinstance(pseudo_order, str) or set(pseudo_order.replace(",", "")) != set(
        "masp"
    ):
        gaps.append(
            _gap(
                f"{path}.pseudo_header_order",
                "HTTP/3 pseudo-header order",
                "order must contain method, authority, scheme, and path once",
            )
        )
    transport = next(
        (
            extension
            for extension in quic_tls.get("extensions", [])
            if isinstance(extension, dict) and extension.get("id") == 57
        ),
        None,
    )
    if not isinstance(transport, dict):
        gaps.append(
            _gap(
                "fingerprint.http3.tls.extensions",
                "QUIC transport parameters",
                "extension 57 is missing",
            )
        )
        return gaps
    gaps.extend(
        _order_gaps(
            transport.get("parameter_order"),
            "fingerprint.http3.tls.extensions[57].parameter_order",
            "QUIC transport-parameter order",
        )
    )
    parameters = transport.get("parameters")
    if not isinstance(parameters, list):
        gaps.append(
            _gap(
                "fingerprint.http3.tls.extensions[57].parameters",
                "QUIC transport parameters",
                "normalized parameter list is missing",
            )
        )
    else:
        for index, parameter in enumerate(parameters):
            parameter_id = parameter.get("id") if isinstance(parameter, dict) else None
            if (
                parameter_id != "GREASE"
                and parameter_id not in SUPPORTED_QUIC_TRANSPORT_PARAMETERS
            ):
                gaps.append(
                    _gap(
                        f"fingerprint.http3.tls.extensions[57].parameters[{index}]",
                        f"QUIC transport parameter {parameter_id}",
                        "ngtcp2 serializer support has not been declared",
                    )
                )
    return gaps


def _native_protocol_gaps(tcp_tls: dict[str, Any]) -> list[CapabilityGap]:
    tcp_extensions = tcp_tls.get("extensions")
    tcp_ids = (
        {item.get("id") for item in tcp_extensions if isinstance(item, dict)}
        if isinstance(tcp_extensions, list)
        else set()
    )
    if 5 not in tcp_ids:
        return [
            _gap(
                "fingerprint.tls_http2.tls.extensions",
                "TLS status_request presence",
                "the current native target always enables status_request on TCP TLS",
            )
        ]
    return []


def _protocol_order_gaps(
    tcp_tls: dict[str, Any], quic_tls: dict[str, Any]
) -> list[CapabilityGap]:
    tcp_order = tcp_tls.get("extension_order")
    quic_order = quic_tls.get("extension_order")
    tcp_mode = tcp_order.get("mode") if isinstance(tcp_order, dict) else None
    quic_mode = quic_order.get("mode") if isinstance(quic_order, dict) else None
    gaps: list[CapabilityGap] = []

    if quic_mode == "permuted" and tcp_mode != "permuted":
        gaps.append(
            _gap(
                "fingerprint.http3.tls.extension_order",
                "HTTP/3 TLS extension permutation",
                "the native permutation switch is shared with TCP TLS",
            )
        )

    transport = next(
        (
            extension
            for extension in quic_tls.get("extensions", [])
            if isinstance(extension, dict) and extension.get("id") == 57
        ),
        None,
    )
    parameter_order = (
        transport.get("parameter_order") if isinstance(transport, dict) else None
    )
    parameter_mode = (
        parameter_order.get("mode") if isinstance(parameter_order, dict) else None
    )
    if parameter_mode in {"fixed", "permuted"} and parameter_mode != tcp_mode:
        gaps.append(
            _gap(
                "fingerprint.http3.tls.extensions[57].parameter_order",
                "QUIC transport-parameter permutation",
                "the native permutation switch is shared with TCP TLS",
            )
        )
    return gaps


def analyze_capabilities(profile: dict[str, Any]) -> list[CapabilityGap]:
    fingerprint = profile.get("fingerprint")
    if not isinstance(fingerprint, dict):
        return [
            CapabilityGap(
                path="fingerprint",
                feature="canonical fingerprint",
                reason="Profile has no selected canonical fingerprint",
            )
        ]

    tls_http2, gaps = _require_mapping(
        fingerprint.get("tls_http2"),
        "fingerprint.tls_http2",
        "TLS/HTTP2 fingerprint",
    )
    http3, section_gaps = _require_mapping(
        fingerprint.get("http3"),
        "fingerprint.http3",
        "HTTP/3 fingerprint",
    )
    gaps.extend(section_gaps)
    tcp_tls = tls_http2.get("tls")
    quic_tls = http3.get("tls")
    tcp_tls = tcp_tls if isinstance(tcp_tls, dict) else {}
    quic_tls = quic_tls if isinstance(quic_tls, dict) else {}

    gaps.extend(
        _extension_gaps(
            tcp_tls.get("extensions"), "fingerprint.tls_http2.tls.extensions"
        )
    )
    gaps.extend(
        _extension_gaps(quic_tls.get("extensions"), "fingerprint.http3.tls.extensions")
    )
    gaps.extend(
        _order_gaps(
            tcp_tls.get("extension_order"),
            "fingerprint.tls_http2.tls.extension_order",
            "TLS extension order",
        )
    )
    gaps.extend(_native_protocol_gaps(tcp_tls))
    gaps.extend(_protocol_order_gaps(tcp_tls, quic_tls))
    gaps.extend(
        _order_gaps(
            quic_tls.get("extension_order"),
            "fingerprint.http3.tls.extension_order",
            "QUIC TLS extension order",
        )
    )
    ciphers = tcp_tls.get("ciphers")
    if not isinstance(ciphers, list) or not ciphers:
        gaps.append(
            _gap(
                "fingerprint.tls_http2.tls.ciphers",
                "TLS cipher suites",
                "normalized cipher list is empty",
            )
        )
    else:
        for cipher in ciphers:
            if cipher != "GREASE" and cipher not in SUPPORTED_CIPHERS:
                gaps.append(
                    _gap(
                        "fingerprint.tls_http2.tls.ciphers",
                        f"TLS cipher {cipher}",
                        "BoringSSL cipher-name mapping has not been declared",
                    )
                )

    normalized_http2, section_gaps = _require_mapping(
        tls_http2.get("http2"),
        "fingerprint.tls_http2.http2",
        "HTTP/2 fingerprint",
    )
    gaps.extend(section_gaps)
    normalized_http3, section_gaps = _require_mapping(
        http3.get("http3"),
        "fingerprint.http3.http3",
        "HTTP/3 fingerprint",
    )
    gaps.extend(section_gaps)
    gaps.extend(_http2_gaps(normalized_http2, "fingerprint.tls_http2.http2"))
    gaps.extend(_http3_gaps(normalized_http3, quic_tls))

    unique: dict[tuple[str, str], CapabilityGap] = {}
    for gap in gaps:
        unique[(gap.feature, gap.reason)] = gap
    return list(unique.values())
