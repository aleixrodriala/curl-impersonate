import hashlib
import json
import re
from collections import Counter
from copy import deepcopy
from typing import Any


GREASE = "GREASE"
EXTENSION_ID_PATTERN = re.compile(r"\((\d+)\)$")
UNKNOWN_EXTENSION_PATTERN = re.compile(r"Unknown extension (\d+)$")

EXTENSION_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    18: "signed_certificate_timestamp",
    21: "padding",
    23: "extended_master_secret",
    27: "compress_certificate",
    35: "session_ticket",
    41: "pre_shared_key",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    57: "quic_transport_parameters",
    17513: "application_settings_old",
    17613: "application_settings",
    4832: "server_padding",
    51764: "trust_anchors",
    64768: "ech_outer_extensions",
    65037: "encrypted_client_hello",
    65281: "renegotiation_info",
}


def _normalize_grease(value: object) -> object:
    if isinstance(value, str) and "GREASE" in value.upper():
        return GREASE
    return value


def _extension_id(name: str, explicit_id: object = None) -> int | str:
    if "GREASE" in name.upper():
        return GREASE
    if isinstance(explicit_id, int):
        return explicit_id
    match = UNKNOWN_EXTENSION_PATTERN.search(name) or EXTENSION_ID_PATTERN.search(name)
    if match is None:
        raise ValueError(f"Could not determine TLS extension id from {name!r}")
    return int(match.group(1))


def _extension_name(extension_id: int | str, observed_name: str) -> str:
    if extension_id == GREASE:
        return GREASE
    return EXTENSION_NAMES.get(extension_id, observed_name)


def _group_name(value: object) -> object:
    value = _normalize_grease(value)
    if not isinstance(value, str) or value == GREASE:
        return value
    return re.sub(r"\s+\(\d+\)$", "", value)


def _algorithm_names(items: object) -> list[object]:
    if not isinstance(items, list):
        return []
    normalized: list[object] = []
    for item in items:
        if isinstance(item, dict):
            normalized.append(_normalize_grease(item.get("name", item.get("value"))))
        else:
            normalized.append(_group_name(item))
    return normalized


def _normalize_trackme_extension(extension: dict[str, Any]) -> dict[str, Any]:
    observed_name = str(extension.get("name", ""))
    extension_id = _extension_id(observed_name)
    normalized: dict[str, Any] = {
        "id": extension_id,
        "name": _extension_name(extension_id, observed_name),
    }

    if extension_id == 10:
        normalized["groups"] = [
            _group_name(item) for item in extension.get("supported_groups", [])
        ]
    elif extension_id == 13:
        normalized["algorithms"] = _algorithm_names(
            extension.get("signature_algorithms")
        )
    elif extension_id == 16:
        normalized["protocols"] = extension.get("protocols", [])
    elif extension_id == 27:
        normalized["algorithms"] = _algorithm_names(extension.get("algorithms"))
    elif extension_id == 43:
        normalized["versions"] = _algorithm_names(extension.get("versions"))
    elif extension_id == 45:
        mode = extension.get("PSK_Key_Exchange_Mode")
        if mode is not None:
            normalized["mode"] = mode
    elif extension_id == 51:
        groups: list[object] = []
        for item in extension.get("shared_keys", []):
            if isinstance(item, dict):
                groups.extend(_group_name(name) for name in item)
        normalized["groups"] = groups
    elif extension_id in (17513, 17613):
        normalized["protocols"] = extension.get("protocols", [])
    elif extension_id == 65037:
        normalized["present"] = True
    elif extension_id in (4832, 51764):
        normalized["data"] = extension.get("data", "")
    elif "data" in extension and extension["data"] not in (None, ""):
        normalized["data"] = extension["data"]
    return normalized


def _extension_sort_key(extension: dict[str, Any]) -> tuple[int, str]:
    extension_id = extension["id"]
    if extension_id == GREASE:
        return (1, GREASE)
    return (0, f"{int(extension_id):05d}")


def _parse_header_line(line: str) -> tuple[str, str]:
    separator = line.find(":", 1) if line.startswith(":") else line.find(":")
    if separator < 0:
        return line.strip().lower(), ""
    value = line[separator + 1 :].strip().replace('\\"', '"')
    if value.endswith("\\"):
        value = value[:-1] + '"'
    return line[:separator].strip().lower(), value


def _normalize_headers(lines: object) -> dict[str, object]:
    if not isinstance(lines, list):
        return {"order": [], "values": []}
    parsed = [_parse_header_line(str(line)) for line in lines]
    return {
        "order": [name for name, _ in parsed],
        "values": [
            {"name": name, "value": value}
            for name, value in parsed
            if not name.startswith(":")
        ],
    }


def _normalize_http2(payload: dict[str, Any]) -> dict[str, Any]:
    http2 = payload.get("http2")
    if not isinstance(http2, dict):
        return {}
    frames = http2.get("sent_frames")
    frames = frames if isinstance(frames, list) else []

    settings: list[dict[str, object]] = []
    window_update = 0
    headers: dict[str, object] = {"order": [], "values": []}
    priority: object = None
    for frame in frames:
        if not isinstance(frame, dict):
            continue
        frame_type = frame.get("frame_type")
        if frame_type == "SETTINGS":
            for item in frame.get("settings", []):
                name, separator, raw_value = str(item).partition(" = ")
                value: object = raw_value
                if separator and raw_value.isdigit():
                    value = int(raw_value)
                settings.append({"name": name, "value": value})
        elif frame_type == "WINDOW_UPDATE":
            window_update = int(frame.get("increment", 0))
        elif frame_type == "HEADERS":
            headers = _normalize_headers(frame.get("headers"))
            priority = frame.get("priority")

    akamai = str(http2.get("akamai_fingerprint", ""))
    pseudo_header_order = akamai.rpartition("|")[2] if "|" in akamai else ""
    return {
        "akamai_fingerprint": akamai,
        "akamai_fingerprint_hash": http2.get("akamai_fingerprint_hash", ""),
        "settings": settings,
        "window_update": window_update,
        "pseudo_header_order": pseudo_header_order,
        "headers": headers,
        "priority": priority,
    }


def normalize_trackme(payload: dict[str, Any]) -> dict[str, Any]:
    tls = payload.get("tls")
    if not isinstance(tls, dict):
        raise ValueError("TrackMe payload has no TLS object")
    raw_extensions = tls.get("extensions")
    if not isinstance(raw_extensions, list):
        raise ValueError("TrackMe payload has no TLS extensions list")

    extensions = [
        _normalize_trackme_extension(item)
        for item in raw_extensions
        if isinstance(item, dict)
    ]
    return {
        "protocol": payload.get("http_version", ""),
        "user_agent": payload.get("user_agent", ""),
        "tls": {
            "ciphers": [_normalize_grease(item) for item in tls.get("ciphers", [])],
            "extension_order": [item["id"] for item in extensions],
            "extensions": sorted(extensions, key=_extension_sort_key),
            "ja4": tls.get("ja4", ""),
            "peetprint": tls.get("peetprint", ""),
            "peetprint_hash": tls.get("peetprint_hash", ""),
            "record_version": tls.get("tls_version_record", ""),
            "negotiated_version": tls.get("tls_version_negotiated", ""),
        },
        "http2": _normalize_http2(payload),
    }


def _normalize_transport_parameters(items: object) -> list[dict[str, object]]:
    if not isinstance(items, list):
        return []
    parameters: list[dict[str, object]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        parameter_id: object = item.get("id")
        value: object = item.get("value")
        if "GREASE" in name.upper():
            parameter_id = GREASE
            name = GREASE
            value = GREASE
        elif name == "initial_source_connection_id":
            value = "AUTO"
        elif isinstance(value, dict):
            normalized_value: dict[str, object] = {}
            for key, nested in value.items():
                if isinstance(nested, list):
                    normalized_list = [_normalize_grease(entry) for entry in nested]
                    if key == "available_versions":
                        normalized_list.sort(
                            key=lambda entry: (entry == GREASE, str(entry))
                        )
                    normalized_value[key] = normalized_list
                else:
                    normalized_value[key] = _normalize_grease(nested)
            value = normalized_value
        parameters.append({"id": parameter_id, "name": name, "value": value})
    return parameters


def _transport_parameter_sort_key(parameter: dict[str, object]) -> tuple[int, str]:
    parameter_id = parameter["id"]
    if parameter_id == GREASE:
        return (1, GREASE)
    return (0, f"{int(parameter_id):020d}")


def _normalize_http3_extension(extension: dict[str, Any]) -> dict[str, Any]:
    observed_name = str(extension.get("name", ""))
    extension_id = _extension_id(observed_name, extension.get("id"))
    normalized: dict[str, Any] = {
        "id": extension_id,
        "name": _extension_name(extension_id, observed_name),
    }
    data = extension.get("data")

    if extension_id == 10 and isinstance(data, dict):
        normalized["groups"] = _algorithm_names(data.get("groups"))
    elif extension_id in (13, 27) and isinstance(data, dict):
        normalized["algorithms"] = _algorithm_names(data.get("algorithms"))
    elif extension_id == 51 and isinstance(data, dict):
        shares: list[dict[str, object]] = []
        for item in data.get("shares", []):
            if not isinstance(item, dict):
                continue
            group = item.get("group")
            group_name = group.get("name") if isinstance(group, dict) else group
            shares.append(
                {
                    "group": _normalize_grease(group_name),
                    "key_length": item.get("key_length"),
                }
            )
        normalized["shares"] = shares
    elif extension_id == 57 and isinstance(data, list):
        parameters = _normalize_transport_parameters(data)
        normalized["parameter_order"] = [item["id"] for item in parameters]
        normalized["parameters"] = sorted(parameters, key=_transport_parameter_sort_key)
    elif extension_id == 65037:
        normalized["present"] = True
        if isinstance(data, dict):
            normalized["type"] = data.get("type", "")
            normalized["cipher_suite"] = data.get("cipher_suite", {})
    elif extension_id in (4832, 51764) and isinstance(data, dict):
        normalized["data"] = data.get("raw", "")
    elif isinstance(data, list):
        normalized["values"] = _algorithm_names(data)
    elif extension_id in (17513, 17613) or data not in (None, ""):
        normalized["present"] = True
    return normalized


def normalize_http3(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("protocol") != "http3":
        raise ValueError("HTTP/3 capture did not negotiate HTTP/3")
    http3 = payload.get("http3")
    tls = payload.get("tls")
    if not isinstance(http3, dict) or not isinstance(tls, dict):
        raise ValueError("HTTP/3 capture is missing protocol details")
    raw_extensions = tls.get("extensions")
    if not isinstance(raw_extensions, list):
        raise ValueError("HTTP/3 capture has no TLS extensions list")

    extensions = [
        _normalize_http3_extension(item)
        for item in raw_extensions
        if isinstance(item, dict)
    ]
    settings: list[dict[str, object]] = []
    for item in http3.get("settings", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", ""))
        setting_id: object = item.get("id")
        value: object = item.get("value")
        if "GREASE" in name.upper():
            name = GREASE
            setting_id = GREASE
            value = GREASE
        settings.append({"id": setting_id, "name": name, "value": value})

    raw_headers = http3.get("headers")
    header_lines = []
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if isinstance(item, dict) and item.get("name") != "cache-control":
                header_lines.append(f"{item.get('name', '')}: {item.get('value', '')}")

    ja3n = tls.get("ja3n")
    ja3n = ja3n if isinstance(ja3n, dict) else {}
    return {
        "protocol": "http3",
        "http3": {
            "perk": http3.get("perk_text_normalized", ""),
            "perk_hash": http3.get("perk_hash_normalized", ""),
            "settings": settings,
            "pseudo_header_order": str(http3.get("perk_text_normalized", "")).split(
                "|"
            )[1]
            if str(http3.get("perk_text_normalized", "")).count("|") >= 2
            else "",
            "headers": _normalize_headers(header_lines),
        },
        "tls": {
            "ja3n": ja3n.get("text", ""),
            "ja3n_hash": ja3n.get("hash", ""),
            "extension_order": [item["id"] for item in extensions],
            "extensions": sorted(extensions, key=_extension_sort_key),
        },
    }


def sanitize_sample(sample: dict[str, Any]) -> dict[str, Any]:
    sanitized = deepcopy(sample)
    trackme = sanitized.get("tls_http2")
    if isinstance(trackme, dict):
        trackme.pop("ip", None)
        trackme.pop("tcpip", None)
        tls = trackme.get("tls")
        if isinstance(tls, dict):
            tls.pop("client_random", None)
            tls.pop("session_id", None)
    return sanitized


def normalize_sample(sample: dict[str, Any]) -> dict[str, Any]:
    trackme = sample.get("tls_http2")
    http3 = sample.get("http3")
    if not isinstance(trackme, dict) or not isinstance(http3, dict):
        raise ValueError("Capture sample must contain tls_http2 and http3 objects")
    return {
        "browser": deepcopy(sample.get("browser", {})),
        "tls_http2": normalize_trackme(trackme),
        "http3": normalize_http3(http3),
    }


def _stable_view(sample: dict[str, Any]) -> dict[str, Any]:
    stable = deepcopy(sample)
    stable.pop("browser", None)
    stable["tls_http2"]["tls"].pop("extension_order", None)
    stable["http3"]["tls"].pop("extension_order", None)
    for extension in stable["http3"]["tls"]["extensions"]:
        if extension.get("id") == 57:
            extension.pop("parameter_order", None)
    return stable


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _comparison_order(value: object) -> object:
    if isinstance(value, dict) and value.get("mode") == "permuted":
        return {"mode": "permuted"}
    return value


def fingerprint_comparison_view(fingerprint: dict[str, Any]) -> dict[str, Any]:
    comparable = deepcopy(fingerprint)
    tcp_tls = comparable.get("tls_http2", {}).get("tls", {})
    h3_tls = comparable.get("http3", {}).get("tls", {})
    if isinstance(tcp_tls, dict) and "extension_order" in tcp_tls:
        tcp_tls["extension_order"] = _comparison_order(tcp_tls["extension_order"])
    if isinstance(h3_tls, dict) and "extension_order" in h3_tls:
        h3_tls["extension_order"] = _comparison_order(h3_tls["extension_order"])
        extensions = h3_tls.get("extensions", [])
        if isinstance(extensions, list):
            for extension in extensions:
                if (
                    isinstance(extension, dict)
                    and extension.get("id") == 57
                    and "parameter_order" in extension
                ):
                    extension["parameter_order"] = _comparison_order(
                        extension["parameter_order"]
                    )
    return comparable


def fingerprint_transport_view(fingerprint: dict[str, Any]) -> dict[str, Any]:
    transport = fingerprint_comparison_view(fingerprint)
    tls_http2 = transport.get("tls_http2")
    if isinstance(tls_http2, dict):
        tls_http2.pop("user_agent", None)
        http2 = tls_http2.get("http2")
        if isinstance(http2, dict):
            headers = http2.get("headers")
            if isinstance(headers, dict):
                headers.pop("values", None)
    http3 = transport.get("http3")
    if isinstance(http3, dict):
        protocol = http3.get("http3")
        if isinstance(protocol, dict):
            headers = protocol.get("headers")
            if isinstance(headers, dict):
                headers.pop("values", None)
    return transport


def _order_observation(orders: list[list[object]]) -> dict[str, object]:
    unique = list(dict.fromkeys(json.dumps(order) for order in orders))
    if len(orders) == 1:
        mode = "unknown"
    elif len(unique) == 1:
        mode = "fixed"
    else:
        mode = "permuted"
    return {
        "mode": mode,
        "observed": [json.loads(item) for item in unique],
    }


def _find_extension(
    extensions: list[dict[str, Any]], extension_id: int
) -> dict[str, Any]:
    for extension in extensions:
        if extension.get("id") == extension_id:
            return extension
    raise ValueError(f"Capture is missing required TLS extension {extension_id}")


def build_profile(samples: list[dict[str, Any]]) -> dict[str, Any]:
    if not samples:
        raise ValueError("At least one capture sample is required")
    normalized = [normalize_sample(sample) for sample in samples]
    stable_samples = [_stable_view(sample) for sample in normalized]
    serialized = [json.dumps(item, sort_keys=True) for item in stable_samples]
    counts = Counter(serialized)
    selected_serialized, selected_count = counts.most_common(1)[0]
    selected = json.loads(selected_serialized)
    selected_indexes = [
        index for index, value in enumerate(serialized) if value == selected_serialized
    ]

    tls_orders = [
        normalized[index]["tls_http2"]["tls"]["extension_order"]
        for index in selected_indexes
    ]
    http3_orders = [
        normalized[index]["http3"]["tls"]["extension_order"]
        for index in selected_indexes
    ]
    selected["tls_http2"]["tls"]["extension_order"] = _order_observation(tls_orders)
    selected["http3"]["tls"]["extension_order"] = _order_observation(http3_orders)
    parameter_orders = [
        _find_extension(normalized[index]["http3"]["tls"]["extensions"], 57)[
            "parameter_order"
        ]
        for index in selected_indexes
    ]
    _find_extension(selected["http3"]["tls"]["extensions"], 57)["parameter_order"] = (
        _order_observation(parameter_orders)
    )

    browser_identities = list(
        {
            json.dumps(item.get("browser", {}), sort_keys=True): item.get("browser", {})
            for item in normalized
        }.values()
    )
    variants = [
        {
            "digest": _digest(json.loads(value)),
            "sample_count": count,
            "selected": value == selected_serialized,
        }
        for value, count in counts.most_common()
    ]
    return {
        "schema_version": 1,
        "browser_identities": browser_identities,
        "sample_count": len(samples),
        "selected_sample_count": selected_count,
        "variant_count": len(variants),
        "variants": variants,
        "fingerprint": selected,
        "fingerprint_digest": _digest(fingerprint_comparison_view(selected)),
    }
