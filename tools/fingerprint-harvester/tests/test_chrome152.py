from copy import deepcopy
from pathlib import Path

import pytest

from fingerprint_harvester.bundle import (
    load_bundle_samples,
    load_json,
    write_capture_bundle,
)
from fingerprint_harvester.capabilities import analyze_capabilities
from fingerprint_harvester.compiler import candidate_from_bundle
from fingerprint_harvester.normalize import build_profile, normalize_sample
from fingerprint_harvester.replay import compare_replay
from test_harvester import make_sample


@pytest.mark.parametrize("platform", ["linux", "win64", "mac", "mac_arm64", "android"])
def test_retained_chrome152_samples_normalize_to_the_verified_profile(platform):
    bundle = Path(__file__).parents[3] / "profiles/evidence/chrome152" / platform
    profile = build_profile(load_bundle_samples(bundle))
    assert profile == load_json(bundle / "profile.json")
    assert profile["variant_count"] == 1
    assert profile["selected_sample_count"] == 5
    assert analyze_capabilities(profile) == []


@pytest.mark.parametrize("codepoint", range(0x0A0A, 0x10000, 0x1010))
def test_numeric_signature_grease_does_not_create_variants(codepoint, tmp_path):
    first = make_sample(signature_algorithms=["0xa0a", "ecdsa_secp256r1_sha256"])
    second = make_sample(
        signature_algorithms=[hex(codepoint), "ecdsa_secp256r1_sha256"]
    )
    third = make_sample(signature_algorithms=[codepoint, "ecdsa_secp256r1_sha256"])
    bundle = tmp_path / "capture"
    profile = write_capture_bundle(
        bundle, [first, second, third], distribution="consumer-chrome"
    )
    assert profile["variant_count"] == 1
    assert analyze_capabilities(profile) == []
    options = candidate_from_bundle(bundle, "chrome152")["options"]
    assert options["signature_algorithms"] == ["GREASE", "ecdsa_secp256r1_sha256"]
    assert options["http3_signature_algorithms"] == ["GREASE", "ecdsa_secp256r1_sha256"]


def test_signature_grease_value_overrides_unknown_collector_name():
    sample = make_sample()
    extension = next(
        item for item in sample["http3"]["tls"]["extensions"] if item["id"] == 13
    )
    extension["data"]["algorithms"].insert(0, {"name": "Unknown", "value": 0xFAFA})
    normalized = normalize_sample(sample)
    algorithms = next(
        item for item in normalized["http3"]["tls"]["extensions"] if item["id"] == 13
    )["algorithms"]
    assert algorithms[0] == "GREASE"


def test_signature_grease_position_must_be_representable():
    sample = make_sample(signature_algorithms=["ecdsa_secp256r1_sha256", "0xaaaa"])
    profile = build_profile([sample, deepcopy(sample), deepcopy(sample)])
    assert any(
        gap.feature == "TLS signature algorithm GREASE position"
        for gap in analyze_capabilities(profile)
    )


@pytest.mark.parametrize("quic_only", [False, True])
def test_trust_anchor_permutation_and_protocol_overrides(tmp_path, quic_only):
    first = make_sample(extra_extensions=[(51764, "00050101028101")])
    second = make_sample(extra_extensions=[(51764, "00050281010101")])
    if quic_only:
        for sample in (first, second):
            sample["tls_http2"]["tls"]["extensions"] = [
                item
                for item in sample["tls_http2"]["tls"]["extensions"]
                if item["name"] != "Unknown extension 51764"
            ]
    bundle = tmp_path / "capture"
    profile = write_capture_bundle(
        bundle, [first, second, deepcopy(first)], distribution="consumer-chrome"
    )
    assert profile["variant_count"] == 1
    assert analyze_capabilities(profile) == []
    anchor = next(
        item
        for item in profile["fingerprint"]["http3"]["tls"]["extensions"]
        if item["id"] == 51764
    )
    assert anchor["ids"] == ["1", "129"]
    assert anchor["id_order"]["mode"] == "permuted"
    options = candidate_from_bundle(bundle, "chrome152")["options"]
    assert options["http3_tls_trust_anchors"] == "1,129"
    assert ("tls_trust_anchors" in options) == (not quic_only)


def test_fixed_trust_anchor_order_and_quic_omission(tmp_path):
    sample = make_sample(extra_extensions=[(51764, "00050281010101")])
    sample["http3"]["tls"]["extensions"] = [
        item for item in sample["http3"]["tls"]["extensions"] if item["id"] != 51764
    ]
    bundle = tmp_path / "capture"
    write_capture_bundle(
        bundle,
        [sample, deepcopy(sample), deepcopy(sample)],
        distribution="consumer-chrome",
    )
    options = candidate_from_bundle(bundle, "chrome152")["options"]
    assert options["tls_trust_anchors"] == "fixed:129,1"
    assert options["http3_tls_trust_anchors"] == "none"


def test_changed_trust_anchor_ids_remain_distinct():
    first = make_sample(extra_extensions=[(51764, "00050101028101")])
    second = make_sample(extra_extensions=[(51764, "00050101028102")])
    assert build_profile([first, second])["variant_count"] == 2


def test_replay_rejects_an_outlier_even_when_the_majority_matches(tmp_path):
    sample = make_sample()
    bundle = tmp_path / "capture"
    write_capture_bundle(
        bundle,
        [sample, deepcopy(sample), deepcopy(sample)],
        distribution="consumer-chrome",
    )
    outlier = make_sample(signature_algorithms=["ed25519"])
    _, differences = compare_replay(bundle, [sample, deepcopy(sample), outlier])
    assert any(item.path == "capture.variant_count" for item in differences)


def test_captured_connection_id_lengths_are_compiled(tmp_path):
    sample = make_sample()
    sample["http3"]["http3"]["perk_text_normalized"] += "|0,8"
    bundle = tmp_path / "capture"
    write_capture_bundle(
        bundle,
        [sample, deepcopy(sample), deepcopy(sample)],
        distribution="consumer-chrome",
    )
    assert (
        candidate_from_bundle(bundle, "chrome152")["options"]["quic_cid_length"]
        == "webkit"
    )


@pytest.mark.parametrize(
    "wire", ["", "xyz", "0001", "000100", "000201", "00020180", "0003028001"]
)
def test_invalid_trust_anchor_encoding_is_rejected(wire):
    with pytest.raises(ValueError, match="TLS trust anchor"):
        normalize_sample(make_sample(extra_extensions=[(51764, wire)]))
