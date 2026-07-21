from dataclasses import dataclass
from typing import Any

from .capabilities import analyze_capabilities
from .models import CapabilityGap


CANONICAL_DISTRIBUTION = "consumer-chrome"


@dataclass(frozen=True, slots=True)
class ReadinessReport:
    ready: bool
    blockers: tuple[str, ...]
    capability_gaps: tuple[CapabilityGap, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "readiness_blockers": list(self.blockers),
            "capability_gaps": [gap.to_dict() for gap in self.capability_gaps],
        }


def evaluate_readiness(
    profile: dict[str, Any],
    distribution: str,
) -> ReadinessReport:
    blockers: list[str] = []
    if distribution != CANONICAL_DISTRIBUTION:
        blockers.append(
            f"capture must come from consumer Google Chrome Stable, not {distribution}"
        )
    if profile.get("sample_count", 0) < 3:
        blockers.append("at least three fresh samples are required")
    if profile.get("variant_count") != 1:
        blockers.append("capture contains more than one stable fingerprint variant")
    if profile.get("selected_sample_count") != profile.get("sample_count"):
        blockers.append("not every sample belongs to the selected fingerprint variant")

    identities = profile.get("browser_identities")
    if not isinstance(identities, list) or not identities:
        blockers.append("capture has no browser identity provenance")
    elif any(
        not isinstance(identity, dict) or identity.get("mode") != "headful"
        for identity in identities
    ):
        blockers.append("headless capture must be confirmed against headful Chrome")

    capability_gaps = tuple(analyze_capabilities(profile))
    return ReadinessReport(
        ready=not blockers and not capability_gaps,
        blockers=tuple(blockers),
        capability_gaps=capability_gaps,
    )
