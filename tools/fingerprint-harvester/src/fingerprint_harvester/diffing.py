from typing import Any

from .models import ProfileDifference


MISSING = object()


def _display_missing(value: object) -> object:
    return "<missing>" if value is MISSING else value


def _diff(
    before: object,
    after: object,
    path: str,
    differences: list[ProfileDifference],
) -> None:
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(before.keys() | after.keys()):
            child_path = f"{path}.{key}" if path else str(key)
            _diff(
                before.get(key, MISSING),
                after.get(key, MISSING),
                child_path,
                differences,
            )
        return

    if isinstance(before, list) and isinstance(after, list):
        for index in range(max(len(before), len(after))):
            previous = before[index] if index < len(before) else MISSING
            current = after[index] if index < len(after) else MISSING
            _diff(previous, current, f"{path}[{index}]", differences)
        return

    if before != after:
        differences.append(
            ProfileDifference(
                path=path,
                before=_display_missing(before),
                after=_display_missing(after),
            )
        )


def diff_profiles(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[ProfileDifference]:
    differences: list[ProfileDifference] = []
    _diff(before, after, "", differences)
    return differences
