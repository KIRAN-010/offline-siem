from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


SEVERITIES = {"low", "medium", "high", "critical"}


@dataclass(frozen=True)
class DetectionRule:
    id: str
    title: str
    description: str
    severity: str
    detection: dict[str, Any]
    condition: str
    tags: tuple[str, ...]
    enabled: bool = True
    logsource: dict[str, Any] | None = None
    threshold: dict[str, Any] | None = None


class RuleValidationError(ValueError):
    pass


def load_rule(path: Path) -> DetectionRule:
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise RuleValidationError(f"Rule {path} must contain a YAML object")
    for key in ("id", "title", "severity", "detection"):
        if key not in raw:
            raise RuleValidationError(f"Rule {path} is missing required field: {key}")
    severity = str(raw["severity"]).lower()
    if severity not in SEVERITIES:
        raise RuleValidationError(f"Unsupported severity: {severity}")
    detection = raw["detection"]
    if not isinstance(detection, dict) or not detection:
        raise RuleValidationError(f"Rule {path} detection must be a non-empty mapping")
    tags = raw.get("tags", [])
    if not isinstance(tags, list):
        raise RuleValidationError(f"Rule {path} tags must be a list")
    threshold = raw.get("threshold")
    if threshold is not None and not isinstance(threshold, dict):
        raise RuleValidationError(f"Rule {path} threshold must be a mapping")
    if isinstance(threshold, dict):
        count = threshold.get("count")
        timeframe = threshold.get("timeframe_seconds")
        if count is not None and (not isinstance(count, int) or count < 1):
            raise RuleValidationError(f"Rule {path} threshold count must be a positive integer")
        if timeframe is not None and (not isinstance(timeframe, int) or timeframe < 1):
            raise RuleValidationError(f"Rule {path} threshold timeframe_seconds must be a positive integer")
    return DetectionRule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        description=str(raw.get("description", "")),
        severity=severity,
        detection=detection,
        condition=str(raw.get("condition", "selection")),
        tags=tuple(str(tag) for tag in tags),
        enabled=bool(raw.get("enabled", True)),
        logsource=raw.get("logsource") if isinstance(raw.get("logsource"), dict) else None,
        threshold=threshold,
    )


def load_rules(directory: Path) -> list[DetectionRule]:
    paths = sorted(set(directory.rglob("*.yml")) | set(directory.rglob("*.yaml")))
    return [rule for rule in (load_rule(path) for path in paths) if rule.enabled]


def event_fields(event: dict[str, Any]) -> dict[str, Any]:
    fields = dict(event)
    raw = event.get("raw_data")
    if isinstance(raw, dict):
        fields.update(raw)
    return {str(k).lower(): v for k, v in fields.items()}


def _contains(value: Any, needle: str) -> bool:
    return value is not None and needle.lower() in str(value).lower()


def _match_field(actual: Any, expected: Any, modifier: str | None) -> bool:
    expected_values = expected if isinstance(expected, list) else [expected]
    if modifier == "contains":
        return any(_contains(actual, str(item)) for item in expected_values)
    if modifier == "startswith":
        return any(str(actual).lower().startswith(str(item).lower()) for item in expected_values)
    if modifier == "endswith":
        return any(str(actual).lower().endswith(str(item).lower()) for item in expected_values)
    return any(str(actual).lower() == str(item).lower() for item in expected_values)


def rule_matches(rule: DetectionRule, event: dict[str, Any]) -> bool:
    if not rule.enabled:
        return False
    fields = event_fields(event)
    selections: dict[str, bool] = {}
    for selection_name, selection in rule.detection.items():
        if not isinstance(selection, dict):
            selections[selection_name] = False
            continue
        selections[selection_name] = all(
            _match_field(
                fields.get(str(key).split("|")[0].lower()),
                expected,
                str(key).split("|")[1].lower() if "|" in str(key) else None,
            )
            for key, expected in selection.items()
        )

    tokens = rule.condition.replace("(", " ").replace(")", " ").split()
    if len(tokens) == 1:
        return selections.get(tokens[0], False)
    if not tokens:
        return False
    result = selections.get(tokens[0], False)
    for index in range(1, len(tokens), 2):
        if index + 1 >= len(tokens):
            return False
        operator = tokens[index].lower()
        rhs = selections.get(tokens[index + 1], False)
        if operator == "and":
            result = result and rhs
        elif operator == "or":
            result = result or rhs
        else:
            return False
    return bool(result)


def _event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("timestamp")
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _threshold_key(rule: DetectionRule, event: dict[str, Any]) -> tuple[str, str]:
    fields = event_fields(event)
    return rule.id, str(fields.get("source_ip") or fields.get("ip") or fields.get("username") or "*")


def threshold_matches(rule: DetectionRule, events: list[dict[str, Any]], event: dict[str, Any]) -> bool:
    if not rule.threshold or "count" not in rule.threshold:
        return True
    current_time = _event_time(event)
    if current_time is None:
        return False
    count = int(rule.threshold["count"])
    timeframe = int(rule.threshold.get("timeframe_seconds", 300))
    key = _threshold_key(rule, event)
    matching_events = []
    for candidate in events:
        candidate_time = _event_time(candidate)
        if candidate_time is None or _threshold_key(rule, candidate) != key:
            continue
        if abs((current_time - candidate_time).total_seconds()) <= timeframe and rule_matches(rule, candidate):
            matching_events.append(candidate)
    return len(matching_events) >= count


def detect(events: list[dict[str, Any]], rules: list[DetectionRule]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for rule in rules:
        for event in events:
            if rule_matches(rule, event) and threshold_matches(rule, events, event):
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "description": rule.description,
                    "tags": list(rule.tags),
                    "event": event,
                })
    return matches
