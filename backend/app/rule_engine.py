from dataclasses import dataclass
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
        threshold=raw.get("threshold") if isinstance(raw.get("threshold"), dict) else None,
    )


def load_rules(directory: Path) -> list[DetectionRule]:
    rules: list[DetectionRule] = []
    for path in sorted(directory.rglob("*.yml")) + sorted(directory.rglob("*.yaml")):
        rules.append(load_rule(path))
    return [rule for rule in rules if rule.enabled]


def event_fields(event: dict[str, Any]) -> dict[str, Any]:
    fields = dict(event)
    raw = event.get("raw_data")
    if isinstance(raw, dict):
        fields.update(raw)
    return {str(k).lower(): v for k, v in fields.items()}


def _contains(value: Any, needle: str) -> bool:
    if value is None:
        return False
    return needle.lower() in str(value).lower()


def _match_field(actual: Any, expected: Any, modifier: str | None) -> bool:
    if modifier == "contains":
        if isinstance(expected, list):
            return any(_contains(actual, item) for item in expected)
        return _contains(actual, str(expected))
    if modifier == "startswith":
        if isinstance(expected, list):
            return any(str(actual).lower().startswith(str(item).lower()) for item in expected)
        return str(actual).lower().startswith(str(expected).lower())
    if modifier == "endswith":
        if isinstance(expected, list):
            return any(str(actual).lower().endswith(str(item).lower()) for item in expected)
        return str(actual).lower().endswith(str(expected).lower())
    if isinstance(expected, list):
        return any(str(actual).lower() == str(item).lower() for item in expected)
    return str(actual).lower() == str(expected).lower()


def rule_matches(rule: DetectionRule, event: dict[str, Any]) -> bool:
    if not rule.enabled:
        return False
    fields = event_fields(event)
    selections: dict[str, bool] = {}
    for selection_name, selection in rule.detection.items():
        if not isinstance(selection, dict):
            selections[selection_name] = False
            continue
        matched = True
        for key, expected in selection.items():
            parts = str(key).split("|")
            field_name = parts[0].lower()
            modifier = parts[1].lower() if len(parts) > 1 else None
            if not _match_field(fields.get(field_name), expected, modifier):
                matched = False
                break
        selections[selection_name] = matched

    condition = rule.condition.strip()
    if condition in selections:
        return selections[condition]
    # Minimal safe expression support for Sigma-style `sel1 or sel2` / `sel1 and sel2`.
    tokens = condition.replace("(", " ").replace(")", " ").split()
    if not tokens:
        return False
    result = selections.get(tokens[0], False)
    index = 1
    while index + 1 < len(tokens):
        operator = tokens[index].lower()
        rhs = selections.get(tokens[index + 1], False)
        if operator == "and":
            result = result and rhs
        elif operator == "or":
            result = result or rhs
        else:
            return False
        index += 2
    return bool(result)


def detect(events: list[dict[str, Any]], rules: list[DetectionRule]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for event in events:
        for rule in rules:
            if rule_matches(rule, event):
                matches.append({
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "description": rule.description,
                    "tags": list(rule.tags),
                    "event": event,
                })
    return matches
