from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from .rule_engine import load_rules, rule_matches

router = APIRouter(prefix="/api/v1/rules", tags=["rules"])
RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "detections"


@router.get("")
def list_rules() -> dict[str, Any]:
    try:
        rules = load_rules(RULES_DIR)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "count": len(rules),
        "rules": [
            {
                "id": rule.id,
                "title": rule.title,
                "description": rule.description,
                "severity": rule.severity,
                "tags": list(rule.tags),
                "logsource": rule.logsource,
                "threshold": rule.threshold,
            }
            for rule in rules
        ],
    }


@router.post("/test")
def test_rules(event: dict[str, Any]) -> dict[str, Any]:
    try:
        rules = load_rules(RULES_DIR)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    matches = [
        {
            "rule_id": rule.id,
            "title": rule.title,
            "severity": rule.severity,
            "tags": list(rule.tags),
        }
        for rule in rules
        if rule_matches(rule, event)
    ]
    return {"matched": len(matches), "matches": matches}
