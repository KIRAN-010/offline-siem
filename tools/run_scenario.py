"""Submit a SentinelX synthetic telemetry scenario to a local API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def load_events(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle if line.strip()]
    if not events:
        raise ValueError(f"No events found in {path}")
    return events


def post_json(url: str, payload: object) -> dict:
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Unable to reach SentinelX API at {url}: {exc.reason}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path, help="Path to a JSONL scenario file")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="SentinelX API base URL")
    args = parser.parse_args()

    events = load_events(args.scenario)
    result = post_json(f"{args.base_url.rstrip('/')}/api/v1/events", events)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
