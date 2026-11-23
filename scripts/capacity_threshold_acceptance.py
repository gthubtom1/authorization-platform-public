"""Run the bounded capacity thresholds declared for a candidate environment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urljoin

from scripts.capacity_probe import evaluate_capacity, run_probe


def _load_thresholds(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"unable to read threshold file: {path}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("threshold file must use schema_version=1")
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("threshold file must contain at least one target")
    return document


def _positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def run_thresholds(
    base_url: str,
    threshold_file: Path,
    *,
    requests_override: int | None = None,
    concurrency_override: int | None = None,
    timeout_override: float | None = None,
) -> dict[str, Any]:
    base_url = base_url.rstrip("/") + "/"
    if not base_url.lower().startswith(("http://", "https://")):
        raise ValueError("base_url must use http or https")
    document = _load_thresholds(threshold_file)
    default_requests = _positive_int(document.get("requests"), field="requests")
    default_concurrency = _positive_int(document.get("concurrency"), field="concurrency")
    default_timeout = float(document.get("timeout_seconds", 5))
    if default_timeout <= 0:
        raise ValueError("timeout_seconds must be positive")

    results: list[dict[str, Any]] = []
    for target in document["targets"]:
        if not isinstance(target, dict):
            raise ValueError("each target must be an object")
        name = target.get("name")
        path = target.get("path")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("each target needs a non-empty name")
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError(f"target {name!r} path must start with '/'")
        requests = requests_override or _positive_int(target.get("requests", default_requests), field=f"{name}.requests")
        concurrency = concurrency_override or _positive_int(target.get("concurrency", default_concurrency), field=f"{name}.concurrency")
        timeout = float(timeout_override if timeout_override is not None else target.get("timeout_seconds", default_timeout))
        if timeout <= 0:
            raise ValueError(f"{name}.timeout_seconds must be positive")
        url = urljoin(base_url, path.lstrip("/"))
        report = run_probe(url, requests=requests, concurrency=concurrency, timeout=timeout)
        acceptance = evaluate_capacity(
            report,
            max_p95_ms=float(target.get("max_p95_ms", 1000)),
            max_transport_errors=int(target.get("max_transport_errors", 0)),
            max_429=int(target.get("max_429", 0)),
            expected_status=int(target.get("expected_status", 200)),
        )
        results.append({"name": name, "url": url, "probe": report, "acceptance": acceptance})

    return {
        "schema_version": 1,
        "profile": document.get("profile", ""),
        "base_url": base_url.rstrip("/"),
        "targets": results,
        "accepted": all(item["acceptance"]["accepted"] for item in results),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deploy/capacity-thresholds.json against a candidate base URL.")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--threshold-file", type=Path, default=Path("deploy/capacity-thresholds.json"))
    parser.add_argument("--requests", type=int)
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--timeout", type=float)
    args = parser.parse_args(argv)
    try:
        result = run_thresholds(
            args.base_url,
            args.threshold_file,
            requests_override=args.requests,
            concurrency_override=args.concurrency,
            timeout_override=args.timeout,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
