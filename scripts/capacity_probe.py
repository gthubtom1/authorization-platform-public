"""Bounded, dependency-free HTTP capacity probe for a local candidate."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class ProbeResult:
    status_code: int | None
    elapsed_ms: float
    error: str | None


def _request(url: str, timeout: float) -> ProbeResult:
    started = time.perf_counter()
    try:
        request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read(1024)
            status = int(response.status)
        return ProbeResult(status_code=status, elapsed_ms=(time.perf_counter() - started) * 1000, error=None)
    except urllib.error.HTTPError as exc:
        return ProbeResult(status_code=int(exc.code), elapsed_ms=(time.perf_counter() - started) * 1000, error=None)
    except (OSError, TimeoutError) as exc:
        return ProbeResult(status_code=None, elapsed_ms=(time.perf_counter() - started) * 1000, error=exc.__class__.__name__)


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return round(ordered[index], 2)


def run_probe(url: str, *, requests: int = 20, concurrency: int = 4, timeout: float = 5.0) -> dict[str, object]:
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("url must use http or https")
    if requests < 1 or requests > 5000:
        raise ValueError("requests must be between 1 and 5000")
    if concurrency < 1 or concurrency > 64:
        raise ValueError("concurrency must be between 1 and 64")
    if timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be greater than 0 and at most 60 seconds")

    started = time.perf_counter()
    results: list[ProbeResult] = []
    with ThreadPoolExecutor(max_workers=min(concurrency, requests), thread_name_prefix="capacity-probe") as pool:
        futures = [pool.submit(_request, url, timeout) for _ in range(requests)]
        for future in as_completed(futures):
            results.append(future.result())
    elapsed = max(time.perf_counter() - started, 0.000001)
    latencies = [item.elapsed_ms for item in results]
    status_counts: dict[str, int] = {}
    for item in results:
        key = str(item.status_code) if item.status_code is not None else "error"
        status_counts[key] = status_counts.get(key, 0) + 1
    errors = [item.error for item in results if item.error]
    return {
        "schema_version": 1,
        "url": url,
        "requests": len(results),
        "concurrency": min(concurrency, requests),
        "elapsed_seconds": round(elapsed, 3),
        "requests_per_second": round(len(results) / elapsed, 2),
        "status_counts": status_counts,
        "http_429": status_counts.get("429", 0),
        "transport_errors": len(errors),
        "latency_ms": {
            "min": round(min(latencies), 2) if latencies else None,
            "mean": round(statistics.mean(latencies), 2) if latencies else None,
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "max": round(max(latencies), 2) if latencies else None,
        },
        "errors": sorted(set(errors)),
    }


def evaluate_capacity(
    result: dict[str, object],
    *,
    max_p95_ms: float = 1000.0,
    max_transport_errors: int = 0,
    max_429: int = 0,
    expected_status: int = 200,
) -> dict[str, object]:
    """Apply the bounded candidate SLO to a probe result without hiding failures."""
    reasons: list[str] = []
    transport_errors = int(result.get("transport_errors", 0))
    http_429 = int(result.get("http_429", 0))
    status_counts = result.get("status_counts", {})
    expected_count = int(status_counts.get(str(expected_status), 0)) if isinstance(status_counts, dict) else 0
    request_count = int(result.get("requests", 0))
    latency = result.get("latency_ms", {})
    p95 = latency.get("p95") if isinstance(latency, dict) else None
    if transport_errors > max_transport_errors:
        reasons.append("transport_errors")
    if http_429 > max_429:
        reasons.append("http_429")
    if expected_count != request_count:
        reasons.append("unexpected_status")
    if p95 is None or float(p95) > max_p95_ms:
        reasons.append("p95_latency")
    return {
        "accepted": not reasons,
        "failure_reasons": reasons,
        "thresholds": {
            "max_p95_ms": max_p95_ms,
            "max_transport_errors": max_transport_errors,
            "max_429": max_429,
            "expected_status": expected_status,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a bounded HTTP capacity probe.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--requests", type=int, default=20)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-p95-ms", type=float, default=1000.0)
    parser.add_argument("--max-transport-errors", type=int, default=0)
    parser.add_argument("--max-429", type=int, default=0)
    parser.add_argument("--expected-status", type=int, default=200)
    args = parser.parse_args(argv)
    try:
        result = run_probe(args.url, requests=args.requests, concurrency=args.concurrency, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))
    result["acceptance"] = evaluate_capacity(
        result,
        max_p95_ms=args.max_p95_ms,
        max_transport_errors=args.max_transport_errors,
        max_429=args.max_429,
        expected_status=args.expected_status,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["acceptance"]["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
