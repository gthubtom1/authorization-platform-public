"""Bounded cross-process probe for the real shared rate-limit implementation.

The probe is deliberately limited to a disposable loopback PostgreSQL target. It
executes ``rate_limit.allow`` in separate processes so a local per-process cache
cannot make the result look shared. The two phases are a positive control (one
identity is allowed once) and a negative control (distinct identities are not
mistakenly throttled together).
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import queue
import secrets
import time
from collections.abc import Mapping, Sequence


class ProbeConfigurationError(ValueError):
    """Raised when the probe target is not an approved isolated environment."""


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})
_DATABASE_CACHE_BACKEND = "django.core.cache.backends.db.DatabaseCache"


def _environment(values: Mapping[str, str] | None) -> dict[str, str]:
    source = os.environ if values is None else values
    return {str(key): str(value) for key, value in source.items()}


def validate_probe_environment(
    values: Mapping[str, str] | None = None,
    *,
    confirm_isolated_target: bool,
) -> dict[str, str]:
    """Validate the bounded, non-production target without printing secrets."""

    if not confirm_isolated_target:
        raise ProbeConfigurationError("必须确认这是可丢弃的隔离目标")
    env = _environment(values)
    if env.get("APP_ENV", "local").strip().lower() == "production":
        raise ProbeConfigurationError("共享限流 probe 拒绝 APP_ENV=production")
    if env.get("DATABASE_ENGINE", "").strip().lower() != "postgresql":
        raise ProbeConfigurationError("共享限流 probe 要求 PostgreSQL 目标")
    if env.get("DATABASE_HOST", "").strip() not in _LOOPBACK_HOSTS:
        raise ProbeConfigurationError("共享限流 probe 只允许 loopback PostgreSQL")
    if env.get("DJANGO_CACHE_BACKEND", "").strip() != _DATABASE_CACHE_BACKEND:
        raise ProbeConfigurationError("共享限流 probe 要求 Django DatabaseCache")
    required = (
        "DATABASE_NAME",
        "DATABASE_USER",
        "DATABASE_PASSWORD",
        "DATABASE_PORT",
        "DJANGO_CACHE_LOCATION",
    )
    missing = [name for name in required if not env.get(name, "").strip()]
    if missing:
        raise ProbeConfigurationError("共享限流 probe 缺少隔离配置：" + ",".join(missing))
    try:
        port = int(env["DATABASE_PORT"])
    except ValueError as exc:
        raise ProbeConfigurationError("共享限流 probe 的 PostgreSQL 端口无效") from exc
    if not 1 <= port <= 65535:
        raise ProbeConfigurationError("共享限流 probe 的 PostgreSQL 端口超出范围")
    return env


def evaluate_phase(
    *,
    name: str,
    workers: int,
    results: Sequence[Mapping[str, object]],
    timed_out: bool,
    exit_codes: Sequence[int | None],
    expected_allowed: int,
    expected_rejected: int,
) -> dict[str, object]:
    """Evaluate a phase and fail closed for incomplete or malformed fixtures."""

    allowed = sum(item.get("allowed") is True for item in results)
    rejected = sum(item.get("allowed") is False for item in results)
    errors = sum(
        item.get("error") not in (None, "") or item.get("allowed") not in (True, False)
        for item in results
    )
    passed = (
        not timed_out
        and len(results) == workers
        and len(exit_codes) == workers
        and all(code == 0 for code in exit_codes)
        and errors == 0
        and allowed == expected_allowed
        and rejected == expected_rejected
    )
    return {
        "name": name,
        "workers": workers,
        "worker_results": len(results),
        "allowed": allowed,
        "rejected": rejected,
        "errors": errors,
        "timed_out": timed_out,
        "exit_codes": list(exit_codes),
        "expected_allowed": expected_allowed,
        "expected_rejected": expected_rejected,
        "passed": passed,
    }


def _worker(scope: str, identity: str, limit: int, start_event, result_queue) -> None:
    try:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
        import django

        django.setup()
        from authorization_platform.accounts.rate_limit import allow

        if not start_event.wait(60):
            result_queue.put({"allowed": None, "error": "start_timeout"})
            return
        result_queue.put({"allowed": bool(allow(scope, identity, limit=limit)), "error": None})
    except Exception as exc:  # pragma: no cover - exercised by the isolated runner
        result_queue.put({"allowed": None, "error": type(exc).__name__})


def _run_phase(
    *,
    scope: str,
    identities: Sequence[str],
    workers: int,
    limit: int,
) -> dict[str, object]:
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = [
        context.Process(target=_worker, args=(scope, identity, limit, start_event, result_queue))
        for identity in identities
    ]
    started = time.perf_counter()
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(60)
    timed_out = any(process.is_alive() for process in processes)
    for process in processes:
        if process.is_alive():
            process.terminate()
        process.join(5)
    results: list[Mapping[str, object]] = []
    for _ in range(workers):
        try:
            item = result_queue.get(timeout=1)
        except queue.Empty:
            break
        if isinstance(item, Mapping):
            results.append(item)
    report = evaluate_phase(
        name="same_identity" if len(set(identities)) == 1 else "different_identity",
        workers=workers,
        results=results,
        timed_out=timed_out,
        exit_codes=[process.exitcode for process in processes],
        expected_allowed=1 if len(set(identities)) == 1 else workers,
        expected_rejected=workers - 1 if len(set(identities)) == 1 else 0,
    )
    report["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return report


def run_rate_limit_probe(
    *,
    workers: int = 2,
    limit: int = 1,
    confirm_isolated_target: bool = False,
) -> dict[str, object]:
    """Run shared-identity and distinct-identity rate-limit controls."""

    env = validate_probe_environment(confirm_isolated_target=confirm_isolated_target)
    if workers < 2 or workers > 8 or limit != 1:
        raise ProbeConfigurationError("限流 probe 只接受 2-8 个 Worker 且 limit 必须为 1")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    import django

    django.setup()
    from authorization_platform.accounts.rate_limit import reset

    scope = "shared-worker-rate-limit-probe"
    nonce = secrets.token_hex(8)
    same_identity = f"{scope}:same:{nonce}"
    different_identities = [f"{scope}:different:{nonce}:{index}" for index in range(workers)]
    reset(scope, same_identity)
    for identity in different_identities:
        reset(scope, identity)
    try:
        same_report = _run_phase(
            scope=scope,
            identities=[same_identity] * workers,
            workers=workers,
            limit=limit,
        )
        different_report = _run_phase(
            scope=scope,
            identities=different_identities,
            workers=workers,
            limit=limit,
        )
    finally:
        reset(scope, same_identity)
        for identity in different_identities:
            reset(scope, identity)
    passed = bool(same_report["passed"] and different_report["passed"])
    return {
        "schema_version": 1,
        "workers": workers,
        "limit": limit,
        "target": {
            "database_engine": env["DATABASE_ENGINE"],
            "database_host": "loopback",
            "cache_backend": "DatabaseCache",
        },
        "same_identity": same_report,
        "different_identity": different_report,
        "passed": passed,
        "secret_values_exposed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe the real shared Django rate limiter across workers.")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--confirm-isolated-target", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_rate_limit_probe(
            workers=args.workers,
            limit=args.limit,
            confirm_isolated_target=args.confirm_isolated_target,
        )
    except ProbeConfigurationError as exc:
        parser.error(str(exc))
    except Exception as exc:  # pragma: no cover - environment-specific failure
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "passed": False,
                    "error_type": type(exc).__name__,
                    "secret_values_exposed": False,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
