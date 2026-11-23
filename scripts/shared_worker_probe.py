"""Run a bounded diagnostic cross-process Django cache counter probe.

``DatabaseCache.incr`` is a read/modify/write operation rather than an atomic
database increment, so this diagnostic is intentionally not a release gate.
The release gate is ``shared_rate_limit_probe.py``.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import secrets
import time
from typing import Sequence


def _worker(key: str, increments: int, result_queue) -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    import django

    django.setup()
    from django.core.cache import cache

    errors = 0
    for _ in range(increments):
        try:
            cache.incr(key)
        except (ValueError, TypeError):
            errors += 1
    result_queue.put({"errors": errors, "increments": increments})


def run_shared_worker_probe(*, workers: int = 2, increments: int = 20, confirm_isolated_target: bool = False) -> dict[str, object]:
    if not confirm_isolated_target:
        raise ValueError("必须确认这是可丢弃的隔离目标")
    if os.getenv("APP_ENV", "local").strip().lower() == "production":
        raise ValueError("共享 Worker probe 拒绝 APP_ENV=production")
    if os.getenv("DATABASE_ENGINE", "").strip().lower() != "postgresql":
        raise ValueError("共享 Worker probe 要求 PostgreSQL 目标")
    if os.getenv("DATABASE_HOST", "").strip() not in {"127.0.0.1", "::1"}:
        raise ValueError("共享 Worker probe 只允许 loopback PostgreSQL")
    if not os.getenv("DATABASE_NAME", "").strip() or not os.getenv("DATABASE_PORT", "").strip():
        raise ValueError("共享 Worker probe 缺少隔离数据库配置")
    backend = os.getenv("DJANGO_CACHE_BACKEND", "")
    if "locmem" in backend.lower() or not backend:
        raise ValueError("共享 Worker probe 要求显式共享 Django cache backend")
    if workers < 2 or workers > 8 or increments < 1 or increments > 1000:
        raise ValueError("workers 或 increments 超出有界验收范围")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    import django

    django.setup()
    from django.core.cache import cache

    key = f"authorization-shared-worker-probe:{secrets.token_hex(8)}"
    cache.set(key, 0, timeout=120)
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    processes = [context.Process(target=_worker, args=(key, increments, result_queue)) for _ in range(workers)]
    started = time.perf_counter()
    for process in processes:
        process.start()
    for process in processes:
        process.join(120)
    timed_out = any(process.is_alive() for process in processes)
    for process in processes:
        if process.is_alive():
            process.terminate()
        process.join(5)
    results = []
    while not result_queue.empty():
        results.append(result_queue.get())
    observed = cache.get(key)
    cache.delete(key)
    expected = workers * increments
    return {
        "schema_version": 1,
        "workers": workers,
        "increments_per_worker": increments,
        "expected": expected,
        "observed": observed,
        "worker_results": len(results),
        "worker_errors": sum(int(item.get("errors", 0)) for item in results),
        "timed_out": timed_out,
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "passed": not timed_out and len(results) == workers and observed == expected and all(process.exitcode == 0 for process in processes),
        "secret_values_exposed": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe shared Django cache semantics across worker processes.")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--increments", type=int, default=20)
    parser.add_argument("--confirm-isolated-target", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run_shared_worker_probe(workers=args.workers, increments=args.increments, confirm_isolated_target=args.confirm_isolated_target)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
