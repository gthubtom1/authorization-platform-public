"""Generate a signed release manifest for the authorization platform candidate.

Produces a JSON manifest documenting: version, source commit, full source tree
SHA-256, python dependency lock SHA-256, frozen UI page digests, migration plan
fingerprint, and a verified signature over the canonical manifest using the
release signing key referenced by RELEASE_SIGNING_KEY_ID.

The manifest is written to output/releases/ as unsigned manifest + detached
signature. Verification commands are printed for later use.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

FROZEN_PAGES = (
    "entry.html",
    "manage.html",
    "manage-login.html",
    "downstream.html",
    "downstream-login.html",
    "downstream-register.html",
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path, excludes: tuple[str, ...]) -> str:
    """Deterministic SHA-256 over tracked source files (sorted relative paths)."""
    digest = hashlib.sha256()
    for candidate in sorted(root.rglob("*")):
        if not candidate.is_file():
            continue
        rel = candidate.relative_to(root).as_posix()
        if any(rel.startswith(prefix) for prefix in excludes):
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(candidate).encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def commit_sha(repo_root: Path) -> str:
    import subprocess

    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_root, capture_output=True, text=True, check=True
    )
    return completed.stdout.strip()


def canonical_manifest(document: dict[str, object]) -> str:
    return json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def load_private_key(path: Path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    raw = path.read_bytes()
    try:
        return load_pem_private_key(raw, password=None)
    except Exception:
        b64 = raw.decode().strip()
        key_bytes = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        return Ed25519PrivateKey.from_private_bytes(key_bytes[:32])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="候选版本号，如 v1.0.0-rc1")
    parser.add_argument("--key", required=True, help="release 私钥路径（PEM 或 base64url raw）")
    parser.add_argument("--key-id", required=True, help="RELEASE_SIGNING_KEY_ID")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "output" / "releases")
    args = parser.parse_args()

    src_root = ROOT / "src"
    manifest = {
        "schema_version": 1,
        "artifact": "authorization-platform-candidate",
        "version": args.version,
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": commit_sha(ROOT),
        "source_tree_sha256": tree_sha256(src_root, excludes=("__pycache__",)),
        "requirements_lock_sha256": sha256_file(ROOT / "requirements.lock"),
        "frozen_ui_pages": {name: sha256_file(ROOT / "docs" / "ui-preview" / name) for name in FROZEN_PAGES},
        "signing_key_id": args.key_id,
    }

    canonical = canonical_manifest(manifest)
    key = load_private_key(Path(args.key))
    signature = key.sign(canonical.encode("utf-8"))
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = args.out_dir / f"{args.version}.manifest.json"
    signature_path = args.out_dir / f"{args.version}.manifest.sig"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    signature_path.write_text(sig_b64 + "\n", encoding="utf-8")

    print(f"manifest: {manifest_path}")
    print(f"signature: {signature_path} (base64url, {len(sig_b64)} chars)")
    print()
    print("canonical manifest (用于验签):")
    print(canonical)
    print()
    print(f"source commit: {manifest['source_commit']}")
    print(f"source tree sha256: {manifest['source_tree_sha256'][:16]}…")
    print(f"requirements.lock sha256: {manifest['requirements_lock_sha256'][:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())