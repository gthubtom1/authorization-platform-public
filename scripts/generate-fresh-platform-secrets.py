#!/usr/bin/env python3
"""Generate secrets for a brand-new, independent authorization platform.

This tool is deliberately separate from recovery. It never reads an existing
key bundle or database and refuses to overwrite an existing output directory.
Keep the output directory private and transfer only the required env files to
an explicitly approved server.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import os
import re
import secrets
import shutil
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.fernet import Fernet

from recovery_kit import pack_directory

ROOT = Path(__file__).resolve().parents[1]
ENV_FILES = (
    "production.env",
    "postgres.env",
    "object-store.env",
    "object-store-init.env",
    "compose.env",
)
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)


def token(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def fernet_key() -> str:
    return Fernet.generate_key().decode("ascii")


def ed25519_seed_and_public() -> tuple[str, str, bytes]:
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    return encode(seed), encode(public), seed


def read_example(name: str) -> str:
    path = ROOT / "deploy" / f"{name}.example"
    if not path.is_file():
        raise SystemExit(f"missing template: {path}")
    return path.read_text(encoding="utf-8")


def set_env(text: str, values: dict[str, str]) -> str:
    found = set()
    lines = []
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#") or "=" not in line:
            lines.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in values:
            line = f"{key}={values[key]}"
            found.add(key)
        lines.append(line)
    missing = sorted(set(values) - found)
    if missing:
        raise SystemExit("template is missing keys: " + ", ".join(missing))
    return "\n".join(lines) + "\n"


def write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def validate_domain(domain: str) -> None:
    if domain.startswith(("http://", "https://")) or not DOMAIN_RE.fullmatch(domain):
        raise SystemExit("--domain must be a confirmed hostname without http:// or https://")
    if domain.lower().endswith(".example.com"):
        raise SystemExit("--domain must be a real confirmed hostname, not an example domain")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--domain", required=True, help="confirmed hostname without scheme")
    parser.add_argument("--candidate-commit", required=True, help="deployed source commit SHA")
    parser.add_argument("--bundle-output", type=Path, help="optional encrypted recovery-kit output path")
    parser.add_argument("--bundle-password-file", type=Path, help="password file for non-interactive kit creation")
    args = parser.parse_args()
    validate_domain(args.domain)
    if not re.fullmatch(r"[0-9a-f]{7,64}", args.candidate_commit, re.IGNORECASE):
        raise SystemExit("--candidate-commit must be a Git commit SHA")

    output = args.output_dir.resolve()
    bundle_output = args.bundle_output.resolve() if args.bundle_output else None
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing directory: {output}")
    if bundle_output and bundle_output.parent == output or bundle_output and output in bundle_output.parents:
        raise SystemExit("--bundle-output must be outside --output-dir")
    output.mkdir(parents=True)
    try:
        authorization_seed, release_public, release_seed = ed25519_seed_and_public()
        database_password = token(32)
        minio_root_user = "minio" + secrets.token_hex(12)
        minio_root_password = token(32)
        object_access_user = "apobj" + secrets.token_hex(12)
        object_access_secret = token(32)
        values = {
            "DJANGO_SECRET_KEY": token(48),
            "ALLOWED_HOSTS": args.domain,
            "AUTHORIZATION_PUBLIC_BASE_URL": f"https://{args.domain}",
            "CSRF_TRUSTED_ORIGINS": f"https://{args.domain}",
            "DATABASE_PASSWORD": database_password,
            "INVITATION_ENCRYPTION_KEY": fernet_key(),
            "PASSWORD_OPERATION_HASH_KEY": token(32),
            "ACCOUNT_OPERATION_HASH_KEY": token(32),
            "QUOTA_CARD_HASH_KEY": token(32),
            "QUOTA_REDEEM_IP_HASH_KEY": token(32),
            "QUOTA_CARD_ENCRYPTION_KEY": fernet_key(),
            "QUOTA_CARD_LEGACY_ENCRYPTION_KEY": "",
            "LICENSE_CARD_HASH_KEY": token(32),
            "LICENSE_CARD_ENCRYPTION_KEY": fernet_key(),
            "LICENSE_CARD_LEGACY_ENCRYPTION_KEY": "",
            "AUTHORIZATION_NONCE_HASH_KEY": token(32),
            "AUTHORIZATION_DEVICE_HASH_KEY": token(32),
            "AUTHORIZATION_SIGNING_PRIVATE_KEY": authorization_seed,
            "AUTHORIZATION_SIGNING_KEY_ID": "platform-" + secrets.token_hex(8),
            "RELEASE_SIGNING_PUBLIC_KEY": release_public,
            "RELEASE_SIGNING_KEY_ID": "release-" + secrets.token_hex(8),
            "OBJECT_STORAGE_ACCESS_KEY_ID": object_access_user,
            "OBJECT_STORAGE_SECRET_ACCESS_KEY": object_access_secret,
            "BACKUP_CANDIDATE_COMMIT": args.candidate_commit,
        }
        env = set_env(read_example("production.env"), values)
        write_private(output / "production.env", env)
        write_private(output / "postgres.env", set_env(read_example("postgres.env"), {
            "POSTGRES_PASSWORD": database_password,
        }))
        write_private(output / "object-store.env", set_env(read_example("object-store.env"), {
            "MINIO_ROOT_USER": minio_root_user,
            "MINIO_ROOT_PASSWORD": minio_root_password,
        }))
        write_private(output / "object-store-init.env", set_env(read_example("object-store-init.env"), {
            "MINIO_ROOT_USER": minio_root_user,
            "MINIO_ROOT_PASSWORD": minio_root_password,
            "OBJECT_STORAGE_ACCESS_KEY_ID": object_access_user,
            "OBJECT_STORAGE_SECRET_ACCESS_KEY": object_access_secret,
        }))
        write_private(output / "compose.env", read_example("compose.env"))

        release_private = Ed25519PrivateKey.from_private_bytes(release_seed).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        (output / "release-signing-private.pem").write_bytes(release_private)
        try:
            (output / "release-signing-private.pem").chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        write_private(output / "README.txt", f"""FRESH PLATFORM SECRET SET

This directory belongs to one new, independent authorization platform.
It is not a recovery bundle and must never be mixed with another platform.
Keep this directory outside Git and restrict it to the deployment operator.

Copy these files to the matching deploy/ paths on the approved server:
{os.linesep.join('  ' + name for name in ENV_FILES)}

Keep release-signing-private.pem outside the server unless that server is also
an approved release-signing workstation. The public key is already in
production.env. Use scripts/build_release_manifest.py with the private key when
signing a release.

The generated platform signing key, card encryption keys, database password,
and object-store credentials must remain unchanged for this platform. Do not
run this tool during an upgrade or a recovery of an existing platform.

For a single removable-media disaster-recovery artifact, rerun this tool with
--bundle-output and a password stored separately from the encrypted kit. The
bundle contains these files and this README, but never contains its password.
""")
        if bundle_output:
            if args.bundle_password_file:
                password = args.bundle_password_file.read_text(encoding="utf-8").rstrip("\r\n").encode("utf-8")
            else:
                password = getpass.getpass("Recovery kit password: ").encode("utf-8")
            if len(password) < 16:
                raise SystemExit("bundle password must contain at least 16 characters")
            digest = pack_directory(output, bundle_output, password)
        else:
            digest = None
    except BaseException:
        shutil.rmtree(output)
        raise

    print(f"generated fresh platform secret set: {output}")
    print("files: " + ", ".join(ENV_FILES) + ", release-signing-private.pem, README.txt")
    if bundle_output:
        print(f"encrypted recovery kit: {bundle_output}")
        print(f"recovery kit sha256: {digest}")
    print("private values were written to files only; none were printed")
    print("next: copy the five env files to deploy/, then run install-site.sh and require VERIFY_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
