#!/usr/bin/env python3
"""Pack and unpack an encrypted authorization-platform recovery kit.

The password is deliberately never stored in the kit. Keep the encrypted kit
on removable/offline storage and keep its password in a separate password
manager or separate sealed record.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import io
from pathlib import Path, PurePosixPath
import secrets
import stat
import struct
import sys
import tarfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AUTHORIZATION-RECOVERY-KIT-v1\0"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32


def password_from_args(password_file: Path | None) -> bytes:
    if password_file:
        value = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    else:
        value = getpass.getpass("Recovery kit password: ")
    if len(value) < 16:
        raise SystemExit("recovery kit password must contain at least 16 characters")
    return value.encode("utf-8")


def derive_key(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=KEY_BYTES, n=2**15, r=8, p=1).derive(password)


def safe_relative(name: str) -> str:
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"unsafe recovery-kit path: {name}")
    return path.as_posix()


def tar_directory(source: Path) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path in sorted(source.rglob("*")):
            relative = path.relative_to(source).as_posix()
            if not path.is_file() or path.is_symlink():
                continue
            safe_relative(relative)
            info = archive.gettarinfo(str(path), arcname=relative)
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            with path.open("rb") as handle:
                archive.addfile(info, handle)
    return output.getvalue()


def pack_directory(source: Path, output: Path, password: bytes) -> str:
    source = source.resolve()
    output = output.resolve()
    if not source.is_dir():
        raise ValueError(f"source directory does not exist: {source}")
    if output.exists():
        raise ValueError(f"refusing to overwrite existing kit: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    plaintext = tar_directory(source)
    header = MAGIC + salt + nonce
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(nonce, plaintext, header)
    output.write_bytes(header + struct.pack(">Q", len(ciphertext)) + ciphertext)
    try:
        output.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return hashlib.sha256(output.read_bytes()).hexdigest()


def unpack_kit(kit: Path, output: Path, password: bytes) -> None:
    if not kit.is_file():
        raise ValueError(f"kit does not exist: {kit}")
    if output.exists():
        raise ValueError(f"refusing to overwrite existing directory: {output}")
    raw = kit.read_bytes()
    header_size = len(MAGIC) + SALT_BYTES + NONCE_BYTES
    if len(raw) < header_size + 8 or raw[:len(MAGIC)] != MAGIC:
        raise ValueError("unsupported or corrupt recovery kit")
    header = raw[:header_size]
    salt = raw[len(MAGIC):len(MAGIC) + SALT_BYTES]
    nonce = raw[len(MAGIC) + SALT_BYTES:header_size]
    size = struct.unpack(">Q", raw[header_size:header_size + 8])[0]
    ciphertext = raw[header_size + 8:]
    if size != len(ciphertext):
        raise ValueError("truncated recovery kit")
    try:
        plaintext = AESGCM(derive_key(password, salt)).decrypt(nonce, ciphertext, header)
    except Exception as exc:
        raise ValueError("recovery kit password or contents are invalid") from exc
    output.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
            members = archive.getmembers()
            for member in members:
                name = safe_relative(member.name)
                destination = output / name
                destination.resolve().relative_to(output.resolve())
                if not member.isfile():
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open("wb") as target:
                    target.write(source.read())
                try:
                    destination.chmod(stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
    except BaseException:
        import shutil
        shutil.rmtree(output, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("pack")
    pack.add_argument("--source-dir", type=Path, required=True)
    pack.add_argument("--output", type=Path, required=True)
    pack.add_argument("--password-file", type=Path)
    unpack = sub.add_parser("unpack")
    unpack.add_argument("--kit", type=Path, required=True)
    unpack.add_argument("--output-dir", type=Path, required=True)
    unpack.add_argument("--password-file", type=Path)
    args = parser.parse_args()
    password = password_from_args(args.password_file)
    if args.command == "pack":
        digest = pack_directory(args.source_dir, args.output, password)
        print(f"recovery kit: {args.output.resolve()}")
        print(f"sha256: {digest}")
    else:
        unpack_kit(args.kit, args.output_dir, password)
        print(f"recovery kit unpacked: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
