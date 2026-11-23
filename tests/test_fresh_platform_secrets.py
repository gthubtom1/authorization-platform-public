from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/generate-fresh-platform-secrets.py"


def read_env(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


class FreshPlatformSecretTests(unittest.TestCase):
    def test_generates_a_complete_independent_secret_set_without_printing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fresh"
            bundle = Path(directory) / "usb" / "authorization-platform-recovery-kit.enc"
            password_file = Path(directory) / "kit-password.txt"
            password_file.write_text("separate-recovery-password-1234\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--output-dir",
                    str(output),
                    "--domain",
                    "auth-new.example.net",
                    "--candidate-commit",
                    "0123456789abcdef0123456789abcdef01234567",
                    "--bundle-output",
                    str(bundle),
                    "--bundle-password-file",
                    str(password_file),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertNotIn("replace-with", result.stdout)
            self.assertIn("private values were written to files only", result.stdout)
            self.assertTrue(bundle.is_file())
            self.assertNotIn(b"AUTHORIZATION_SIGNING_PRIVATE_KEY", bundle.read_bytes())
            restored = Path(directory) / "restored"
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/recovery_kit.py"),
                    "unpack",
                    "--kit",
                    str(bundle),
                    "--output-dir",
                    str(restored),
                    "--password-file",
                    str(password_file),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(
                (restored / "production.env").read_bytes(),
                (output / "production.env").read_bytes(),
            )
            production = read_env(output / "production.env")
            postgres = read_env(output / "postgres.env")
            object_store = read_env(output / "object-store.env")
            object_init = read_env(output / "object-store-init.env")
            required = (
                "DJANGO_SECRET_KEY",
                "INVITATION_ENCRYPTION_KEY",
                "PASSWORD_OPERATION_HASH_KEY",
                "ACCOUNT_OPERATION_HASH_KEY",
                "QUOTA_CARD_HASH_KEY",
                "QUOTA_CARD_ENCRYPTION_KEY",
                "LICENSE_CARD_HASH_KEY",
                "LICENSE_CARD_ENCRYPTION_KEY",
                "AUTHORIZATION_NONCE_HASH_KEY",
                "AUTHORIZATION_DEVICE_HASH_KEY",
                "AUTHORIZATION_SIGNING_PRIVATE_KEY",
                "RELEASE_SIGNING_PUBLIC_KEY",
                "RELEASE_SIGNING_KEY_ID",
            )
            for name in required:
                self.assertTrue(production[name])
                self.assertNotIn("replace-with", production[name])
            self.assertEqual(production["ALLOWED_HOSTS"], "auth-new.example.net")
            self.assertEqual(production["AUTHORIZATION_PUBLIC_BASE_URL"], "https://auth-new.example.net")
            self.assertEqual(production["CSRF_TRUSTED_ORIGINS"], "https://auth-new.example.net")
            self.assertEqual(production["BACKUP_CANDIDATE_COMMIT"], "0123456789abcdef0123456789abcdef01234567")
            self.assertEqual(postgres["POSTGRES_PASSWORD"], production["DATABASE_PASSWORD"])
            self.assertEqual(object_store["MINIO_ROOT_USER"], object_init["MINIO_ROOT_USER"])
            self.assertEqual(object_store["MINIO_ROOT_PASSWORD"], object_init["MINIO_ROOT_PASSWORD"])
            self.assertEqual(object_init["OBJECT_STORAGE_ACCESS_KEY_ID"], production["OBJECT_STORAGE_ACCESS_KEY_ID"])
            self.assertEqual(object_init["OBJECT_STORAGE_SECRET_ACCESS_KEY"], production["OBJECT_STORAGE_SECRET_ACCESS_KEY"])
            Fernet(production["INVITATION_ENCRYPTION_KEY"].encode())
            Fernet(production["QUOTA_CARD_ENCRYPTION_KEY"].encode())
            Fernet(production["LICENSE_CARD_ENCRYPTION_KEY"].encode())
            seed = base64.urlsafe_b64decode(production["AUTHORIZATION_SIGNING_PRIVATE_KEY"] + "==")
            self.assertEqual(len(seed), 32)
            release_private = serialization.load_pem_private_key(
                (output / "release-signing-private.pem").read_bytes(), password=None
            )
            public = release_private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            encoded_public = base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")
            self.assertEqual(encoded_public, production["RELEASE_SIGNING_PUBLIC_KEY"])

    def test_refuses_to_overwrite_existing_secret_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--output-dir",
                    str(output),
                    "--domain",
                    "auth-new.example.net",
                    "--candidate-commit",
                    "0123456789abcdef0123456789abcdef01234567",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to overwrite", result.stderr + result.stdout)
