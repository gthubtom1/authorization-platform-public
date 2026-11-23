#!/usr/bin/env python
"""Django's command-line utility for the authorization platform."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parent
    sys.path.insert(0, str(root / "src"))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authorization_platform.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
