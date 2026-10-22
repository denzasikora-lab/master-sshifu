#!/usr/bin/env python3
from pathlib import Path
import sys

# Изолированный системный Python импортирует только код рядом с этой точкой входа.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sshvpn.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
