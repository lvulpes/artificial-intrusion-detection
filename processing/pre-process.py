#!/usr/bin/env python3
"""Feature extraction pipeline entry point.

    python3 processing/pre-process.py extract --manifest manifest.csv --out output [--config processing/config.yaml]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from extraction.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
