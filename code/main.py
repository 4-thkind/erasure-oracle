#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Run from the repository root:

    python code/main.py

Reads the participant dataset from ``dataset/`` and writes the submission file
to ``output.csv`` in the repository root.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_agent.pipeline import main as run  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(run())
