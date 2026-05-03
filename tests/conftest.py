import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python-analysis"))

if "CODEQL" not in os.environ:
    found = shutil.which("codeql") or os.path.expanduser("~/tools/codeql/codeql")
    if Path(found).exists():
        os.environ["CODEQL"] = found
