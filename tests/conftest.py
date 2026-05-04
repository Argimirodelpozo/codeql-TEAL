import os
import shutil
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(TESTS_DIR))

if "CODEQL" not in os.environ:
    found = shutil.which("codeql") or os.path.expanduser("~/tools/codeql/codeql")
    if Path(found).exists():
        os.environ["CODEQL"] = found


def pytest_sessionstart(session):
    """Build any missing tealtools fixture DBs before tests run.

    Idempotent — DBs that already exist are left alone. Lives at
    session-start so the cost is paid once per pytest invocation
    rather than per-test.
    """
    if "CODEQL" not in os.environ:
        return  # tests will skip; nothing to build
    import build_dbs

    built, _ = build_dbs.build_all()
    if built:
        print(f"\n[conftest] built {built} missing tealtools fixture DB(s)")
