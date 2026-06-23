import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent

# The test suite is CodeQL-free: fixture DBs are committed (read via the
# pure-Python graph backend), and the graph producers are pinned by
# ``test_graph_golden`` instead of a fresh-CodeQL differential. No `codeql`
# binary is detected, invoked, or required.
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))   # the `security` package lives at src/security/
sys.path.insert(0, str(TESTS_DIR))
