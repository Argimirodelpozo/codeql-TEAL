"""Explicit experimental policy obligations."""
import json
from pathlib import Path

from tealql.tealtools.diagnostics.errors import TealQLError
from ._common import _load_programs


def _run(args):
    from tealql.security.obligations import analyze_obligations, render_obligations
    try:
        policy = json.loads(Path(args.policy).read_text())
        reports = [analyze_obligations(prog, policy) for prog, _ in _load_programs(args)]
    except (ValueError, KeyError, TypeError) as error:
        raise TealQLError(f'invalid obligation policy: {error}') from error
    for report in reports:
        print(render_obligations(report))
    return 0 if reports and all(r['complete'] for r in reports) else 2


def register(sub, add):
    parser = add('obligations', 'experimental relational/state policy obligations (JSON)', _run)
    parser.add_argument('--policy', required=True, help='JSON obligation policy; see docs/OBLIGATIONS.md')
