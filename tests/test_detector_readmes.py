"""Every detector README carries remediation guidance that the detector itself credits.

The READMEs are shipped as SARIF ``help.markdown``, through the agent's
``list_detectors`` tool and ``security.description_of()``, so a fix pattern that
the detector would STILL flag is a wrong instruction delivered everywhere at once.

Each README must have a ``## How to fix`` section with at least one fenced
```` ```teal ```` block and a ``## False positives`` section. A TEAL block preceded
by ``<!-- verify: <detector> clean -->`` is a complete program that must yield NO
finding for that detector; ``<!-- verify: <detector> finding -->`` marks the
vulnerable counterpart, which must yield at least one (the control that proves the
clean block is clean because of its guard, not because the detector is blind).
"""
import re

import pytest

from tealql.security import DETECTORS, description_of, readme_of
from tealql.tealtools.ssa import SSAProgram

_VERIFY_RE = re.compile(
    r"<!--\s*verify:\s*([\w\-]+)\s+(clean|finding)\s*-->\s*\n```teal\n(.*?)```",
    re.S)


def _section(text: str, heading: str) -> str:
    m = re.search(rf"^## {re.escape(heading)}\s*$(.*?)(?=^## |\Z)", text, re.M | re.S)
    return m.group(1) if m else ""


def _verify_blocks():
    for det in sorted(DETECTORS):
        for i, (target, expect, body) in enumerate(_VERIFY_RE.findall(readme_of(det))):
            yield pytest.param(det, target, expect, body, id=f"{det}#{i}-{expect}")


@pytest.mark.parametrize("det", sorted(DETECTORS))
def test_readme_has_remediation(det):
    text = readme_of(det)
    fix = _section(text, "How to fix")
    assert fix, f"{det}: README has no '## How to fix' section"
    assert "```teal" in fix, f"{det}: '## How to fix' has no ```teal block"
    assert re.search(r"<!--\s*verify:\s*" + re.escape(det) + r"\s+clean\s*-->", fix), \
        f"{det}: no verified clean fix pattern in '## How to fix'"
    assert "tealql-ignore" in fix, f"{det}: '## How to fix' does not say how to suppress"
    assert _section(text, "False positives"), f"{det}: README has no '## False positives'"
    # description_of() takes the first prose paragraph: the remediation text must
    # not displace the detector's description.
    assert description_of(det) not in fix


@pytest.mark.parametrize("det,target,expect,body", list(_verify_blocks()))
def test_readme_teal_block_verdict(det, target, expect, body, tmp_path):
    assert target in DETECTORS, f"{det}: verify names unknown detector {target!r}"
    assert body.lstrip().startswith("#pragma version"), \
        f"{det}: a verified block must be a complete program"
    path = tmp_path / "snippet.teal"
    path.write_text(body)
    prog = SSAProgram(str(path))
    prog.propagate_constants()
    found = DETECTORS[target](prog).detect()
    if expect == "clean":
        assert not found, f"{det}: README fix pattern is flagged by {target}: {found}"
    else:
        assert found, f"{det}: README vulnerable example is NOT flagged by {target}"
