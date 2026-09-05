"""AVM coverage is pinned independently of optional backend metadata."""
import pytest

from tealql.tealtools.language import avm
from tealql.tealtools.language.spec import (
    SPECS, SPEC_REVISION, PUYA_57_UNSUPPORTED, opcode_spec, support_inventory,
)
from tealql.tealtools.ssa import SSAProgram


def test_every_pinned_opcode_has_an_explicit_transfer():
    assert len(SPECS) > 180
    assert len(SPEC_REVISION) == 40
    inventory = support_inventory()['opcodes']
    assert set(inventory) == set(SPECS)
    for name in SPECS:
        assert avm.is_known_op(name), name
        if name not in avm._FRAME_OVERRIDES and name not in avm._IMMEDIATE_ARITY_OPS:
            assert avm.op_arity(name, '') == opcode_spec(name).arity


@pytest.mark.parametrize('name', sorted(PUYA_57_UNSUPPORTED))
def test_v13_instruction_survives_parse_and_stack_reconstruction(name):
    spec = opcode_spec(name)
    pushes = ['int 1' if kind == 'uint64' else 'byte 0x00' for kind in spec.args]
    immediate = ' ' + next(iter(spec.fields)) if spec.fields else ''
    teal = '\n'.join(['#pragma version 13', *pushes, name + immediate,
                      *['pop' for _ in spec.returns], 'int 1', 'return'])
    program = SSAProgram.from_text(teal, name='v13.teal')
    assignment = next(a for a in program.assignments if a.op == name)
    assert len(assignment.inputs) == len(spec.args)
    assert len(assignment.outputs) == len(spec.returns)
    assert not program.parse_diagnostics
    assert support_inventory()['opcodes'][name]['puya_5_7'] == 'unsupported'


@pytest.mark.parametrize('instruction', ['app_box_get extra', 'app_params_set Nope',
                                         'poseidon2 Nope', 'poseidon2'])
def test_invalid_new_immediates_remain_diagnostics(instruction):
    p = SSAProgram.from_text('#pragma version 13\n' + instruction + '\nint 1\nreturn',
                             name='invalid.teal', strict=False)
    assert p.parse_diagnostics
    assert not p.health().complete


def test_version_and_mode_are_not_inferred_from_installed_backend():
    assert opcode_spec('app_box_get', 12) is None
    assert opcode_spec('app_box_get').permits(13, 'app')
    assert not opcode_spec('app_box_get').permits(13, 'logicsig')
    assert not opcode_spec('app_params_get').permits(12, 'app', 'AppFamilyBoxAccess')
    assert opcode_spec('app_params_get').permits(13, 'app', 'AppFamilyBoxAccess')


def test_future_program_versions_remain_incomplete():
    p = SSAProgram.from_text('#pragma version 14\nint 1\nreturn', name='future.teal')
    assert not p.health().complete
    assert any(d.code == 'unsupported-version' for d in p.health().degradations)


def test_new_fields_have_types_lengths_and_explicit_backend_limits():
    p = SSAProgram.from_text('#pragma version 13\nint 1\nblock BlkBranch512\nlen\nreturn', name='block.teal')
    from tealql.tealtools.analysis import FactDomain
    facts = p.facts(FactDomain.BYTE_LENGTHS)
    output = next(a.outputs[0] for a in p.assignments if a.op == 'block')
    assert facts.fact(output).type.byte_length == 64
    assert 'BlkBranch512' in support_inventory()['opcodes']['block']['puya_5_7_unsupported_fields']
    pytest.importorskip('puya')
    from tealql.tealtools.lift import to_puya
    from tealql.tealtools.diagnostics.errors import LiftError
    with pytest.raises(LiftError, match='Puya 5.7 does not support'):
        to_puya(p)
