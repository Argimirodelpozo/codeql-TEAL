"""TEAL opcode stack-arity signatures, derived from the TEAL
opcode classes (``getNumberOfConsumedArgs`` / ``getNumberOfOutputArgs`` in
``codeql/teal/ast/opcodes/*.qll``).

``op_arity(op, immediates) -> (n_in, n_out)`` gives the per-op stack
pop/push counts that drive PySSA's reconstruction, replacing the row-counts
PySSA used to read from QL's ``ssaInputs`` / ``ssaOutputs`` queries.

``frame_dig`` / ``frame_bury`` / ``callsub`` / ``retsub`` return the simple
counts PySSA's ``_phase1_instantiate`` expects; their height-dependent
"fat" forms are reconstructed by later PySSA phases (``_try_expand_frame_op``
+ subroutine/proto analysis), so phase 1 must NOT use the fat counts here.

The table is authoritative for ``n_out`` (validated row-for-row against
``ssaOutputs.ql`` by ``tests/test_ql_python_parity.py``). For ``n_in`` it is
the *true* arity, which is sometimes higher than QL's ``ssaInputs`` emitted
(QL drops inputs it can't resolve at a basic-block boundary) — a deliberate
precision gain, validated by the full suite rather than strict QL parity.
"""
from __future__ import annotations

# Constant-arity opcodes: mnemonic -> (n_in, n_out). Mnemonics are the
# source tokens (so symbolic ops are "+", "&&", "b==", etc.).
SIG: dict[str, tuple[int, int]] = {
    # Arithmetic
    "+": (2, 1), "-": (2, 1), "*": (2, 1), "/": (2, 1), "%": (2, 1),
    "addw": (2, 2), "mulw": (2, 2), "divmodw": (4, 4), "exp": (2, 1),
    "expw": (2, 2), "divw": (3, 1), "sqrt": (1, 1), "shl": (2, 1), "shr": (2, 1),
    # Byte arithmetic
    "b+": (2, 1), "b-": (2, 1), "b/": (2, 1), "b*": (2, 1), "b%": (2, 1),
    "bsqrt": (1, 1),
    # Byte comparison
    "b<": (2, 1), "b>": (2, 1), "b<=": (2, 1), "b>=": (2, 1),
    "b==": (2, 1), "b!=": (2, 1),
    # Comparison
    "<": (2, 1), "<=": (2, 1), ">": (2, 1), ">=": (2, 1),
    "==": (2, 1), "!=": (2, 1), "!": (1, 1),
    # Logic / bitwise
    "&&": (2, 1), "||": (2, 1), "&": (2, 1), "|": (2, 1), "^": (2, 1), "~": (1, 1),
    "b|": (2, 1), "b&": (2, 1), "b^": (2, 1), "b~": (1, 1),
    # Hashing
    "sha256": (1, 1), "sha512_256": (1, 1), "keccak256": (1, 1),
    "sha3_256": (1, 1), "mimc": (1, 1),
    # Crypto
    "ed25519verify": (3, 1), "ed25519verify_bare": (3, 1), "ecdsa_verify": (5, 1),
    "ecdsa_pk_decompress": (1, 2), "ecdsa_pk_recover": (4, 2), "vrf_verify": (3, 2),
    # Elliptic curve
    "ec_add": (2, 1), "ec_pairing_check": (2, 1), "ec_multi_scalar_mul": (2, 1),
    "ec_subgroup_check": (1, 1), "ec_map_to": (1, 1),
    # Byte ops
    "concat": (2, 1), "substring": (1, 1), "substring3": (3, 1),
    "extract": (1, 1), "extract3": (3, 1), "extract_uint16": (2, 1),
    "extract_uint32": (2, 1), "extract_uint64": (2, 1), "replace2": (2, 1),
    "replace3": (3, 1), "len": (1, 1), "bitlen": (1, 1), "getbit": (2, 1),
    "setbit": (3, 1), "getbyte": (2, 1), "setbyte": (3, 1), "itob": (1, 1),
    "btoi": (1, 1), "base64_decode": (1, 1), "json_ref": (2, 1),
    # Constants (fixed-arity members; pushints/pushbytess are dynamic — see op_arity)
    "int": (0, 1), "intc": (0, 1), "intc_0": (0, 1), "intc_1": (0, 1),
    "intc_2": (0, 1), "intc_3": (0, 1), "pushint": (0, 1), "intcblock": (0, 0),
    "bytec": (0, 1), "bytec_0": (0, 1), "bytec_1": (0, 1), "bytec_2": (0, 1),
    "bytec_3": (0, 1), "pushbytes": (0, 1), "bytecblock": (0, 0), "bzero": (1, 1),
    # Control flow (callsub/retsub handled by op_arity overrides; match dynamic)
    "return": (0, 0), "err": (0, 0), "assert": (1, 0), "b": (0, 0),
    "bnz": (1, 0), "bz": (1, 0), "switch": (1, 0),
    # Stack manipulation (dig/popn/dupn/bury/cover/uncover/frame_* dynamic)
    "pop": (1, 0), "dup": (1, 2), "dup2": (2, 4), "swap": (2, 2),
    "select": (3, 1), "proto": (0, 0),
    # Scratch space
    "load": (0, 1), "store": (1, 0), "loads": (1, 1), "stores": (2, 0),
    "gload": (0, 1), "gloads": (1, 1), "gloadss": (2, 1), "gaid": (0, 1),
    "gaids": (1, 1),
    # Transaction
    "txn": (0, 1), "txna": (0, 1), "txnas": (1, 1), "gtxn": (0, 1),
    "gtxna": (0, 1), "gtxnas": (1, 1), "gtxns": (1, 1), "gtxnsa": (1, 1),
    "gtxnsas": (2, 1), "gitxn": (0, 1), "gitxna": (0, 1), "gitxnas": (1, 1),
    # Global / app state
    "global": (0, 1), "app_opted_in": (2, 1), "app_local_get": (2, 1),
    "app_local_get_ex": (3, 2), "app_global_get": (1, 1), "app_global_get_ex": (2, 2),
    "app_local_put": (3, 0), "app_global_put": (2, 0), "app_local_del": (2, 0),
    "app_global_del": (1, 0), "app_params_get": (1, 2), "asset_holding_get": (2, 2),
    "asset_params_get": (1, 2), "acct_params_get": (1, 2), "balance": (1, 1),
    "min_balance": (1, 1), "online_stake": (0, 1), "voter_params_get": (1, 2),
    # Inner transactions
    "itxn_begin": (0, 0), "itxn_next": (0, 0), "itxn_submit": (0, 0),
    "itxn_field": (1, 0), "itxn": (0, 1), "itxna": (0, 1), "itxnas": (1, 1),
    # Logging
    "log": (1, 0),
    # Misc
    "arg": (0, 1), "arg_0": (0, 1), "arg_1": (0, 1), "arg_2": (0, 1),
    "arg_3": (0, 1), "args": (1, 1), "block": (1, 1),
    # Box storage
    "box_create": (2, 1), "box_extract": (3, 1), "box_replace": (3, 0),
    "box_del": (1, 1), "box_len": (1, 2), "box_get": (1, 2), "box_put": (2, 0),
    "box_splice": (4, 0), "box_resize": (2, 0),
}

# Height-dependent ops PySSA phase 1 instantiates with simple counts; the
# fat / proto-aware forms are rebuilt by later PySSA phases.
_FRAME_OVERRIDES: dict[str, tuple[int, int]] = {
    "frame_dig": (0, 1),
    "frame_bury": (1, 0),
    "callsub": (0, 0),
    "retsub": (0, 0),
}


def _imm_int(immediates: str) -> int:
    try:
        return int(immediates.split()[0])
    except (ValueError, IndexError):
        return 0


def op_arity(op: str, immediates: str) -> tuple[int, int]:
    """Return ``(n_in, n_out)`` for an opcode + its immediate text."""
    o = _FRAME_OVERRIDES.get(op)
    if o is not None:
        return o
    if op == "dig":
        n = _imm_int(immediates)
        return (n + 1, n + 2)
    if op == "bury":
        n = _imm_int(immediates)
        return (n + 1, n)
    if op == "cover" or op == "uncover":
        n = _imm_int(immediates)
        return (n + 1, n + 1)
    if op == "popn":
        return (_imm_int(immediates), 0)
    if op == "dupn":
        return (1, _imm_int(immediates) + 1)
    if op == "pushints":
        return (0, len(immediates.split()))
    if op == "pushbytess":
        from .const_values import _split_byte_literals
        return (0, len(_split_byte_literals(immediates)))
    if op == "match":
        return (len(immediates.split()) + 1, 0)
    return SIG.get(op, (0, 0))
