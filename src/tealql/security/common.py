"""Shared helpers for the sec-guide detectors — the FACADE over six sibling
modules (``_program_shape``, ``_value_flow``, ``_enforcement``,
``_field_protection``, ``_action_guards``, ``_itxn_taint``).

Every name is re-exported, ``_``-prefixed ones included, because detector bodies
and tests reach both through ``common.<name>`` — this is the ONLY import surface
a detector should need.

Prefer :meth:`PathPredicateAnalysis.predicates_at` for "must hold on every path"
reasoning; it is already a sound, cached abstraction over branch/assert outcomes.
Hand-rolled CFG reachability appears only where it is strictly stronger than what
path predicates can express.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("tealql.security.common")

from ._program_shape import (  # noqa: E402,F401
    _APP_ONLY_OPS,
    _is_const_zero,
    _return_likely_zero,
    _txna_reads,
    approving_exits,
    classify_program,
    file_match,
    global_field_reads,
    gtxn_field_reads,
    has_instructions,
    is_approval_exit,
    is_rejection_exit,
    loc,
    op_output_seeds,
    prepare,
    ssavar_outputs,
    txn_field_reads,
)
from ._value_flow import (  # noqa: E402,F401
    _frame_param_sources_cached,
    _operand_flows_from_field_var,
    _scratch_stores_for,
    cached_path_predicates,
    resolve_through_copies,
)
from ._enforcement import (  # noqa: E402,F401
    _ENFORCEMENT_TERM_OPS,
    _bb_at,
    _fall_through_bb,
    _label_to_bb_first_line,
    branch_gates_rejection,
    def_forward_reaches_enforcement,
    enforced_op_exists,
    scratch_forward_map,
)
from ._field_protection import (  # noqa: E402,F401
    _all_entry_paths_cross,
    _approval_exit_protected_for_seeds,
    _collect_field_enforcement_bbs,
    _global_field_seeds,
    _txn_field_seeds,
    approval_exit_protected_for_any_txn_field,
    approval_exit_protected_for_arg_reads,
    approval_exit_protected_for_field,
    approval_exit_protected_for_signed_txn_field,
    approval_exit_protected_for_global_field,
    field_validated_on_all_paths,
    is_comparison,
)
from ._action_guards import (  # noqa: E402,F401
    ONC_CLEAR_STATE,
    ONC_CLOSEOUT,
    ONC_DELETE_APPLICATION,
    ONC_NOOP,
    ONC_OPTIN,
    ONC_UPDATE_APPLICATION,
    _is_oncompletion_var,
    _is_sender_eq_creator,
    _is_txn_field_var,
    _oncompletion_eq_const_value,
    approval_exit_guarded_for_action,
    approval_exit_unguarded_for_action,
    sender_creator_guard_covers_action,
    sender_creator_guard_dominates,
)
from ._itxn_taint import (  # noqa: E402,F401
    _CMP_OPS,
    InnerTxnFieldSet,
    _compute_user_input_taint,
    _zero_address_seeds,
    inner_txn_field_assigns,
    inner_txn_sets_nonzero_fee,
    ir_lifter,
    itxn_value_guarded,
    sender_creator_vars,
    source_label,
    user_input_taint,
    value_is_zero_address,
)
