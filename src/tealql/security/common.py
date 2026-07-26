"""Shared helpers for the sec-guide detectors — the FACADE.

The common helper layer (OnCompletion guards, fee-validation guards, …) on top
of the :class:`SSAProgram` substrate and :class:`PathPredicateAnalysis`. Each
detector imports the predicates it needs from here rather than rebuilding them.

The implementation lives in six cohesive sibling modules; this module
re-exports every name (public and ``_``-prefixed alike — detector bodies and
tests reach both through ``common.<name>``), so ``from tealql.security import
common`` remains the ONLY import surface detectors need:

  - :mod:`._program_shape`    — approval/rejection exits, file-scoped field
                                reads + seed builders, app-vs-logicsig
                                classification, ``loc`` formatting.
  - :mod:`._value_flow`       — cached path predicates, the interprocedural
                                frame-param map, the MUST-flow operand walk
                                (phi / scratch / proto-frame bridges).
  - :mod:`._enforcement`      — "does this check's result actually reach an
                                assert / branch-to-reject sink?"
  - :mod:`._field_protection` — ``field_validated_on_all_paths`` (dominance)
                                and the every-path ``approval_exit_protected_
                                for_*`` family.
  - :mod:`._action_guards`    — sender==creator and OnCompletion action
                                guards over path predicates.
  - :mod:`._itxn_taint`       — inner-txn field sets, the shared user-input
                                taint fixpoint, and the cached IR-lifter
                                bridge (``ir_lifter``) the ir-* family runs on.

Where possible, we lean on :meth:`PathPredicateAnalysis.predicates_at` for
"must hold on every path" reasoning — it's already a sound, cached abstraction
over branch / assert outcomes. Hand-rolled CFG reachability only shows up in
:func:`approval_exit_protected_for_field` (which is strictly stronger than
what path predicates alone can express).

The detector outputs are intentionally over-conservative on several fixtures
(e.g. ``is-deletable`` flags ``fixed-complex-dispatch.teal`` because the
OnCompletion==5 reject sits *after* the dispatch). This is a deliberate choice
— the goal is soundness, not strictly tighter detection. Improvements live in
follow-ups.
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
    _is_global_field_var,
    _is_oncompletion_var,
    _is_sender_eq_creator,
    _is_txn_field_var,
    _oncompletion_eq_const_value,
    approval_exit_guarded_for_action,
    approval_exit_unguarded_for_action,
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
