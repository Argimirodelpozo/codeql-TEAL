"""SSA functional-pass package.

Houses the optional analysis / cleanup passes that layer on top of
the :mod:`tealtools.ssa` substrate — one module per pass: the actual
semantics of constant propagation, input unification, range
propagation / assert-refinement, byte_length inference, bytemath, and
dead-code cleanup. The substrate exposes a thin lazy-import bridge
method (e.g. :meth:`SSAProgram.propagate_byte_lengths`) that delegates
here; that is the supported way to run a pass.

(Construction-time helpers the *builder* needs — ``const_fold``,
``inner_txn_fields``, ``scratch_influence`` — live in the
:mod:`tealtools.ssa` package instead; they run while a program is being
built, not as optional passes over a finished one.)
"""
