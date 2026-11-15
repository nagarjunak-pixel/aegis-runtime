# ADR-0006: Event-Sourced Time-Travel & Counterfactual Policy Blast-Radius Replay

- **Status**: Accepted
- **Date**: 2026-11

## Context

In large enterprises, tightening a governance rule (for example, reducing autonomous procurement authority from `$25,000` to `$10,000` or adding a newly sanctioned jurisdiction) risks unexpectedly halting critical factory-floor supply-chain automations if deployed blind.

## Decision

Because `AegisRuntime` records every `WORKFLOW_STARTED`, `POLICY_EVALUATED`, `SAGA_STEP_EXECUTED`, and `SAGA_STEP_COMPENSATED` event in an immutable sequence-ordered ledger, `ReplayEngine` (`src/aegis/replay/engine.py`) provides two deterministic capabilities:
1. **Sequence-Bounded Time-Travel Reconstruction (`replay_workflow(workflow_id, up_to_seq=k)`)**: Folds historical events up to sequence `k` to inspect exact in-flight step and compensation state during post-incident forensics.
2. **Counterfactual Policy Simulation (`simulate_counterfactual_policy`)**: Compiles a candidate `.aegis` policy string into an isolated `PolicyEngine` and replays historical `ActionIntent` envelopes against it—emitting `CounterfactualDiffReport` (`verdict_flips`, `newly_blocked_steps`, `newly_permitted_steps`).

## Consequences

- **Positive**: Governance and CISO teams can quantify exact production blast radius before promoting a policy PR to `main`.
- **Negative / Trade-off**: Counterfactual simulation evaluates recorded action intents deterministically without re-executing live external ERP mutations or re-sampling stochastic LLM tokens.
