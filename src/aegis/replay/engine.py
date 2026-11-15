"""Event-sourced time-travel replay & counterfactual policy blast-radius engine."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.ledger.store import EventLedger, LedgerEntry
from aegis.policy.evaluator import PolicyEngine
from aegis.types import ActionIntent, LedgerEventType, PrincipalContext


class WorkflowReplaySnapshot(BaseModel):
    """Deterministic reconstruction of a workflow state at an exact ledger sequence."""

    model_config = ConfigDict(frozen=True)

    workflow_id: str
    tenant_id: str
    replayed_up_to_seq: int
    workflow_name: str
    principal_id: str
    agent_id: str
    derived_status: str
    executed_steps: tuple[str, ...]
    compensated_steps: tuple[str, ...]
    failed_steps: tuple[str, ...]
    blocked_steps: tuple[str, ...]
    policy_decisions: tuple[dict[str, Any], ...]
    state_digest: str


class CounterfactualStepDelta(BaseModel):
    """Comparison between historical policy verdict and candidate policy verdict."""

    model_config = ConfigDict(frozen=True)

    seq: int
    step_name: str
    tool_name: str
    amount_usd: float
    original_effect: str
    candidate_effect: str
    original_rule_id: str | None
    candidate_rule_id: str | None
    flipped: bool
    candidate_reason: str


class CounterfactualDiffReport(BaseModel):
    """Blast-radius report when replaying historical traffic against a candidate policy."""

    model_config = ConfigDict(frozen=True)

    workflow_id: str
    candidate_policy_hash: str
    total_evaluated_steps: int
    verdict_flips: int
    newly_blocked_steps: int
    newly_permitted_steps: int
    deltas: tuple[CounterfactualStepDelta, ...]


class ReplayEngine:
    """Reconstructs historical execution timelines and evaluates counterfactual policies."""

    def __init__(self, ledger: EventLedger) -> None:
        self._ledger = ledger

    def replay_workflow(
        self,
        workflow_id: str,
        *,
        up_to_seq: int | None = None,
    ) -> WorkflowReplaySnapshot:
        """Deterministically fold ledger events up to `up_to_seq` into a state snapshot."""
        events = self._ledger.list_events(workflow_id=workflow_id, up_to_seq=up_to_seq, limit=5000)
        if not events:
            raise KeyError(f"No ledger events found for workflow_id='{workflow_id}'")

        tenant_id = events[0].tenant_id
        workflow_name = "unknown"
        principal_id = "unknown"
        agent_id = "unknown"
        derived_status = "IN_PROGRESS"

        executed: list[str] = []
        compensated: list[str] = []
        failed: list[str] = []
        blocked: list[str] = []
        decisions: list[dict[str, Any]] = []

        for ev in events:
            p = ev.payload
            if ev.event_type == LedgerEventType.WORKFLOW_STARTED:
                workflow_name = str(p.get("workflow_name", workflow_name))
                principal_id = str(p.get("principal_id", principal_id))
                agent_id = str(p.get("agent_id", agent_id))
                derived_status = "EXECUTING"
            elif ev.event_type == LedgerEventType.POLICY_EVALUATED:
                decisions.append(p)
                if p.get("effect") == "DENY":
                    blocked.append(str(p.get("step_name", "")))
            elif ev.event_type == LedgerEventType.SAGA_STEP_EXECUTED:
                executed.append(str(p.get("step_name", "")))
            elif ev.event_type == LedgerEventType.SAGA_STEP_FAILED:
                failed.append(str(p.get("step_name", "")))
                derived_status = "COMPENSATING"
            elif ev.event_type == LedgerEventType.SAGA_STEP_COMPENSATED:
                compensated.append(str(p.get("step_name", "")))
            elif ev.event_type == LedgerEventType.WORKFLOW_COMPLETED:
                derived_status = str(p.get("status", derived_status))

        return WorkflowReplaySnapshot(
            workflow_id=workflow_id,
            tenant_id=tenant_id,
            replayed_up_to_seq=events[-1].seq,
            workflow_name=workflow_name,
            principal_id=principal_id,
            agent_id=agent_id,
            derived_status=derived_status,
            executed_steps=tuple(executed),
            compensated_steps=tuple(compensated),
            failed_steps=tuple(failed),
            blocked_steps=tuple(blocked),
            policy_decisions=tuple(decisions),
            state_digest=events[-1].event_hash,
        )

    def simulate_counterfactual_policy(
        self,
        workflow_id: str,
        *,
        candidate_policy_source: str,
        principal_override: PrincipalContext | None = None,
        context_override: dict[str, Any] | None = None,
    ) -> CounterfactualDiffReport:
        """Re-evaluate recorded intents of `workflow_id` under `candidate_policy_source`."""
        candidate_engine = PolicyEngine.from_source(candidate_policy_source)
        events = self._ledger.list_events(workflow_id=workflow_id, limit=5000)
        if not events:
            raise KeyError(f"No ledger events found for workflow_id='{workflow_id}'")

        principal = principal_override or self._extract_principal(events)
        deltas: list[CounterfactualStepDelta] = []
        newly_blocked = 0
        newly_permitted = 0

        for ev in events:
            if ev.event_type != LedgerEventType.POLICY_EVALUATED:
                continue
            p = ev.payload
            step_name = str(p.get("step_name", "step"))
            tool_name = str(p.get("tool_name", "unknown.tool"))
            op = str(p.get("operation", "create"))
            amount = float(p.get("amount_usd", 0.0))
            resource_type = self._infer_resource_type(tool_name)

            intent = ActionIntent(
                step_name=step_name,
                tool_name=tool_name,
                resource_type=resource_type,
                operation=op,
                amount_usd=amount,
            )
            verdict = candidate_engine.evaluate(principal, intent, context_override or {})
            orig_eff = str(p.get("effect", "DENY"))
            cand_eff = verdict.effect.value
            flipped = orig_eff != cand_eff
            if flipped:
                if cand_eff == "DENY":
                    newly_blocked += 1
                else:
                    newly_permitted += 1

            deltas.append(
                CounterfactualStepDelta(
                    seq=ev.seq,
                    step_name=step_name,
                    tool_name=tool_name,
                    amount_usd=amount,
                    original_effect=orig_eff,
                    candidate_effect=cand_eff,
                    original_rule_id=p.get("deciding_rule_id"),
                    candidate_rule_id=verdict.deciding_rule_id,
                    flipped=flipped,
                    candidate_reason=verdict.reason,
                )
            )

        return CounterfactualDiffReport(
            workflow_id=workflow_id,
            candidate_policy_hash=candidate_engine.policy_hash,
            total_evaluated_steps=len(deltas),
            verdict_flips=newly_blocked + newly_permitted,
            newly_blocked_steps=newly_blocked,
            newly_permitted_steps=newly_permitted,
            deltas=tuple(deltas),
        )

    @staticmethod
    def _extract_principal(events: list[LedgerEntry]) -> PrincipalContext:
        for ev in events:
            if ev.event_type == LedgerEventType.WORKFLOW_STARTED:
                p = ev.payload
                return PrincipalContext(
                    tenant_id=ev.tenant_id,
                    principal_id=str(p.get("principal_id", "replayed-principal")),
                    agent_id=str(p.get("agent_id", "replayed-agent")),
                    roles=tuple(p.get("roles", ["procurement_planner"])),
                )
        return PrincipalContext(
            tenant_id=events[0].tenant_id,
            principal_id="replayed-principal",
            agent_id="replayed-agent",
            roles=("procurement_planner",),
        )

    @staticmethod
    def _infer_resource_type(tool_name: str) -> str:
        mapping = {
            "inventory": "inventory_lot",
            "requisition": "purchase_requisition",
            "purchase_order": "purchase_order",
            "wire": "wire_transfer",
            "fx": "fx_hedge",
            "vendor": "vendor_master",
            "shipment": "logistics_shipment",
        }
        for key, rtype in mapping.items():
            if key in tool_name:
                return rtype
        return "purchase_order"
