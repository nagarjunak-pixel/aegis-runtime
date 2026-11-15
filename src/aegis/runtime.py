"""Unified AegisRuntime Control Plane orchestrating Policy, PII Vault, Router, Sagas & Ledger."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.enterprise.erp_systems import EnterpriseERPSandbox, FaultProfile
from aegis.enterprise.mcp_server import EnterpriseMCPServer
from aegis.enterprise.scenarios import EnterpriseScenarioCatalog
from aegis.ledger.store import EventLedger
from aegis.policy.evaluator import PolicyEngine
from aegis.privacy.vault import PIITokenVault
from aegis.replay.engine import ReplayEngine
from aegis.router.pareto_router import ParetoModelRouter, RoutingDecision, RoutingRequest
from aegis.saga.coordinator import SagaCoordinator, SagaDefinition, SagaExecutionResult
from aegis.saga.idempotency import IdempotencyStore
from aegis.telemetry.tracing import TelemetryCollector
from aegis.types import LedgerEventType, PrincipalContext

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policies" / "enterprise_erp.aegis"

FALLBACK_DEFAULT_POLICY = """
rule "forbid-unauthenticated-or-no-mfa" {
    effect: forbid
    description: "All autonomous agent executions require MFA-verified principal session lineage"
    when: principal.mfa_verified == false
}
rule "forbid-segregation-of-duties-self-approval" {
    effect: forbid
    description: "SOX Segregation of Duties: principal cannot approve their own workflow"
    when: principal.approver_id != null and principal.principal_id == principal.approver_id
}
rule "forbid-spend-above-autonomous-cap-without-secondary-approver" {
    effect: forbid
    description: "Financial mutations exceeding autonomous cap require independent approver_id"
    when: action.amount_usd > principal.max_autonomous_spend_usd and principal.approver_id == null
}
rule "forbid-hard-enterprise-ceiling" {
    effect: forbid
    description: "Hard treasury ceiling: single autonomous transaction may never exceed $500,000"
    when: action.amount_usd > 500000
}
rule "forbid-sanctioned-jurisdictions" {
    effect: forbid
    description: "OFAC compliance: block restricted country codes"
    when: context.vendor_country in ["KP", "IR", "SY", "CU", "RU_SANCTIONED"]
}
rule "forbid-untrusted-taint-on-mutations" {
    effect: forbid
    description: "Forbid state mutations when UNTRUSTED_EXTERNAL taint is present"
    when: "UNTRUSTED_EXTERNAL" in action.taint_labels and action.operation in ["create", "update", "approve", "transfer"]
}
rule "forbid-vendor-bank-iban-mutation-by-non-treasury" {
    effect: forbid
    description: "Master-data bank IBAN updates require treasury_controller role"
    when: action.tool_name == "vendor.update_bank_iban" and "treasury_controller" not in principal.roles
}
rule "permit-erp-procurement-and-supply-chain" {
    effect: permit
    description: "Permit authorized procurement planners and supply-chain operators"
    when: ("procurement_planner" in principal.roles or "supply_chain_operator" in principal.roles) and action.resource_type in ["inventory_lot", "purchase_requisition", "purchase_order", "logistics_shipment", "vendor_master"]
}
rule "permit-treasury-settlement-operations" {
    effect: permit
    description: "Permit authorized treasury settlements on internal ERP domain"
    when: ("treasury_operator" in principal.roles or "procurement_planner" in principal.roles) and action.resource_type in ["fx_hedge", "wire_transfer"] and action.target_domain == "internal.erp"
}
rule "permit-compensating-rollback-actions" {
    effect: permit
    description: "Always permit deterministic saga compensation rollbacks on internal ERP"
    when: action.operation == "compensate" and action.target_domain == "internal.erp"
}
"""


class WorkflowRunBundle(BaseModel):
    """End-to-end execution bundle combining model routing, saga execution, and invariants."""

    model_config = ConfigDict(frozen=True)

    routing: RoutingDecision
    saga_result: SagaExecutionResult
    merkle_root: str
    ledger_event_count: int
    conservation_passed: bool


class AegisRuntime:
    """Production-grade Zero-Trust Agentic Control Plane & Transactional Saga Runtime."""

    def __init__(
        self,
        *,
        policy_source: str | None = None,
        db_path: str | Path = ":memory:",
    ) -> None:
        if policy_source is None:
            if DEFAULT_POLICY_PATH.exists():
                policy_source = DEFAULT_POLICY_PATH.read_text(encoding="utf-8")
            else:
                policy_source = FALLBACK_DEFAULT_POLICY

        self.policy_source = policy_source
        self.policy_engine = PolicyEngine.from_source(policy_source)
        self.pii_vault = PIITokenVault()
        self.ledger = EventLedger(db_path=db_path)
        self.telemetry = TelemetryCollector()
        self.router = ParetoModelRouter()
        self.idempotency = IdempotencyStore()
        self.erp = EnterpriseERPSandbox()
        self.mcp_server = EnterpriseMCPServer(self.erp)
        self.replay_engine = ReplayEngine(self.ledger)
        self.coordinator = SagaCoordinator(
            policy_engine=self.policy_engine,
            ledger=self.ledger,
            pii_vault=self.pii_vault,
            idempotency_store=self.idempotency,
            telemetry=self.telemetry,
        )

    async def execute_governed_workflow(
        self,
        *,
        principal: PrincipalContext,
        prompt: str,
        saga: SagaDefinition,
        min_quality_score: float = 0.85,
    ) -> WorkflowRunBundle:
        """Tokenize PII in prompt, route model on Pareto frontier, and execute governed Saga."""
        tok_prompt = self.pii_vault.tokenize_text(principal.tenant_id, prompt)
        if tok_prompt.tokens_created:
            self.ledger.append(
                tenant_id=principal.tenant_id,
                workflow_id=saga.workflow_id,
                event_type=LedgerEventType.PII_TOKENIZED,
                payload={
                    "pii_kinds": list(tok_prompt.pii_kinds_detected),
                    "token_count": len(tok_prompt.tokens_created),
                },
            )

        with self.telemetry.span(
            "aegis.router.dispatch",
            attributes={"tenant_id": principal.tenant_id, "workflow_id": saga.workflow_id},
        ):
            routing = self.router.route_and_invoke(
                RoutingRequest(
                    tenant_id=principal.tenant_id,
                    prompt=str(tok_prompt.sanitized_value),
                    min_quality_score=min_quality_score,
                )
            )

        self.ledger.append(
            tenant_id=principal.tenant_id,
            workflow_id=saga.workflow_id,
            event_type=LedgerEventType.MODEL_ROUTED,
            payload={
                "selected_model_id": routing.selected_model_id,
                "provider": routing.provider,
                "estimated_cost_usd": routing.estimated_cost_usd,
                "cache_hit": routing.cache_hit,
                "pareto_frontier": list(routing.pareto_frontier_models),
            },
        )

        saga_result = await self.coordinator.execute(principal, saga)
        chain_audit = self.ledger.verify_chain_integrity()
        inv_audit = self.erp.audit_conservation_invariants()

        return WorkflowRunBundle(
            routing=routing,
            saga_result=saga_result,
            merkle_root=chain_audit.merkle_root,
            ledger_event_count=chain_audit.events_checked,
            conservation_passed=inv_audit.passed,
        )

    async def run_reference_scenario(self, scenario_id: str) -> WorkflowRunBundle:
        """Build and execute one of the 6 reference Fortune-500 scenarios with fault reset."""
        principal, saga, prompt, fault_profile = EnterpriseScenarioCatalog.build_scenario(
            scenario_id, self.erp
        )
        self.erp.set_fault_profile(fault_profile)
        try:
            return await self.execute_governed_workflow(
                principal=principal,
                prompt=prompt,
                saga=saga,
            )
        finally:
            self.erp.set_fault_profile(FaultProfile())

    def system_overview(self) -> dict[str, Any]:
        chain = self.ledger.verify_chain_integrity()
        return {
            "version": "0.4.0",
            "policy_hash": self.policy_engine.policy_hash,
            "policy_rule_count": len(self.policy_engine.policy_set.rules),
            "ledger": {
                "valid": chain.valid,
                "events_checked": chain.events_checked,
                "merkle_root": chain.merkle_root,
                "public_key": self.ledger.signer.public_key_hex,
            },
            "pii_vaulted_secrets": self.pii_vault.vaulted_count,
            "router_cache": self.router.cache.stats,
            "model_fleet": self.router.fleet_snapshot(),
            "erp": self.erp.state_summary(),
            "recent_spans": [s.model_dump() for s in self.telemetry.recent_spans(limit=25)],
        }
