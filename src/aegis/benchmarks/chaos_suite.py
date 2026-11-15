"""Chaos fault-injection benchmark verifying Saga rollback & conservation invariants."""

from __future__ import annotations

import statistics
import time

from pydantic import BaseModel, ConfigDict

from aegis.enterprise.erp_systems import FaultProfile
from aegis.runtime import AegisRuntime
from aegis.saga.coordinator import SagaDefinition, SagaStepSpec
from aegis.types import ActionIntent, PrincipalContext, SagaStatus


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(round((pct / 100.0) * (len(sorted_vals) - 1)))))
    return round(sorted_vals[idx], 3)


class ChaosBenchmarkReport(BaseModel):
    """Quantitative resilience & latency metrics produced by the chaos harness."""

    model_config = ConfigDict(frozen=True)

    total_sagas: int
    fault_injection_rate: float
    committed_sagas: int
    compensated_sagas: int
    blocked_sagas: int
    quarantined_sagas: int
    orphan_mutations: int
    conservation_invariants_passed: bool
    ledger_integrity_passed: bool
    ledger_events_verified: int
    merkle_root: str
    policy_eval_p50_us: float
    policy_eval_p95_us: float
    policy_eval_p99_us: float
    saga_latency_p50_ms: float
    saga_latency_p95_ms: float
    saga_latency_p99_ms: float
    throughput_sagas_per_sec: float


async def run_chaos_benchmark(
    *,
    transactions: int = 150,
    fault_rate: float = 0.25,
    seed: int = 2026,
) -> ChaosBenchmarkReport:
    """Execute `transactions` multi-step ERP sagas under probabilistic downstream faults."""
    rt = AegisRuntime()
    rt.erp.set_fault_profile(
        FaultProfile(
            random_permanent_rate=fault_rate * 0.6,
            random_transient_rate=fault_rate * 0.4,
            seed=seed,
        )
    )

    principal = PrincipalContext(
        tenant_id="chaos-bench-tenant",
        principal_id="bench-operator-01",
        agent_id="chaos-runner-v4",
        roles=("procurement_planner", "treasury_operator"),
        cost_center="CC-1000",
        max_autonomous_spend_usd=25_000.0,
    )

    saga_latencies_ms: list[float] = []
    policy_latencies_us: list[float] = []
    committed = 0
    compensated = 0
    blocked = 0
    quarantined = 0

    t_bench_start = time.perf_counter()

    for i in range(transactions):
        is_policy_violation = (i % 19) == 18
        po_amount = 45_000.0 if is_policy_violation else 1_250.0

        saga = SagaDefinition(
            name=f"chaos_tx_{i:04d}",
            base_context={"vendor_country": "TW"},
            steps=(
                SagaStepSpec(
                    name="step_1_atp",
                    action=ActionIntent(
                        step_name="step_1_atp",
                        tool_name="inventory.reserve_atp",
                        resource_type="inventory_lot",
                        operation="update",
                        parameters={"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 2},
                    ),
                    forward_fn=rt.erp.reserve_atp,
                    compensate_fn=rt.erp.release_atp,
                    compensate_tool_name="compensate.inventory.release_atp",
                    max_retries=1,
                    retry_backoff_seconds=0.001,
                ),
                SagaStepSpec(
                    name="step_2_po",
                    action=ActionIntent(
                        step_name="step_2_po",
                        tool_name="erp.create_purchase_order",
                        resource_type="purchase_order",
                        operation="create",
                        amount_usd=po_amount,
                        parameters={
                            "vendor_id": "VEND-TSMC-01",
                            "amount_usd": po_amount,
                            "cost_center": "CC-1000",
                        },
                    ),
                    forward_fn=rt.erp.create_purchase_order,
                    compensate_fn=rt.erp.cancel_purchase_order,
                    compensate_tool_name="compensate.erp.cancel_purchase_order",
                    max_retries=1,
                    retry_backoff_seconds=0.001,
                ),
                SagaStepSpec(
                    name="step_3_wire",
                    action=ActionIntent(
                        step_name="step_3_wire",
                        tool_name="treasury.execute_wire",
                        resource_type="wire_transfer",
                        operation="transfer",
                        amount_usd=po_amount,
                        parameters={
                            "po_step_ref": "step_2_po",
                            "beneficiary_iban": "DE89370400440532013000",
                        },
                    ),
                    forward_fn=rt.erp.execute_wire,
                    compensate_fn=rt.erp.reverse_wire,
                    compensate_tool_name="compensate.treasury.reverse_wire",
                    max_retries=1,
                    retry_backoff_seconds=0.001,
                ),
            ),
        )

        res = await rt.coordinator.execute(principal, saga)
        saga_latencies_ms.append(res.total_latency_ms)
        for st in res.steps:
            policy_latencies_us.append(st.policy_verdict.evaluation_latency_us)

        if res.status == SagaStatus.COMMITTED:
            committed += 1
        elif res.status == SagaStatus.COMPENSATED:
            compensated += 1
        elif res.status == SagaStatus.BLOCKED_BY_POLICY:
            blocked += 1
        elif res.status == SagaStatus.QUARANTINED:
            quarantined += 1

    elapsed_sec = max(1e-6, time.perf_counter() - t_bench_start)
    inv_report = rt.erp.audit_conservation_invariants()
    ledger_report = rt.ledger.verify_chain_integrity()

    # Exact orphan check: active reservations and active POs must equal `committed`!
    expected_committed_units = committed
    orphan_reservations = abs(inv_report.active_reservations - expected_committed_units)
    orphan_pos = abs(inv_report.active_purchase_orders - expected_committed_units)
    orphan_mutations = orphan_reservations + orphan_pos

    sorted_pol = sorted(policy_latencies_us)
    sorted_saga = sorted(saga_latencies_ms)

    return ChaosBenchmarkReport(
        total_sagas=transactions,
        fault_injection_rate=fault_rate,
        committed_sagas=committed,
        compensated_sagas=compensated,
        blocked_sagas=blocked,
        quarantined_sagas=quarantined,
        orphan_mutations=orphan_mutations,
        conservation_invariants_passed=inv_report.passed and orphan_mutations == 0,
        ledger_integrity_passed=ledger_report.valid,
        ledger_events_verified=ledger_report.events_checked,
        merkle_root=ledger_report.merkle_root,
        policy_eval_p50_us=round(statistics.median(sorted_pol), 2) if sorted_pol else 0.0,
        policy_eval_p95_us=_percentile(sorted_pol, 95.0),
        policy_eval_p99_us=_percentile(sorted_pol, 99.0),
        saga_latency_p50_ms=round(statistics.median(sorted_saga), 3) if sorted_saga else 0.0,
        saga_latency_p95_ms=_percentile(sorted_saga, 95.0),
        saga_latency_p99_ms=_percentile(sorted_saga, 99.0),
        throughput_sagas_per_sec=round(transactions / elapsed_sec, 1),
    )
