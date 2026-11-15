"""Hypothesis property-based & fault-injection tests proving Saga conservation laws."""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.runtime import AegisRuntime
from aegis.saga.coordinator import (
    PermanentStepError,
    SagaDefinition,
    SagaStepSpec,
    TransientStepError,
)
from aegis.types import ActionIntent, PrincipalContext, SagaStatus, StepStatus


@settings(max_examples=40, deadline=None)
@given(
    ops=st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=25),
            st.floats(min_value=500.0, max_value=40_000.0, allow_nan=False, allow_infinity=False),
            st.sampled_from(["none", "fail_po", "fail_wire", "transient_wire"]),
        ),
        min_size=1,
        max_size=10,
    )
)
def test_property_double_entry_and_inventory_conservation_under_arbitrary_faults(
    ops: list[tuple[int, float, str]],
) -> None:
    """Property: Regardless of arbitrary mid-saga failures, policy denials, or retries,
    total cost-center dollars and warehouse ATP + reserved units remain strictly conserved,
    and zero uncompensated resources remain from rolled-back sagas.
    """

    async def _scenario() -> None:
        rt = AegisRuntime()
        principal = PrincipalContext(
            tenant_id="prop-tenant",
            principal_id="prop-user",
            agent_id="prop-agent",
            roles=("procurement_planner", "treasury_operator"),
            cost_center="CC-1000",
            max_autonomous_spend_usd=25_000.0,
        )

        expected_reserved_units = 0
        expected_committed_pos = 0

        for idx, (qty, amount_usd, fault_mode) in enumerate(ops):
            transient_fired = {"wire": False}

            async def _po_fn(
                p: dict[str, object],
                prior: dict[str, object],
                mode: str = fault_mode,
            ) -> dict[str, object]:
                if mode == "fail_po":
                    raise PermanentStepError("Injected PO fault")
                return await rt.erp.create_purchase_order(p, prior)  # type: ignore[arg-type]

            async def _wire_fn(
                p: dict[str, object],
                prior: dict[str, object],
                mode: str = fault_mode,
                state: dict[str, bool] = transient_fired,
            ) -> dict[str, object]:
                if mode == "fail_wire":
                    raise PermanentStepError("Injected SWIFT fault")
                if mode == "transient_wire" and not state["wire"]:
                    state["wire"] = True
                    raise TransientStepError("Transient 503")
                return await rt.erp.execute_wire(p, prior)  # type: ignore[arg-type]

            saga = SagaDefinition(
                name=f"prop_saga_{idx}",
                base_context={"vendor_country": "TW"},
                steps=(
                    SagaStepSpec(
                        name="atp",
                        action=ActionIntent(
                            step_name="atp",
                            tool_name="inventory.reserve_atp",
                            resource_type="inventory_lot",
                            operation="update",
                            parameters={
                                "plant": "PLANT-DE-01",
                                "sku": "MAT-CHIP-7NM",
                                "quantity": qty,
                            },
                        ),
                        forward_fn=rt.erp.reserve_atp,
                        compensate_fn=rt.erp.release_atp,
                        compensate_tool_name="compensate.inventory.release_atp",
                    ),
                    SagaStepSpec(
                        name="po",
                        action=ActionIntent(
                            step_name="po",
                            tool_name="erp.create_purchase_order",
                            resource_type="purchase_order",
                            operation="create",
                            amount_usd=round(amount_usd, 2),
                            parameters={
                                "vendor_id": "VEND-TSMC-01",
                                "amount_usd": round(amount_usd, 2),
                                "cost_center": "CC-1000",
                            },
                        ),
                        forward_fn=_po_fn,
                        compensate_fn=rt.erp.cancel_purchase_order,
                        compensate_tool_name="compensate.erp.cancel_purchase_order",
                    ),
                    SagaStepSpec(
                        name="wire",
                        action=ActionIntent(
                            step_name="wire",
                            tool_name="treasury.execute_wire",
                            resource_type="wire_transfer",
                            operation="transfer",
                            amount_usd=round(amount_usd, 2),
                            parameters={
                                "po_step_ref": "po",
                                "beneficiary_iban": "DE89370400440532013000",
                            },
                        ),
                        forward_fn=_wire_fn,
                        compensate_fn=rt.erp.reverse_wire,
                        compensate_tool_name="compensate.treasury.reverse_wire",
                        max_retries=2,
                        retry_backoff_seconds=0.0005,
                    ),
                ),
            )

            res = await rt.coordinator.execute(principal, saga)
            if res.status == SagaStatus.COMMITTED:
                expected_reserved_units += qty
                expected_committed_pos += 1
            else:
                assert res.status in (SagaStatus.COMPENSATED, SagaStatus.BLOCKED_BY_POLICY)

        inv = rt.erp.audit_conservation_invariants()
        assert inv.passed, f"Conservation violations: {inv.violations}"
        assert inv.active_purchase_orders == expected_committed_pos
        lot_summary = rt.erp.state_summary()["inventory"][0]
        assert lot_summary["reserved"] == expected_reserved_units
        assert rt.ledger.verify_chain_integrity().valid

    asyncio.run(_scenario())


async def test_saga_quarantine_when_compensation_itself_fails() -> None:
    rt = AegisRuntime()
    principal = PrincipalContext(
        tenant_id="t-q",
        principal_id="u-q",
        agent_id="a-q",
        roles=("procurement_planner",),
    )

    async def _broken_compensate(
        _params: dict[str, object], _out: dict[str, object]
    ) -> dict[str, object]:
        raise RuntimeError("Downstream ERP deadlocked during rollback")

    async def _failing_step2(
        _params: dict[str, object], _prior: dict[str, object]
    ) -> dict[str, object]:
        raise PermanentStepError("Step 2 exploded")

    saga = SagaDefinition(
        name="quarantine_test",
        steps=(
            SagaStepSpec(
                name="s1",
                action=ActionIntent(
                    step_name="s1",
                    tool_name="inventory.reserve_atp",
                    resource_type="inventory_lot",
                    operation="update",
                    parameters={"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 5},
                ),
                forward_fn=rt.erp.reserve_atp,
                compensate_fn=_broken_compensate,
                compensate_tool_name="compensate.inventory.release_atp",
                max_retries=1,
                retry_backoff_seconds=0.001,
            ),
            SagaStepSpec(
                name="s2",
                action=ActionIntent(
                    step_name="s2",
                    tool_name="erp.create_purchase_order",
                    resource_type="purchase_order",
                    operation="create",
                    amount_usd=1_000.0,
                ),
                forward_fn=_failing_step2,
            ),
        ),
    )

    res = await rt.coordinator.execute(principal, saga)
    assert res.status == SagaStatus.QUARANTINED
    assert res.steps[0].status == StepStatus.COMPENSATION_FAILED


async def test_idempotency_store_prevents_duplicate_side_effect() -> None:
    rt = AegisRuntime()
    principal = PrincipalContext(
        tenant_id="t-idem",
        principal_id="u-1",
        agent_id="a-1",
        roles=("procurement_planner",),
    )
    step = SagaStepSpec(
        name="reserve_once",
        action=ActionIntent(
            step_name="reserve_once",
            tool_name="inventory.reserve_atp",
            resource_type="inventory_lot",
            operation="update",
            parameters={"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 10},
        ),
        forward_fn=rt.erp.reserve_atp,
        compensate_fn=rt.erp.release_atp,
    )
    saga = SagaDefinition(workflow_id="wf_fixed_idem", name="idem_test", steps=(step,))
    r1 = await rt.coordinator.execute(principal, saga)
    r2 = await rt.coordinator.execute(principal, saga)

    assert r1.status == SagaStatus.COMMITTED
    assert r2.status == SagaStatus.COMMITTED
    assert r2.steps[0].idempotency_hit is True
    # Physical stock only deducted ONCE (10 units, not 20!)
    assert rt.erp.state_summary()["inventory"][0]["reserved"] == 10
