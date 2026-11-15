"""CLI (`typer.testing.CliRunner`), UI static route, and ERP subsystem edge-case tests."""

from __future__ import annotations

import json

import httpx
import pytest
from typer.testing import CliRunner

from aegis.api.app import create_app
from aegis.cli import app as cli_app
from aegis.enterprise.erp_systems import EnterpriseERPSandbox, FaultProfile
from aegis.policy.evaluator import PolicyEngine
from aegis.runtime import DEFAULT_POLICY_PATH, AegisRuntime
from aegis.saga.coordinator import PermanentStepError, TransientStepError
from aegis.types import ActionIntent, PrincipalContext

runner = CliRunner()


def test_cli_demo_command() -> None:
    res = runner.invoke(cli_app, ["demo"])
    assert res.exit_code == 0
    assert "Zero-Trust Attestation Summary" in res.stdout


def test_cli_benchmark_human_and_json_modes() -> None:
    res_human = runner.invoke(cli_app, ["benchmark", "--transactions", "30", "--fault-rate", "0.2"])
    assert res_human.exit_code == 0
    assert "VERIFIED" in res_human.stdout

    res_json = runner.invoke(
        cli_app, ["benchmark", "--transactions", "25", "--fault-rate", "0.15", "--json"]
    )
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["orphan_mutations"] == 0
    assert parsed["conservation_invariants_passed"] is True


def test_cli_redteam_human_and_json_modes() -> None:
    res_human = runner.invoke(cli_app, ["redteam"])
    assert res_human.exit_code == 0
    assert "100.0%" in res_human.stdout

    res_json = runner.invoke(cli_app, ["redteam", "--json"])
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["all_contained"] is True
    assert parsed["total_attacks"] == 12


async def test_ui_root_served_when_bundle_built() -> None:
    app = create_app(AegisRuntime())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r = await client.get("/")
        assert r.status_code == 200
        assert "AegisRuntime" in r.text


def test_policy_engine_from_file() -> None:
    engine = PolicyEngine.from_file(DEFAULT_POLICY_PATH)
    p = PrincipalContext(
        tenant_id="t1",
        principal_id="u1",
        agent_id="a1",
        roles=("procurement_planner",),
    )
    act = ActionIntent(
        step_name="s1",
        tool_name="inventory.reserve_atp",
        resource_type="inventory_lot",
        operation="update",
    )
    assert engine.evaluate(p, act).permitted


@pytest.mark.parametrize(
    ("method_name", "params", "err_match"),
    [
        ("reserve_atp", {"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 0}, "positive"),
        ("reserve_atp", {"plant": "BAD", "sku": "MAT-CHIP-7NM", "quantity": 5}, "not found"),
        (
            "reserve_atp",
            {"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 999999},
            "Insufficient ATP",
        ),
        (
            "create_purchase_order",
            {"vendor_id": "VEND-TSMC-01", "amount_usd": 0, "cost_center": "CC-1000"},
            "positive",
        ),
        (
            "create_purchase_order",
            {"vendor_id": "UNKNOWN", "amount_usd": 100, "cost_center": "CC-1000"},
            "Unknown SAP vendor",
        ),
        (
            "create_purchase_order",
            {"vendor_id": "VEND-TSMC-01", "amount_usd": 100, "cost_center": "CC-9999"},
            "Unknown cost center",
        ),
        (
            "create_purchase_order",
            {"vendor_id": "VEND-TSMC-01", "amount_usd": 9_999_999, "cost_center": "CC-2000"},
            "Insufficient budget",
        ),
        ("book_expedited_lane", {"lane_id": "BAD-LANE", "slots": 1}, "Insufficient air-freight"),
        (
            "execute_wire",
            {"po_id": "MISSING", "beneficiary_iban": "DE89370400440532013000"},
            "valid encumbered PO",
        ),
    ],
)
async def test_erp_validation_guards(
    method_name: str, params: dict[str, object], err_match: str
) -> None:
    erp = EnterpriseERPSandbox()
    fn = getattr(erp, method_name)
    with pytest.raises(PermanentStepError, match=err_match):
        await fn(params, {})


async def test_erp_transient_fault_injection_once_then_succeeds() -> None:
    erp = EnterpriseERPSandbox(FaultProfile(fail_tools_transient_once={"inventory.reserve_atp"}))
    with pytest.raises(TransientStepError):
        await erp.reserve_atp({"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 5}, {})
    out = await erp.reserve_atp({"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 5}, {})
    assert out["quantity"] == 5

    # Idempotent double-release returns ALREADY_RELEASED cleanly
    r1 = await erp.release_atp({}, out)
    r2 = await erp.release_atp({}, out)
    assert r1["status"] == "RELEASED"
    assert r2["status"] == "ALREADY_RELEASED"
    assert erp.audit_conservation_invariants().passed


async def test_erp_fx_unwind_wire_reverse_and_vendor_iban_update() -> None:
    erp = EnterpriseERPSandbox()
    fx = await erp.lock_fx_hedge({"currency_pair": "USD/EUR", "notional_usd": 10000.0}, {})
    unwound = await erp.unwind_fx_hedge({}, fx)
    assert unwound["status"] == "UNWOUND"

    po = await erp.create_purchase_order(
        {"vendor_id": "VEND-TSMC-01", "amount_usd": 2000.0, "cost_center": "CC-1000"}, {}
    )
    wire = await erp.execute_wire(
        {"po_id": po["po_id"], "beneficiary_iban": "DE89370400440532013000"}, {}
    )
    rev1 = await erp.reverse_wire({}, wire)
    rev2 = await erp.reverse_wire({}, wire)
    assert rev1["status"] == "REVERSED"
    assert rev2["status"] == "ALREADY_REVERSED"

    cancel_po = await erp.cancel_purchase_order({}, po)
    assert cancel_po["status"] == "CANCELLED"

    upd = await erp.update_vendor_iban(
        {"vendor_id": "VEND-TSMC-01", "new_iban": "DE44500105175407324931"}, {}
    )
    assert upd["new_iban"] == "DE44500105175407324931"
    assert erp.audit_conservation_invariants().passed


@pytest.mark.parametrize(
    "scenario_bad",
    ["unknown_scenario_xyz"],
)
async def test_unknown_scenario_raises_key_error(scenario_bad: str) -> None:
    rt = AegisRuntime()
    with pytest.raises(KeyError):
        await rt.run_reference_scenario(scenario_bad)
