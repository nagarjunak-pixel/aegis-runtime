"""Tests for Deterministic Time-Travel Replay, Counterfactual Diffing & MCP JSON-RPC."""

from __future__ import annotations

import pytest

from aegis.benchmarks.chaos_suite import run_chaos_benchmark
from aegis.benchmarks.redteam_suite import run_redteam_suite
from aegis.enterprise.scenarios import EnterpriseScenarioCatalog
from aegis.runtime import AegisRuntime


async def test_time_travel_replay_and_counterfactual_policy_diff() -> None:
    rt = AegisRuntime()
    bundle = await rt.run_reference_scenario("semiconductor_shortage_resilience")
    wf_id = bundle.saga_result.workflow_id

    full_snap = rt.replay_engine.replay_workflow(wf_id)
    assert full_snap.derived_status == "COMMITTED"
    assert len(full_snap.executed_steps) == 4

    # Time-travel to sequence 4 (mid-flight before completion)
    events = rt.ledger.list_events(workflow_id=wf_id)
    mid_seq = events[3].seq
    partial_snap = rt.replay_engine.replay_workflow(wf_id, up_to_seq=mid_seq)
    assert partial_snap.replayed_up_to_seq == mid_seq
    assert partial_snap.derived_status != "COMMITTED"

    # Counterfactual policy lowering autonomous spend cap to $5,000 flips the $18,500 steps to DENY!
    stricter_policy = (
        'rule "strict-5k-cap" { effect: forbid when: action.amount_usd > 5000 }\n'
        + rt.policy_source
    )
    diff = rt.replay_engine.simulate_counterfactual_policy(
        wf_id, candidate_policy_source=stricter_policy
    )
    assert diff.newly_blocked_steps >= 2
    assert diff.verdict_flips >= 2


async def test_mcp_jsonrpc_protocol_compliance() -> None:
    rt = AegisRuntime()
    mcp = rt.mcp_server

    init_resp = await mcp.handle_jsonrpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp["result"]["serverInfo"]["name"] == "aegis-enterprise-erp-mcp"

    list_resp = await mcp.handle_jsonrpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = list_resp["result"]["tools"]
    assert len(tools) == 6

    call_resp = await mcp.handle_jsonrpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "inventory.reserve_atp",
                "arguments": {"plant": "PLANT-DE-01", "sku": "MAT-CHIP-7NM", "quantity": 15},
            },
        }
    )
    assert call_resp["result"]["isError"] is False
    assert call_resp["result"]["content"][0]["data"]["quantity"] == 15

    bad_ver = await mcp.handle_jsonrpc({"jsonrpc": "1.0", "id": 4, "method": "initialize"})
    assert bad_ver["error"]["code"] == -32600

    bad_tool = await mcp.handle_jsonrpc(
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "nope"}}
    )
    assert bad_tool["error"]["code"] == -32601


@pytest.mark.parametrize(
    ("scenario_id", "expected_status"),
    [
        ("semiconductor_shortage_resilience", "COMMITTED"),
        ("mid_saga_treasury_outage_rollback", "COMPENSATED"),
        ("indirect_prompt_injection_iban_hijack", "BLOCKED_BY_POLICY"),
        ("sox_segregation_of_duties_violation", "BLOCKED_BY_POLICY"),
        ("ofac_sanctioned_vendor_mid_saga_block", "BLOCKED_BY_POLICY"),
        ("executive_dual_control_high_value_po", "COMMITTED"),
    ],
)
async def test_all_six_reference_enterprise_scenarios(
    scenario_id: str, expected_status: str
) -> None:
    rt = AegisRuntime()
    assert len(EnterpriseScenarioCatalog.list_scenarios()) == 6
    bundle = await rt.run_reference_scenario(scenario_id)
    assert bundle.saga_result.status.value == expected_status
    assert bundle.conservation_passed


async def test_redteam_and_chaos_suites_achieve_100_percent_invariants() -> None:
    red = await run_redteam_suite()
    assert red.all_contained
    assert red.containment_rate_pct == 100.0

    chaos = await run_chaos_benchmark(transactions=60, fault_rate=0.30)
    assert chaos.orphan_mutations == 0
    assert chaos.conservation_invariants_passed
    assert chaos.ledger_integrity_passed
