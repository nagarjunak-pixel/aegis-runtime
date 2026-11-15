"""End-to-end FastAPI Control Plane integration tests over ASGI."""

from __future__ import annotations

import httpx

from aegis.api.app import create_app
from aegis.runtime import AegisRuntime


async def test_fastapi_control_plane_endpoints_e2e() -> None:
    rt = AegisRuntime()
    app = create_app(rt)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        r_health = await client.get("/api/v1/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "healthy"

        r_sc = await client.get("/api/v1/scenarios")
        assert r_sc.status_code == 200
        assert len(r_sc.json()) == 6

        r_not_found = await client.post("/api/v1/scenarios/nonexistent/run")
        assert r_not_found.status_code == 404

        r_run = await client.post("/api/v1/scenarios/semiconductor_shortage_resilience/run")
        assert r_run.status_code == 200
        run_data = r_run.json()
        wf_id = run_data["saga_result"]["workflow_id"]
        assert run_data["saga_result"]["status"] == "COMMITTED"

        r_ov = await client.get("/api/v1/overview")
        assert r_ov.status_code == 200
        assert r_ov.json()["ledger"]["valid"] is True

        r_pol = await client.get("/api/v1/policy/source")
        assert r_pol.status_code == 200
        assert len(r_pol.json()["rules"]) >= 8

        r_eval = await client.post(
            "/api/v1/policy/evaluate",
            json={
                "principal": {
                    "tenant_id": "t1",
                    "principal_id": "u1",
                    "agent_id": "a1",
                    "roles": ["procurement_planner"],
                },
                "action": {
                    "step_name": "s1",
                    "tool_name": "erp.create_purchase_order",
                    "resource_type": "purchase_order",
                    "operation": "create",
                    "amount_usd": 1200.0,
                },
            },
        )
        assert r_eval.status_code == 200
        assert r_eval.json()["effect"] == "PERMIT"

        r_bad_pol = await client.post(
            "/api/v1/policy/evaluate",
            json={
                "principal": {"tenant_id": "t1", "principal_id": "u1", "agent_id": "a1"},
                "action": {
                    "step_name": "s1",
                    "tool_name": "erp.create_purchase_order",
                    "resource_type": "purchase_order",
                    "operation": "create",
                },
                "custom_policy_source": "invalid syntax {{{",
            },
        )
        assert r_bad_pol.status_code == 400

        r_events = await client.get(f"/api/v1/ledger/events?workflow_id={wf_id}")
        assert r_events.status_code == 200
        assert len(r_events.json()) >= 5

        r_verify = await client.get("/api/v1/ledger/verify")
        assert r_verify.status_code == 200
        assert r_verify.json()["valid"] is True

        r_proof = await client.get("/api/v1/ledger/proof/1")
        assert r_proof.status_code == 200
        assert r_proof.json()["verified"] is True

        r_proof_404 = await client.get("/api/v1/ledger/proof/99999")
        assert r_proof_404.status_code == 404

        r_replay = await client.get(f"/api/v1/replay/{wf_id}")
        assert r_replay.status_code == 200
        assert r_replay.json()["derived_status"] == "COMMITTED"

        r_cf = await client.post(
            f"/api/v1/replay/{wf_id}/counterfactual",
            json={
                "candidate_policy_source": 'rule "block-all" { effect: forbid when: action.amount_usd > 100 }'
            },
        )
        assert r_cf.status_code == 200
        assert r_cf.json()["verdict_flips"] >= 1

        r_chaos = await client.post(
            "/api/v1/benchmarks/chaos",
            json={"transactions": 30, "fault_rate": 0.2},
        )
        assert r_chaos.status_code == 200
        assert r_chaos.json()["orphan_mutations"] == 0

        r_rt = await client.post("/api/v1/benchmarks/redteam")
        assert r_rt.status_code == 200
        assert r_rt.json()["all_contained"] is True

        r_mcp = await client.post(
            "/api/v1/mcp/rpc",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert r_mcp.status_code == 200
        assert len(r_mcp.json()["result"]["tools"]) == 6

        r_metrics = await client.get("/metrics")
        assert r_metrics.status_code == 200
        assert "aegis_spans_recorded_total" in r_metrics.text
