"""FastAPI async control-plane server exposing governance, replay, chaos, MCP & UI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aegis.benchmarks.chaos_suite import run_chaos_benchmark
from aegis.benchmarks.redteam_suite import run_redteam_suite
from aegis.enterprise.scenarios import EnterpriseScenarioCatalog
from aegis.ledger.crypto import verify_merkle_proof
from aegis.policy.compaction_guard import (
    CompactionAttributionLedger,
    canonicalize_tool_schemas,
)
from aegis.policy.credential_broker import EgressAllowRule, OpaqueSecretBroker
from aegis.policy.evaluator import PolicyEngine
from aegis.policy.parser import PolicySyntaxError
from aegis.runtime import AegisRuntime
from aegis.types import ActionIntent, PrincipalContext


class PolicyEvalRequest(BaseModel):
    principal: PrincipalContext
    action: ActionIntent
    context: dict[str, Any] = Field(default_factory=dict)
    custom_policy_source: str | None = None


class CounterfactualRequest(BaseModel):
    candidate_policy_source: str
    context_override: dict[str, Any] = Field(default_factory=dict)


class ChaosRequest(BaseModel):
    transactions: int = Field(default=120, ge=10, le=1000)
    fault_rate: float = Field(default=0.25, ge=0.0, le=0.9)


class CompactionVerifyRequest(BaseModel):
    principal_id: str
    user_turns: list[str]
    compactor_summary: str
    sensitive_target: str
    tools: list[dict[str, Any]] = Field(default_factory=list)


class EgressBrokerRequest(BaseModel):
    actor_id: str
    method: str = "POST"
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    allowed_host: str = "api.erp.example.com"
    allowed_path_prefix: str = "/v1"


def create_app(runtime: AegisRuntime | None = None) -> FastAPI:
    """Create the FastAPI Control Plane application wired to `AegisRuntime`."""
    rt = runtime or AegisRuntime()

    app = FastAPI(
        title="AegisRuntime Control Plane API",
        version="0.4.0",
        description=(
            "Zero-Trust Enterprise Agentic Control Plane: AST Policy Gatekeeper, "
            "Distributed ERP Sagas, RFC-6962 Merkle Audit Ledger, and Counterfactual Replay."
        ),
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health")
    async def health() -> dict[str, Any]:
        chain = rt.ledger.verify_chain_integrity()
        inv = rt.erp.audit_conservation_invariants()
        return {
            "status": "healthy" if (chain.valid and inv.passed) else "degraded",
            "version": "0.4.0",
            "ledger_valid": chain.valid,
            "erp_conservation_valid": inv.passed,
        }

    @app.get("/api/v1/overview")
    async def overview() -> dict[str, Any]:
        return rt.system_overview()

    @app.get("/api/v1/policy/source")
    async def get_policy_source() -> dict[str, Any]:
        return {
            "policy_hash": rt.policy_engine.policy_hash,
            "source": rt.policy_source,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "effect": r.effect.value,
                    "description": r.description,
                    "expression": r.condition.pretty(),
                }
                for r in rt.policy_engine.policy_set.rules
            ],
        }

    @app.post("/api/v1/policy/evaluate")
    async def evaluate_policy(req: PolicyEvalRequest) -> dict[str, Any]:
        try:
            engine = (
                PolicyEngine.from_source(req.custom_policy_source)
                if req.custom_policy_source
                else rt.policy_engine
            )
        except PolicySyntaxError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        verdict = engine.evaluate(req.principal, req.action, req.context)
        return verdict.model_dump()

    @app.get("/api/v1/scenarios")
    async def list_scenarios() -> list[dict[str, Any]]:
        return [s.model_dump() for s in EnterpriseScenarioCatalog.list_scenarios()]

    @app.post("/api/v1/scenarios/{scenario_id}/run")
    async def run_scenario(scenario_id: str) -> dict[str, Any]:
        try:
            bundle = await rt.run_reference_scenario(scenario_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return bundle.model_dump()

    @app.get("/api/v1/ledger/events")
    async def list_ledger_events(
        workflow_id: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        entries = rt.ledger.list_events(workflow_id=workflow_id, limit=limit)
        return [e.model_dump() for e in entries]

    @app.get("/api/v1/ledger/verify")
    async def verify_ledger() -> dict[str, Any]:
        return rt.ledger.verify_chain_integrity().model_dump()

    @app.get("/api/v1/ledger/proof/{seq}")
    async def get_merkle_proof(seq: int) -> dict[str, Any]:
        try:
            proof = rt.ledger.generate_inclusion_proof(seq)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        verified = verify_merkle_proof(proof)
        return {
            "leaf_index": proof.leaf_index,
            "tree_size": proof.tree_size,
            "event_hash_hex": proof.event_hash_hex,
            "root_hash_hex": proof.root_hash_hex,
            "verified": verified,
            "audit_path": [
                {
                    "sibling_hash_hex": s.sibling_hash_hex,
                    "is_left_sibling": s.is_left_sibling,
                }
                for s in proof.audit_path
            ],
        }

    @app.get("/api/v1/replay/{workflow_id}")
    async def replay_workflow(
        workflow_id: str,
        up_to_seq: int | None = None,
    ) -> dict[str, Any]:
        try:
            snap = rt.replay_engine.replay_workflow(workflow_id, up_to_seq=up_to_seq)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return snap.model_dump()

    @app.post("/api/v1/replay/{workflow_id}/counterfactual")
    async def counterfactual_replay(
        workflow_id: str,
        req: CounterfactualRequest,
    ) -> dict[str, Any]:
        try:
            diff = rt.replay_engine.simulate_counterfactual_policy(
                workflow_id,
                candidate_policy_source=req.candidate_policy_source,
                context_override=req.context_override,
            )
        except PolicySyntaxError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return diff.model_dump()

    @app.post("/api/v1/benchmarks/chaos")
    async def trigger_chaos_benchmark(req: ChaosRequest) -> dict[str, Any]:
        report = await run_chaos_benchmark(
            transactions=req.transactions,
            fault_rate=req.fault_rate,
        )
        return report.model_dump()

    @app.post("/api/v1/benchmarks/redteam")
    async def trigger_redteam_suite() -> dict[str, Any]:
        report = await run_redteam_suite()
        return report.model_dump()

    @app.post("/api/v1/mcp/rpc")
    async def mcp_jsonrpc_endpoint(payload: dict[str, Any]) -> dict[str, Any]:
        return await rt.mcp_server.handle_jsonrpc(payload)

    @app.post("/api/v1/compact/verify")
    async def verify_compaction_boundary(req: CompactionVerifyRequest) -> dict[str, Any]:
        ledger = CompactionAttributionLedger(b"aegis-runtime-compaction-hmac-v1")
        for turn in req.user_turns:
            ledger.seal_user_turn(req.principal_id, turn)
        bundle = ledger.compact_context(req.compactor_summary)
        verdict = ledger.verify_request_derived_target(
            req.principal_id, req.sensitive_target, bundle
        )
        _, tool_manifest_sha256 = canonicalize_tool_schemas(req.tools)
        return {
            "allowed": verdict.allowed,
            "matched_turn_id": verdict.matched_turn_id,
            "reason": verdict.reason,
            "compaction_epoch": bundle.compaction_epoch,
            "tool_manifest_sha256": tool_manifest_sha256,
        }

    @app.post("/api/v1/egress/broker")
    async def inspect_egress_broker(req: EgressBrokerRequest) -> dict[str, Any]:
        broker = OpaqueSecretBroker(b"aegis-runtime-egress-broker-key-v1")
        handle = broker.register_secret(
            "erp_token",
            "sk-live-erp-9876543210abcdef",
            allowed_egress=(
                EgressAllowRule(
                    actor_id=req.actor_id,
                    host=req.allowed_host,
                    method=req.method,
                    path_prefix=req.allowed_path_prefix,
                ),
            ),
        )
        headers = {k: v.replace("{{ERP_TOKEN}}", handle) for k, v in req.headers.items()}
        body = req.body.replace("{{ERP_TOKEN}}", handle)
        res = broker.inspect_and_swap_egress(
            actor_id=req.actor_id,
            method=req.method,
            url=req.url,
            headers=headers,
            body=body,
        )
        return {
            "allowed": res.allowed,
            "reason": res.reason,
            "exfiltration_detected": res.exfiltration_detected,
            "swapped_aliases": list(res.swapped_aliases),
            "sandbox_env": broker.agent_environment_view(),
            "proposal_sha256": (
                res.policy_diff_proposal.proposal_sha256 if res.policy_diff_proposal else None
            ),
        }

    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics() -> str:
        return rt.telemetry.render_prometheus_metrics()

    ui_dist = Path(__file__).resolve().parents[3] / "ui" / "dist"
    if ui_dist.exists() and (ui_dist / "index.html").exists():
        assets_dir = ui_dist / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="ui-assets")

        @app.get("/", response_model=None)
        async def serve_control_tower() -> FileResponse:
            return FileResponse(ui_dist / "index.html")
    else:

        @app.get("/")
        async def serve_headless_root() -> dict[str, str]:
            return {
                "service": "AegisRuntime Control Plane",
                "version": "0.4.0",
                "openapi_docs": "/docs",
                "metrics": "/metrics",
            }

    return app
