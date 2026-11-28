"""Unit, API, and Hypothesis property tests for OpaqueSecretBroker & MultiActorCapabilitySession."""

from __future__ import annotations

import base64
import urllib.parse

import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.api.app import create_app
from aegis.policy.credential_broker import (
    EgressAllowRule,
    MultiActorCapabilitySession,
    OpaqueSecretBroker,
)


def test_broker_validation_and_sandbox_env_isolation() -> None:
    with pytest.raises(ValueError, match="broker_key"):
        OpaqueSecretBroker(b"short")

    broker = OpaqueSecretBroker(b"0123456789abcdef0123456789abcdef")
    with pytest.raises(ValueError, match="Invalid secret alias"):
        broker.register_secret("bad alias!", "secret-value-1234", ())
    with pytest.raises(ValueError, match="at least 8"):
        broker.register_secret("short_sec", "tiny", ())

    raw = "sk-prod-erp-key-9988776655"
    handle = broker.register_secret(
        "sap-odata",
        raw,
        allowed_egress=(EgressAllowRule("agent-fin", "erp.corp.internal", "GET", "/sap/opu"),),
    )
    env = broker.agent_environment_view()
    assert env == {"AEGIS_SECRET_SAP_ODATA": handle}
    assert raw not in str(env)


def test_authorized_swap_and_default_deny_proposals() -> None:
    broker = OpaqueSecretBroker(b"aegis-broker-test-master-secret-32b")
    raw_secret = "Bearer-SuperSecret-Token-2026"
    handle = broker.register_secret(
        "billing_api",
        raw_secret,
        allowed_egress=(
            EgressAllowRule("agent-ap", "billing.example.com", "POST", "/v1/invoices"),
        ),
    )
    broker.add_egress_rule(EgressAllowRule("agent-ap", "status.example.com", "GET", "/health"))

    ok = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="POST",
        url="https://billing.example.com/v1/invoices/create",
        headers={"Authorization": f"Bearer {handle}"},
        body=f'{{"token_echo":"{handle}"}}',
    )
    assert ok.allowed is True
    assert ok.swapped_aliases == ("billing_api",)
    assert ok.resolved_headers["Authorization"] == f"Bearer {raw_secret}"
    assert raw_secret in ok.resolved_body
    assert ok.policy_diff_proposal is None

    pub = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="GET",
        url="https://status.example.com/health",
        headers={"Accept": "application/json"},
    )
    assert pub.allowed is True
    assert pub.swapped_aliases == ()

    denied_unlisted = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="GET",
        url="https://attacker.example.net/collect",
        headers={},
    )
    assert denied_unlisted.allowed is False
    assert denied_unlisted.reason == "default_deny_unlisted_egress_host"
    assert denied_unlisted.policy_diff_proposal is not None
    assert denied_unlisted.policy_diff_proposal.path_prefix == "/collect"

    denied_http = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="POST",
        url="http://billing.example.com/v1/invoices",
        headers={"Authorization": handle},
    )
    assert denied_http.allowed is False
    assert denied_http.reason == "non_https_or_missing_host_blocked"

    denied_scope = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="POST",
        url="https://evil.example.org/v1/invoices",
        headers={"Authorization": handle},
    )
    assert denied_scope.allowed is False
    assert denied_scope.reason == "secret_scope_denied_for_route:billing_api"
    assert len(broker.proposals) == 3

    forged = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="POST",
        url="https://billing.example.com/v1/invoices",
        headers={"Authorization": "sec_ref://billing_api:0000000000000000"},
    )
    assert forged.allowed is False
    assert forged.reason == "forged_or_unknown_secret_handle:billing_api"

    in_query = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="POST",
        url=f"https://billing.example.com/v1/invoices?tok={handle}",
        headers={},
    )
    assert in_query.allowed is False
    assert in_query.reason == "secret_handle_disallowed_in_url_path_or_query"

    root_denied = broker.inspect_and_swap_egress(
        actor_id="agent-ap",
        method="GET",
        url="https://unlisted.example.org/",
        headers={},
    )
    assert root_denied.policy_diff_proposal is not None
    assert root_denied.policy_diff_proposal.path_prefix == "/"


@given(
    secret_core=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
        min_size=12,
        max_size=32,
    )
)
@settings(max_examples=40)
def test_property_raw_and_encoded_exfiltration_always_blocked(secret_core: str) -> None:
    broker = OpaqueSecretBroker(b"hypothesis-secret-broker-key-2026")
    broker.register_secret(
        "vault_key",
        secret_core,
        allowed_egress=(EgressAllowRule("*", "api.safe.internal", "*", "/"),),
    )
    b64 = base64.b64encode(secret_core.encode("utf-8")).decode("ascii")
    hex_enc = secret_core.encode("utf-8").hex()
    url_enc = urllib.parse.quote(secret_core, safe="")

    for leaked in (secret_core, b64, hex_enc, url_enc):
        res = broker.inspect_and_swap_egress(
            actor_id="agent-1",
            method="POST",
            url="https://api.safe.internal/upload",
            headers={"X-Trace": "clean"},
            body=f"payload={leaked}",
        )
        assert res.allowed is False
        assert res.exfiltration_detected is True


def test_multi_actor_capability_isolation_zero_authority_bleed() -> None:
    session = MultiActorCapabilitySession()
    with pytest.raises(ValueError, match="non-empty"):
        session.register_actor("", {"read_kb"})

    session.register_actor("cfo_user", {"read_kb", "approve_wire", "export_ledger"})
    session.register_actor("guest_analyst", {"read_kb"})

    assert session.authorize_tool_call("unknown_user", "read_kb").allowed is False
    assert session.authorize_tool_call("guest_analyst", "read_kb").allowed is True
    assert session.authorize_tool_call("guest_analyst", "approve_wire").allowed is False

    bleed = session.authorize_tool_call(
        "guest_analyst", "approve_wire", claimed_delegator_id="cfo_user"
    )
    assert bleed.allowed is False
    assert bleed.reason == "cross_speaker_authority_bleed_blocked"

    with pytest.raises(PermissionError):
        session.grant_scoped_delegation("guest_analyst", "cfo_user", "approve_wire")

    session.grant_scoped_delegation("cfo_user", "guest_analyst", "export_ledger")
    delegated = session.authorize_tool_call(
        "guest_analyst", "export_ledger", claimed_delegator_id="cfo_user"
    )
    assert delegated.allowed is True
    assert "export_ledger" in delegated.effective_capabilities


def test_fastapi_egress_broker_endpoint() -> None:
    client = TestClient(create_app())
    ok_resp = client.post(
        "/api/v1/egress/broker",
        json={
            "actor_id": "fin-agent",
            "method": "POST",
            "url": "https://api.erp.example.com/v1/journal",
            "headers": {"Authorization": "Bearer {{ERP_TOKEN}}"},
            "body": '{"status":"ready"}',
            "allowed_host": "api.erp.example.com",
            "allowed_path_prefix": "/v1",
        },
    )
    assert ok_resp.status_code == 200
    data = ok_resp.json()
    assert data["allowed"] is True
    assert data["swapped_aliases"] == ["erp_token"]
    assert data["proposal_sha256"] is None

    deny_resp = client.post(
        "/api/v1/egress/broker",
        json={
            "actor_id": "fin-agent",
            "method": "POST",
            "url": "https://untrusted.external.io/v1/steal",
            "headers": {"Authorization": "Bearer {{ERP_TOKEN}}"},
        },
    )
    assert deny_resp.status_code == 200
    deny_data = deny_resp.json()
    assert deny_data["allowed"] is False
    assert isinstance(deny_data["proposal_sha256"], str)
