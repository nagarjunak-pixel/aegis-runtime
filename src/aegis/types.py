"""Immutable core domain models and security context primitives for AegisRuntime."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp with microsecond precision."""
    return datetime.now(UTC).isoformat()


def new_ulid_like(prefix: str) -> str:
    """Generate a time-sortable, collision-resistant identifier with a semantic prefix."""
    ts_ms = int(time.time() * 1000)
    rand_hex = uuid.uuid4().hex[:12]
    return f"{prefix}_{ts_ms:012x}{rand_hex}"


def deterministic_idempotency_key(
    tenant_id: str,
    workflow_id: str,
    step_name: str,
    tool_name: str,
    parameters: dict[str, Any],
) -> str:
    """Compute a content-addressed SHA-256 idempotency key for ERP/MCP mutations."""
    canonical = json.dumps(
        {
            "tenant_id": tenant_id,
            "workflow_id": workflow_id,
            "step_name": step_name,
            "tool_name": tool_name,
            "parameters": parameters,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
    return f"idem_{digest}"


class TaintLabel(StrEnum):
    """Information-flow security labels propagated across context and tool parameters."""

    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    AUTHENTICATED_USER = "AUTHENTICATED_USER"
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"
    PII_SENSITIVE = "PII_SENSITIVE"
    SECRET_CREDENTIAL = "SECRET_CREDENTIAL"


class SensitivityTier(StrEnum):
    """Data classification tiers aligned with enterprise governance standards."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_PII = "RESTRICTED_PII"
    REGULATED_FINANCIAL = "REGULATED_FINANCIAL"


class PolicyDecisionEffect(StrEnum):
    """Terminal decision produced by the deterministic policy gatekeeper."""

    PERMIT = "PERMIT"
    DENY = "DENY"


class SagaStatus(StrEnum):
    """Lifecycle states of a distributed multi-step agent saga."""

    PENDING = "PENDING"
    EXECUTING = "EXECUTING"
    COMMITTED = "COMMITTED"
    COMPENSATING = "COMPENSATING"
    COMPENSATED = "COMPENSATED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    QUARANTINED = "QUARANTINED"


class StepStatus(StrEnum):
    """Execution states of an individual forward/compensating saga step."""

    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    COMPENSATED = "COMPENSATED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"


class LedgerEventType(StrEnum):
    """Canonical event types persisted in the hash-chained execution ledger."""

    WORKFLOW_STARTED = "WORKFLOW_STARTED"
    PII_TOKENIZED = "PII_TOKENIZED"
    MODEL_ROUTED = "MODEL_ROUTED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    SAGA_STEP_EXECUTED = "SAGA_STEP_EXECUTED"
    SAGA_STEP_FAILED = "SAGA_STEP_FAILED"
    SAGA_STEP_COMPENSATED = "SAGA_STEP_COMPENSATED"
    SAGA_COMPENSATION_FAILED = "SAGA_COMPENSATION_FAILED"
    WORKFLOW_COMPLETED = "WORKFLOW_COMPLETED"


class PrincipalContext(BaseModel):
    """Zero-trust identity, role, and financial authority context of the caller."""

    model_config = ConfigDict(frozen=True)

    tenant_id: str = Field(min_length=1)
    principal_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    roles: tuple[str, ...] = Field(default_factory=tuple)
    department: str = "operations"
    cost_center: str = "CC-1000"
    max_autonomous_spend_usd: float = Field(default=25_000.0, ge=0.0)
    approver_id: str | None = None
    mfa_verified: bool = True
    region: str = "us-east-1"
    session_id: str = Field(default_factory=lambda: new_ulid_like("sess"))


class ActionIntent(BaseModel):
    """Proposed side-effecting or read tool invocation subject to formal verification."""

    model_config = ConfigDict(frozen=True)

    intent_id: str = Field(default_factory=lambda: new_ulid_like("int"))
    step_name: str
    tool_name: str
    resource_type: str
    operation: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    amount_usd: float = Field(default=0.0, ge=0.0)
    sensitivity: SensitivityTier = SensitivityTier.INTERNAL
    taint_labels: tuple[TaintLabel, ...] = Field(default_factory=tuple)
    target_domain: str = "internal.erp"
    idempotency_key: str = Field(default_factory=lambda: new_ulid_like("idem"))


class RuleEvaluationTrace(BaseModel):
    """Explainable proof record for an individual `.aegis` policy rule."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    effect: str
    matched: bool
    description: str
    expression_repr: str


class PolicyVerdict(BaseModel):
    """Deterministic authorization verdict with audit proof trace and latency."""

    model_config = ConfigDict(frozen=True)

    effect: PolicyDecisionEffect
    deciding_rule_id: str | None = None
    reason: str
    evaluation_latency_us: float = 0.0
    taint_violation: bool = False
    traces: tuple[RuleEvaluationTrace, ...] = Field(default_factory=tuple)

    @property
    def permitted(self) -> bool:
        return self.effect == PolicyDecisionEffect.PERMIT
