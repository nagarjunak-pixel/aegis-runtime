"""Orchestrated Distributed Saga Engine with reverse-order rollbacks and quarantine isolation."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aegis.ledger.store import EventLedger
from aegis.policy.evaluator import PolicyEngine
from aegis.privacy.vault import PIITokenVault
from aegis.saga.idempotency import IdempotencyStore
from aegis.telemetry.tracing import TelemetryCollector
from aegis.types import (
    ActionIntent,
    LedgerEventType,
    PolicyDecisionEffect,
    PolicyVerdict,
    PrincipalContext,
    SagaStatus,
    StepStatus,
    deterministic_idempotency_key,
    new_ulid_like,
)

ForwardCallable = Callable[[dict[str, Any], dict[str, Any]], Awaitable[dict[str, Any]]]
CompensateCallable = Callable[[dict[str, Any], dict[str, Any]], Awaitable[dict[str, Any]]]
ContextBuilder = Callable[[dict[str, Any]], dict[str, Any]]


class TransientStepError(RuntimeError):
    """Retriable downstream infrastructure error (e.g., HTTP 503, lock contention)."""


class PermanentStepError(RuntimeError):
    """Non-retriable domain or invariant error requiring immediate saga rollback."""


@dataclass(frozen=True, slots=True)
class SagaStepSpec:
    """Declarative specification of a forward action and its compensating inverse."""

    name: str
    action: ActionIntent
    forward_fn: ForwardCallable
    compensate_fn: CompensateCallable | None = None
    compensate_tool_name: str | None = None
    max_retries: int = 2
    retry_backoff_seconds: float = 0.01
    timeout_seconds: float = 5.0
    context_builder: ContextBuilder | None = None


@dataclass(frozen=True, slots=True)
class SagaDefinition:
    """Multi-step transactional workflow executed under zero-trust governance."""

    workflow_id: str = field(default_factory=lambda: new_ulid_like("wf"))
    name: str = "enterprise_saga"
    steps: tuple[SagaStepSpec, ...] = ()
    base_context: Mapping[str, Any] = field(default_factory=dict)


class StepExecutionRecord(BaseModel):
    """Audit and timing record for an individual saga step."""

    model_config = ConfigDict(frozen=True)

    step_name: str
    tool_name: str
    status: StepStatus
    attempts: int
    latency_ms: float
    policy_verdict: PolicyVerdict
    forward_output: dict[str, Any] = Field(default_factory=dict)
    compensation_output: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    idempotency_hit: bool = False


class SagaExecutionResult(BaseModel):
    """Terminal result of an orchestrated enterprise saga."""

    model_config = ConfigDict(frozen=True)

    workflow_id: str
    workflow_name: str
    tenant_id: str
    status: SagaStatus
    steps: tuple[StepExecutionRecord, ...]
    total_latency_ms: float
    compensated_steps: int = 0
    failure_reason: str | None = None


class SagaCoordinator:
    """Deterministic Saga Orchestrator enforcing Policy-before-Mutation and Reverse Rollback."""

    def __init__(
        self,
        *,
        policy_engine: PolicyEngine,
        ledger: EventLedger,
        pii_vault: PIITokenVault | None = None,
        idempotency_store: IdempotencyStore | None = None,
        telemetry: TelemetryCollector | None = None,
    ) -> None:
        self._policy = policy_engine
        self._ledger = ledger
        self._vault = pii_vault or PIITokenVault()
        self._idempotency = idempotency_store or IdempotencyStore()
        self._telemetry = telemetry or TelemetryCollector()

    async def execute(
        self,
        principal: PrincipalContext,
        saga: SagaDefinition,
    ) -> SagaExecutionResult:
        """Execute all saga steps atomically up to compensation equivalence."""
        t_workflow_start = time.perf_counter()

        self._ledger.append(
            tenant_id=principal.tenant_id,
            workflow_id=saga.workflow_id,
            event_type=LedgerEventType.WORKFLOW_STARTED,
            payload={
                "workflow_name": saga.name,
                "principal_id": principal.principal_id,
                "agent_id": principal.agent_id,
                "roles": list(principal.roles),
                "step_count": len(saga.steps),
                "policy_hash": self._policy.policy_hash,
            },
        )

        prior_outputs: dict[str, Any] = {}
        completed_stack: list[tuple[SagaStepSpec, dict[str, Any], dict[str, Any], str]] = []
        step_records: list[StepExecutionRecord] = []

        for step in saga.steps:
            step_t0 = time.perf_counter()
            eval_ctx = dict(saga.base_context)
            if step.context_builder is not None:
                eval_ctx.update(step.context_builder(prior_outputs))

            tokenized_params_res = self._vault.tokenize_payload(
                principal.tenant_id, step.action.parameters
            )
            sanitized_params: dict[str, Any] = tokenized_params_res.sanitized_value
            idem_key = deterministic_idempotency_key(
                tenant_id=principal.tenant_id,
                workflow_id=saga.workflow_id,
                step_name=step.name,
                tool_name=step.action.tool_name,
                parameters=sanitized_params,
            )

            governed_intent = step.action.model_copy(
                update={
                    "parameters": sanitized_params,
                    "idempotency_key": idem_key,
                }
            )

            with self._telemetry.span(
                "aegis.policy.evaluate",
                attributes={"workflow_id": saga.workflow_id, "step": step.name},
            ):
                verdict = self._policy.evaluate(principal, governed_intent, eval_ctx)

            self._ledger.append(
                tenant_id=principal.tenant_id,
                workflow_id=saga.workflow_id,
                event_type=LedgerEventType.POLICY_EVALUATED,
                payload={
                    "step_name": step.name,
                    "tool_name": governed_intent.tool_name,
                    "operation": governed_intent.operation,
                    "amount_usd": governed_intent.amount_usd,
                    "effect": verdict.effect.value,
                    "deciding_rule_id": verdict.deciding_rule_id,
                    "reason": verdict.reason,
                    "taint_violation": verdict.taint_violation,
                    "latency_us": verdict.evaluation_latency_us,
                },
            )

            if not verdict.permitted:
                step_elapsed = (time.perf_counter() - step_t0) * 1000.0
                step_records.append(
                    StepExecutionRecord(
                        step_name=step.name,
                        tool_name=governed_intent.tool_name,
                        status=StepStatus.BLOCKED,
                        attempts=0,
                        latency_ms=round(step_elapsed, 3),
                        policy_verdict=verdict,
                        error_message=verdict.reason,
                    )
                )
                comp_count, quarantined = await self._rollback_completed(
                    principal=principal,
                    workflow_id=saga.workflow_id,
                    completed_stack=completed_stack,
                    step_records=step_records,
                )
                final_status = (
                    SagaStatus.QUARANTINED if quarantined else SagaStatus.BLOCKED_BY_POLICY
                )
                return self._finalize_workflow(
                    principal=principal,
                    saga=saga,
                    status=final_status,
                    step_records=step_records,
                    compensated_steps=comp_count,
                    failure_reason=verdict.reason,
                    t_start=t_workflow_start,
                )

            cached_output = self._idempotency.get(principal.tenant_id, idem_key)
            if cached_output is not None:
                step_elapsed = (time.perf_counter() - step_t0) * 1000.0
                prior_outputs[step.name] = cached_output
                completed_stack.append((step, sanitized_params, cached_output, idem_key))
                step_records.append(
                    StepExecutionRecord(
                        step_name=step.name,
                        tool_name=governed_intent.tool_name,
                        status=StepStatus.SUCCEEDED,
                        attempts=0,
                        latency_ms=round(step_elapsed, 3),
                        policy_verdict=verdict,
                        forward_output=cached_output,
                        idempotency_hit=True,
                    )
                )
                continue

            # Detokenize strictly inside trusted `.erp` execution boundary
            exec_params = self._vault.detokenize_payload(
                principal.tenant_id,
                sanitized_params,
                target_domain=governed_intent.target_domain,
            )

            attempts = 0
            last_exc: Exception | None = None
            forward_out: dict[str, Any] | None = None

            with self._telemetry.span(
                "aegis.saga.step.forward",
                attributes={
                    "workflow_id": saga.workflow_id,
                    "step": step.name,
                    "tool": governed_intent.tool_name,
                },
            ):
                while attempts <= step.max_retries:
                    attempts += 1
                    try:
                        raw_out = await asyncio.wait_for(
                            step.forward_fn(exec_params, dict(prior_outputs)),
                            timeout=step.timeout_seconds,
                        )
                        forward_out = self._vault.tokenize_payload(
                            principal.tenant_id, raw_out
                        ).sanitized_value
                        break
                    except TransientStepError as exc:
                        last_exc = exc
                        if attempts <= step.max_retries:
                            await asyncio.sleep(step.retry_backoff_seconds * (2 ** (attempts - 1)))
                            continue
                        break
                    except (TimeoutError, PermanentStepError, Exception) as exc:
                        last_exc = exc
                        break

            step_elapsed = (time.perf_counter() - step_t0) * 1000.0

            if forward_out is not None:
                self._idempotency.put(principal.tenant_id, idem_key, forward_out)
                prior_outputs[step.name] = forward_out
                completed_stack.append((step, exec_params, forward_out, idem_key))

                self._ledger.append(
                    tenant_id=principal.tenant_id,
                    workflow_id=saga.workflow_id,
                    event_type=LedgerEventType.SAGA_STEP_EXECUTED,
                    payload={
                        "step_name": step.name,
                        "tool_name": governed_intent.tool_name,
                        "idempotency_key": idem_key,
                        "attempts": attempts,
                        "parameters": sanitized_params,
                        "output": forward_out,
                        "latency_ms": round(step_elapsed, 3),
                    },
                )

                step_records.append(
                    StepExecutionRecord(
                        step_name=step.name,
                        tool_name=governed_intent.tool_name,
                        status=StepStatus.SUCCEEDED,
                        attempts=attempts,
                        latency_ms=round(step_elapsed, 3),
                        policy_verdict=verdict,
                        forward_output=forward_out,
                    )
                )
            else:
                err_msg = f"{type(last_exc).__name__}: {last_exc}" if last_exc else "Step failed"
                self._ledger.append(
                    tenant_id=principal.tenant_id,
                    workflow_id=saga.workflow_id,
                    event_type=LedgerEventType.SAGA_STEP_FAILED,
                    payload={
                        "step_name": step.name,
                        "tool_name": governed_intent.tool_name,
                        "attempts": attempts,
                        "error": err_msg,
                    },
                )
                step_records.append(
                    StepExecutionRecord(
                        step_name=step.name,
                        tool_name=governed_intent.tool_name,
                        status=StepStatus.FAILED,
                        attempts=attempts,
                        latency_ms=round(step_elapsed, 3),
                        policy_verdict=verdict,
                        error_message=err_msg,
                    )
                )
                comp_count, quarantined = await self._rollback_completed(
                    principal=principal,
                    workflow_id=saga.workflow_id,
                    completed_stack=completed_stack,
                    step_records=step_records,
                )
                final_status = SagaStatus.QUARANTINED if quarantined else SagaStatus.COMPENSATED
                return self._finalize_workflow(
                    principal=principal,
                    saga=saga,
                    status=final_status,
                    step_records=step_records,
                    compensated_steps=comp_count,
                    failure_reason=err_msg,
                    t_start=t_workflow_start,
                )

        return self._finalize_workflow(
            principal=principal,
            saga=saga,
            status=SagaStatus.COMMITTED,
            step_records=step_records,
            compensated_steps=0,
            failure_reason=None,
            t_start=t_workflow_start,
        )

    async def _rollback_completed(
        self,
        *,
        principal: PrincipalContext,
        workflow_id: str,
        completed_stack: list[tuple[SagaStepSpec, dict[str, Any], dict[str, Any], str]],
        step_records: list[StepExecutionRecord],
    ) -> tuple[int, bool]:
        """Execute compensating actions in strict reverse topological order."""
        compensated_count = 0
        quarantined = False

        for step, exec_params, forward_out, idem_key in reversed(completed_stack):
            if step.compensate_fn is None:
                continue

            comp_intent = ActionIntent(
                step_name=f"compensate:{step.name}",
                tool_name=step.compensate_tool_name or f"compensate.{step.action.tool_name}",
                resource_type=step.action.resource_type,
                operation="compensate",
                parameters={"original_step": step.name},
                target_domain=step.action.target_domain,
            )
            comp_verdict = self._policy.evaluate(principal, comp_intent, {})
            if comp_verdict.effect != PolicyDecisionEffect.PERMIT:
                quarantined = True
                self._ledger.append(
                    tenant_id=principal.tenant_id,
                    workflow_id=workflow_id,
                    event_type=LedgerEventType.SAGA_COMPENSATION_FAILED,
                    payload={
                        "step_name": step.name,
                        "error": f"Compensation policy blocked: {comp_verdict.reason}",
                    },
                )
                continue

            comp_succeeded = False
            comp_out: dict[str, Any] = {}
            comp_err: str | None = None

            with self._telemetry.span(
                "aegis.saga.step.compensate",
                attributes={"workflow_id": workflow_id, "step": step.name},
            ):
                for attempt in range(1, step.max_retries + 2):
                    try:
                        raw_comp = await asyncio.wait_for(
                            step.compensate_fn(exec_params, forward_out),
                            timeout=step.timeout_seconds,
                        )
                        comp_out = self._vault.tokenize_payload(
                            principal.tenant_id, raw_comp
                        ).sanitized_value
                        comp_succeeded = True
                        break
                    except Exception as exc:
                        comp_err = f"{type(exc).__name__}: {exc}"
                        if attempt <= step.max_retries:
                            await asyncio.sleep(step.retry_backoff_seconds * attempt)

            if comp_succeeded:
                compensated_count += 1
                self._idempotency.clear_for_compensation(principal.tenant_id, idem_key)
                self._ledger.append(
                    tenant_id=principal.tenant_id,
                    workflow_id=workflow_id,
                    event_type=LedgerEventType.SAGA_STEP_COMPENSATED,
                    payload={
                        "step_name": step.name,
                        "compensate_tool": comp_intent.tool_name,
                        "output": comp_out,
                    },
                )
                self._update_step_record(
                    step_records,
                    step_name=step.name,
                    new_status=StepStatus.COMPENSATED,
                    comp_output=comp_out,
                    error=None,
                )
            else:
                quarantined = True
                self._ledger.append(
                    tenant_id=principal.tenant_id,
                    workflow_id=workflow_id,
                    event_type=LedgerEventType.SAGA_COMPENSATION_FAILED,
                    payload={
                        "step_name": step.name,
                        "error": comp_err or "Compensation exhausted retries",
                    },
                )
                self._update_step_record(
                    step_records,
                    step_name=step.name,
                    new_status=StepStatus.COMPENSATION_FAILED,
                    comp_output={},
                    error=comp_err,
                )

        return compensated_count, quarantined

    @staticmethod
    def _update_step_record(
        records: list[StepExecutionRecord],
        *,
        step_name: str,
        new_status: StepStatus,
        comp_output: dict[str, Any],
        error: str | None,
    ) -> None:
        for idx, rec in enumerate(records):
            if rec.step_name == step_name:
                records[idx] = rec.model_copy(
                    update={
                        "status": new_status,
                        "compensation_output": comp_output,
                        "error_message": error or rec.error_message,
                    }
                )
                return

    def _finalize_workflow(
        self,
        *,
        principal: PrincipalContext,
        saga: SagaDefinition,
        status: SagaStatus,
        step_records: list[StepExecutionRecord],
        compensated_steps: int,
        failure_reason: str | None,
        t_start: float,
    ) -> SagaExecutionResult:
        total_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
        self._telemetry.increment_counter(f'aegis_saga_total{{status="{status.value}"}}')

        self._ledger.append(
            tenant_id=principal.tenant_id,
            workflow_id=saga.workflow_id,
            event_type=LedgerEventType.WORKFLOW_COMPLETED,
            payload={
                "status": status.value,
                "compensated_steps": compensated_steps,
                "failure_reason": failure_reason,
                "total_latency_ms": total_ms,
            },
        )
        return SagaExecutionResult(
            workflow_id=saga.workflow_id,
            workflow_name=saga.name,
            tenant_id=principal.tenant_id,
            status=status,
            steps=tuple(step_records),
            total_latency_ms=total_ms,
            compensated_steps=compensated_steps,
            failure_reason=failure_reason,
        )
