"""Information-flow taint propagation & indirect prompt-injection containment gate."""

from __future__ import annotations

import re
from typing import Any

from aegis.types import ActionIntent, TaintLabel

_INJECTION_SIGNATURES: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|system)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*override\s*:", re.IGNORECASE),
    re.compile(r"<\s*/?\s*system_prompt\s*>", re.IGNORECASE),
    re.compile(r"transfer\s+to\s+iban\s+[a-z]{2}\d{2}", re.IGNORECASE),
    re.compile(r"exfiltrate|webhook\.site|ngrok-free\.app|requestbin", re.IGNORECASE),
)

_HIGH_INTEGRITY_SINKS: frozenset[str] = frozenset(
    {
        "treasury.execute_wire",
        "vendor.update_bank_iban",
        "erp.override_credit_limit",
        "iam.grant_role",
        "erp.approve_purchase_order",
    }
)


class TaintViolationError(PermissionError):
    """Raised when untrusted or sensitive taint crosses a forbidden security boundary."""


class TaintAnalyzer:
    """Enforces information-flow lattice invariants against Lethal Trifecta attacks."""

    def derive_taint_from_inputs(
        self,
        *,
        external_documents: list[str] | None = None,
        contains_pii: bool = False,
        base_labels: tuple[TaintLabel, ...] = (TaintLabel.AUTHENTICATED_USER,),
    ) -> tuple[TaintLabel, ...]:
        """Compute the lattice join (union) of taint labels across workflow inputs."""
        labels: set[TaintLabel] = set(base_labels)
        if external_documents:
            labels.add(TaintLabel.UNTRUSTED_EXTERNAL)
        if contains_pii:
            labels.add(TaintLabel.PII_SENSITIVE)
        return tuple(sorted(labels, key=lambda x: x.value))

    def scan_text_for_injection(self, text: str) -> list[str]:
        """Return matched adversarial prompt-injection pattern names for telemetry/audit."""
        matches: list[str] = []
        for pattern in _INJECTION_SIGNATURES:
            if pattern.search(text):
                matches.append(pattern.pattern)
        return matches

    def check_action_integrity(self, action: ActionIntent) -> str | None:
        """Verify information-flow lattice invariants before policy AST evaluation.

        Invariants enforced:
        1. Integrity Invariant (Biba-inspired): `UNTRUSTED_EXTERNAL` taint cannot drive
           high-integrity financial/IAM mutations without sanitization/human re-origination.
        2. Confidentiality Invariant (Bell-LaPadula-inspired): `PII_SENSITIVE` or
           `SECRET_CREDENTIAL` taint cannot egress to non-internal target domains.
        3. Parameter Payload Scan: Tool arguments must not carry embedded exfiltration domains
           or shell/SQL/command injection payloads.
        """
        taints = set(action.taint_labels)

        if TaintLabel.UNTRUSTED_EXTERNAL in taints and (
            action.tool_name in _HIGH_INTEGRITY_SINKS or action.operation in ("transfer", "approve")
        ):
            return (
                f"Biba Integrity Violation: tool '{action.tool_name}' (op='{action.operation}') "
                f"rejected because context carries UNTRUSTED_EXTERNAL taint"
            )

        if (
            TaintLabel.PII_SENSITIVE in taints or TaintLabel.SECRET_CREDENTIAL in taints
        ) and not action.target_domain.endswith(".erp"):
            return (
                f"Bell-LaPadula Confidentiality Violation: sensitive taint {sorted(t.value for t in taints)} "
                f"cannot egress to external domain '{action.target_domain}'"
            )

        serialized_args = _flatten_strings(action.parameters)
        for text_val in serialized_args:
            hits = self.scan_text_for_injection(text_val)
            if hits:
                return (
                    f"Adversarial Payload Blocked in '{action.tool_name}' parameters: "
                    f"matched signature '{hits[0]}'"
                )
            if ("https://" in text_val or "http://" in text_val) and not any(
                allowed in text_val for allowed in ("internal.erp", "corp.local", "localhost")
            ):
                return (
                    f"Unauthorized External Egress URL detected in '{action.tool_name}' "
                    f"parameters: '{text_val[:80]}'"
                )

        return None


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values():
            out.extend(_flatten_strings(v))
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            out.extend(_flatten_strings(item))
        return out
    return []
