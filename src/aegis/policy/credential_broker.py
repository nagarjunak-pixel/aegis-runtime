"""Out-of-sandbox credential broker and multi-actor session capability isolation.

Implements two zero-trust runtime controls for tool-calling enterprise agents:
1. Out-of-Sandbox Credential Broker (OpenShell supervisor pattern): Sandboxed agents
   never hold raw API keys or bearer credentials in process memory or environment
   variables. Instead, agents receive HMAC-authenticated opaque handles
   (`sec_ref://<alias>:<tag>`). An external egress supervisor enforces default-deny
   network policy, blocks raw/encoded secret exfiltration across URLs, headers, and
   bodies, swaps real credentials only on allowlisted `(actor, host, method, path)`
   routes, and converts denied egress attempts into auditable `PolicyDiffProposal`
   records without container restarts.
2. Multi-Actor Capability Isolation (arXiv:2611.34920, mu-Bench): Prevents cross-speaker
   authority bleed in shared multi-user threads by binding tool authorization to the
   invoking speaker's capability set (or the intersection `speaker & delegator` under
   explicit delegation).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import urllib.parse
from dataclasses import dataclass
from typing import Final

_SEC_REF_RE: Final[re.Pattern[str]] = re.compile(r"sec_ref://([a-zA-Z0-9_-]+):([0-9a-f]{16})")


@dataclass(frozen=True)
class EgressAllowRule:
    """Allowlist rule binding an actor, HTTPS host, HTTP method, and path prefix."""

    actor_id: str
    host: str
    method: str
    path_prefix: str = "/"

    def matches(self, actor_id: str, host: str, method: str, path: str) -> bool:
        actor_ok = self.actor_id in ("*", actor_id)
        host_ok = self.host.lower() == host.lower()
        method_ok = self.method.upper() in ("*", method.upper())
        norm_path = path if path.startswith("/") else f"/{path}"
        prefix_ok = norm_path.startswith(self.path_prefix)
        return actor_ok and host_ok and method_ok and prefix_ok


@dataclass(frozen=True)
class PolicyDiffProposal:
    """Auditable egress policy diff emitted when default-deny blocks an unapproved route."""

    actor_id: str
    host: str
    method: str
    path_prefix: str
    secret_alias: str | None
    reason: str
    proposal_sha256: str


@dataclass(frozen=True)
class EgressBrokerResult:
    """Outcome of external egress inspection and opaque credential substitution."""

    allowed: bool
    reason: str
    exfiltration_detected: bool
    resolved_headers: dict[str, str]
    resolved_body: str
    swapped_aliases: tuple[str, ...]
    policy_diff_proposal: PolicyDiffProposal | None


@dataclass(frozen=True)
class _VaultEntry:
    alias: str
    raw_secret: bytes
    handle: str
    allowed_egress: tuple[EgressAllowRule, ...]


class OpaqueSecretBroker:
    """External supervisor vault swapping opaque `sec_ref://` tokens at egress time."""

    def __init__(self, broker_key: bytes, require_https: bool = True) -> None:
        if len(broker_key) < 16:
            raise ValueError("broker_key must be at least 16 bytes")
        self._key = bytes(broker_key)
        self._require_https = require_https
        self._vault: dict[str, _VaultEntry] = {}
        self._route_allowlist: list[EgressAllowRule] = []
        self._proposals: list[PolicyDiffProposal] = []

    def add_egress_rule(self, rule: EgressAllowRule) -> None:
        """Allow outbound network requests matching `rule` even when no secret is swapped."""
        self._route_allowlist.append(rule)

    def _compute_tag(self, alias: str) -> str:
        return hmac.new(self._key, alias.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def register_secret(
        self,
        alias: str,
        raw_secret: str,
        allowed_egress: tuple[EgressAllowRule, ...],
    ) -> str:
        """Store `raw_secret` outside the sandbox and return its opaque `sec_ref://` handle."""
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", alias):
            raise ValueError(f"Invalid secret alias: {alias!r}")
        if len(raw_secret) < 8:
            raise ValueError("raw_secret must be at least 8 characters")
        tag = self._compute_tag(alias)
        handle = f"sec_ref://{alias}:{tag}"
        self._vault[alias] = _VaultEntry(
            alias=alias,
            raw_secret=raw_secret.encode("utf-8"),
            handle=handle,
            allowed_egress=allowed_egress,
        )
        return handle

    def agent_environment_view(self) -> dict[str, str]:
        """Return environment variables safe to inject into the sandboxed agent container."""
        return {
            f"AEGIS_SECRET_{alias.upper().replace('-', '_')}": entry.handle
            for alias, entry in sorted(self._vault.items())
        }

    @property
    def proposals(self) -> tuple[PolicyDiffProposal, ...]:
        """Return immutable history of denied-egress policy diff proposals."""
        return tuple(self._proposals)

    def _contains_exfiltrated_secret(self, payload: str) -> str | None:
        lowered = payload.lower()
        unquoted = urllib.parse.unquote(payload)
        for alias, entry in self._vault.items():
            secret_str = entry.raw_secret.decode("utf-8")
            b64_str = base64.b64encode(entry.raw_secret).decode("ascii").rstrip("=")
            urlsafe_b64 = base64.urlsafe_b64encode(entry.raw_secret).decode("ascii").rstrip("=")
            hex_str = entry.raw_secret.hex().lower()
            if (
                secret_str in payload
                or secret_str in unquoted
                or b64_str in payload
                or urlsafe_b64 in payload
                or hex_str in lowered
            ):
                return alias
        return None

    def _emit_proposal(
        self,
        actor_id: str,
        host: str,
        method: str,
        path: str,
        secret_alias: str | None,
        reason: str,
    ) -> PolicyDiffProposal:
        segments = [seg for seg in path.split("/") if seg]
        prefix = f"/{segments[0]}" if segments else "/"
        canonical = f"{actor_id}|{host.lower()}|{method.upper()}|{prefix}|{secret_alias or ''}"
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        proposal = PolicyDiffProposal(
            actor_id=actor_id,
            host=host.lower(),
            method=method.upper(),
            path_prefix=prefix,
            secret_alias=secret_alias,
            reason=reason,
            proposal_sha256=digest,
        )
        self._proposals.append(proposal)
        return proposal

    def inspect_and_swap_egress(
        self,
        actor_id: str,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str = "",
    ) -> EgressBrokerResult:
        """Enforce default-deny egress, block secret leaks, and swap authorized handles."""
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        full_path = f"{path}?{parsed.query}" if parsed.query else path

        if not host or (self._require_https and scheme != "https"):
            prop = self._emit_proposal(
                actor_id,
                host or "invalid-host",
                method,
                path,
                None,
                "non_https_or_missing_host_blocked",
            )
            return EgressBrokerResult(
                allowed=False,
                reason="non_https_or_missing_host_blocked",
                exfiltration_detected=False,
                resolved_headers={},
                resolved_body="",
                swapped_aliases=(),
                policy_diff_proposal=prop,
            )

        combined_wire = "\n".join(
            [full_path, *(f"{k}: {v}" for k, v in sorted(headers.items())), body]
        )
        leaked_alias = self._contains_exfiltrated_secret(combined_wire)
        if leaked_alias is not None:
            return EgressBrokerResult(
                allowed=False,
                reason=f"raw_or_encoded_secret_exfiltration_blocked:{leaked_alias}",
                exfiltration_detected=True,
                resolved_headers={},
                resolved_body="",
                swapped_aliases=(),
                policy_diff_proposal=None,
            )

        referenced = _SEC_REF_RE.findall(combined_wire)
        if not referenced:
            route_ok = any(
                rule.matches(actor_id, host, method, path) for rule in self._route_allowlist
            )
            if not route_ok:
                prop = self._emit_proposal(
                    actor_id, host, method, path, None, "default_deny_unlisted_egress_host"
                )
                return EgressBrokerResult(
                    allowed=False,
                    reason="default_deny_unlisted_egress_host",
                    exfiltration_detected=False,
                    resolved_headers={},
                    resolved_body="",
                    swapped_aliases=(),
                    policy_diff_proposal=prop,
                )
            return EgressBrokerResult(
                allowed=True,
                reason="allowlisted_egress_no_secret_swap",
                exfiltration_detected=False,
                resolved_headers=dict(headers),
                resolved_body=body,
                swapped_aliases=(),
                policy_diff_proposal=None,
            )

        swapped: list[str] = []
        replacements: dict[str, str] = {}
        for alias, tag in referenced:
            entry = self._vault.get(alias)
            expected_tag = self._compute_tag(alias)
            if entry is None or not hmac.compare_digest(tag, expected_tag):
                return EgressBrokerResult(
                    allowed=False,
                    reason=f"forged_or_unknown_secret_handle:{alias}",
                    exfiltration_detected=False,
                    resolved_headers={},
                    resolved_body="",
                    swapped_aliases=(),
                    policy_diff_proposal=None,
                )
            if not any(rule.matches(actor_id, host, method, path) for rule in entry.allowed_egress):
                prop = self._emit_proposal(
                    actor_id,
                    host,
                    method,
                    path,
                    alias,
                    f"secret_scope_denied_for_route:{alias}",
                )
                return EgressBrokerResult(
                    allowed=False,
                    reason=f"secret_scope_denied_for_route:{alias}",
                    exfiltration_detected=False,
                    resolved_headers={},
                    resolved_body="",
                    swapped_aliases=(),
                    policy_diff_proposal=prop,
                )
            replacements[entry.handle] = entry.raw_secret.decode("utf-8")
            if alias not in swapped:
                swapped.append(alias)

        if _SEC_REF_RE.search(full_path):
            return EgressBrokerResult(
                allowed=False,
                reason="secret_handle_disallowed_in_url_path_or_query",
                exfiltration_detected=False,
                resolved_headers={},
                resolved_body="",
                swapped_aliases=(),
                policy_diff_proposal=None,
            )

        out_headers: dict[str, str] = {}
        for h_key, h_val in headers.items():
            updated = h_val
            for handle, secret_text in replacements.items():
                updated = updated.replace(handle, secret_text)
            out_headers[h_key] = updated

        out_body = body
        for handle, secret_text in replacements.items():
            out_body = out_body.replace(handle, secret_text)

        return EgressBrokerResult(
            allowed=True,
            reason="opaque_secret_swapped_at_egress",
            exfiltration_detected=False,
            resolved_headers=out_headers,
            resolved_body=out_body,
            swapped_aliases=tuple(swapped),
            policy_diff_proposal=None,
        )


@dataclass(frozen=True)
class ActorCapabilityVerdict:
    """Decision for a tool invocation inside a shared multi-participant session."""

    allowed: bool
    actor_id: str
    tool_name: str
    effective_capabilities: frozenset[str]
    reason: str


class MultiActorCapabilitySession:
    """Isolates per-speaker tool capabilities in shared multi-user conversations."""

    def __init__(self) -> None:
        self._actor_caps: dict[str, frozenset[str]] = {}
        self._explicit_delegations: set[tuple[str, str, str]] = set()

    def register_actor(self, actor_id: str, capabilities: set[str] | frozenset[str]) -> None:
        """Bind `actor_id` to an explicit capability set."""
        if not actor_id:
            raise ValueError("actor_id must be non-empty")
        self._actor_caps[actor_id] = frozenset(capabilities)

    def grant_scoped_delegation(self, delegator_id: str, delegate_id: str, tool_name: str) -> None:
        """Grant `delegate_id` a single-tool delegation bounded by `delegator_id`'s own scope."""
        delegator_scope = self._actor_caps.get(delegator_id, frozenset())
        if tool_name not in delegator_scope:
            raise PermissionError(
                f"Delegator {delegator_id!r} cannot delegate unowned capability {tool_name!r}"
            )
        self._explicit_delegations.add((delegator_id, delegate_id, tool_name))

    def authorize_tool_call(
        self,
        invoking_actor_id: str,
        tool_name: str,
        claimed_delegator_id: str | None = None,
    ) -> ActorCapabilityVerdict:
        """Verify `invoking_actor_id` holds `tool_name` without cross-speaker authority bleed."""
        if invoking_actor_id not in self._actor_caps:
            return ActorCapabilityVerdict(
                allowed=False,
                actor_id=invoking_actor_id,
                tool_name=tool_name,
                effective_capabilities=frozenset(),
                reason="unregistered_actor",
            )
        own_caps = self._actor_caps[invoking_actor_id]
        if tool_name in own_caps:
            return ActorCapabilityVerdict(
                allowed=True,
                actor_id=invoking_actor_id,
                tool_name=tool_name,
                effective_capabilities=own_caps,
                reason="authorized_by_own_capability",
            )
        if claimed_delegator_id is not None:
            delegator_caps = self._actor_caps.get(claimed_delegator_id, frozenset())
            if (
                tool_name in delegator_caps
                and (claimed_delegator_id, invoking_actor_id, tool_name)
                in self._explicit_delegations
            ):
                effective = own_caps | frozenset({tool_name})
                return ActorCapabilityVerdict(
                    allowed=True,
                    actor_id=invoking_actor_id,
                    tool_name=tool_name,
                    effective_capabilities=effective,
                    reason=f"authorized_by_explicit_delegation:{claimed_delegator_id}",
                )
            return ActorCapabilityVerdict(
                allowed=False,
                actor_id=invoking_actor_id,
                tool_name=tool_name,
                effective_capabilities=own_caps,
                reason="cross_speaker_authority_bleed_blocked",
            )
        return ActorCapabilityVerdict(
            allowed=False,
            actor_id=invoking_actor_id,
            tool_name=tool_name,
            effective_capabilities=own_caps,
            reason="capability_not_granted_to_actor",
        )
