"""Formal Policy-as-Code AST compiler, deny-overrides evaluator, and taint tracker."""

from aegis.policy.ast_nodes import ExprNode, PolicyRule, PolicySet, RuleEffect
from aegis.policy.compaction_guard import (
    CompactedSessionBundle,
    CompactionAttributionLedger,
    CompactionAuthVerdict,
    SealedUserSpan,
    canonicalize_tool_schemas,
)
from aegis.policy.credential_broker import (
    ActorCapabilityVerdict,
    EgressAllowRule,
    EgressBrokerResult,
    MultiActorCapabilitySession,
    OpaqueSecretBroker,
    PolicyDiffProposal,
)
from aegis.policy.evaluator import PolicyEngine
from aegis.policy.parser import PolicySyntaxError, compile_policy
from aegis.policy.taint import TaintAnalyzer, TaintViolationError

__all__ = [
    "ActorCapabilityVerdict",
    "CompactedSessionBundle",
    "CompactionAttributionLedger",
    "CompactionAuthVerdict",
    "EgressAllowRule",
    "EgressBrokerResult",
    "ExprNode",
    "MultiActorCapabilitySession",
    "OpaqueSecretBroker",
    "PolicyDiffProposal",
    "PolicyEngine",
    "PolicyRule",
    "PolicySet",
    "PolicySyntaxError",
    "RuleEffect",
    "SealedUserSpan",
    "TaintAnalyzer",
    "TaintViolationError",
    "canonicalize_tool_schemas",
    "compile_policy",
]
