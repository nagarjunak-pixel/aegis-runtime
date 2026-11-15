"""Recursive-descent compiler from `.aegis` policy source into immutable ASTs."""

from __future__ import annotations

import hashlib

from aegis.policy.ast_nodes import (
    AttributePathNode,
    BinaryOperator,
    BinaryOpNode,
    ExprNode,
    ListLiteralNode,
    LiteralNode,
    PolicyRule,
    PolicySet,
    RuleEffect,
    UnaryOperator,
    UnaryOpNode,
)
from aegis.policy.lexer import LexerError, Token, TokenKind, tokenize_policy

_ALLOWED_ROOT_NAMESPACES = frozenset({"principal", "action", "context"})


class PolicySyntaxError(ValueError):
    """Raised when a `.aegis` policy violates grammar or namespace constraints."""


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        if tok.kind != TokenKind.EOF:
            self._pos += 1
        return tok

    def _expect(self, kind: TokenKind, lexeme: str | None = None) -> Token:
        tok = self._peek()
        if tok.kind != kind or (lexeme is not None and tok.lexeme != lexeme):
            expected = f"{kind.value}('{lexeme}')" if lexeme else kind.value
            raise PolicySyntaxError(
                f"Expected {expected} at {tok.line}:{tok.column}, got {tok.kind.value}('{tok.lexeme}')"
            )
        return self._advance()

    def parse_policy_set(self, source_hash: str) -> PolicySet:
        rules: list[PolicyRule] = []
        seen_ids: set[str] = set()
        while self._peek().kind != TokenKind.EOF:
            rule = self._parse_rule()
            if rule.rule_id in seen_ids:
                raise PolicySyntaxError(f"Duplicate policy rule identifier '{rule.rule_id}'")
            seen_ids.add(rule.rule_id)
            rules.append(rule)
        return PolicySet(rules=tuple(rules), source_hash=source_hash)

    def _parse_rule(self) -> PolicyRule:
        self._expect(TokenKind.IDENT, "rule")
        rule_id_tok = self._expect(TokenKind.STRING)
        self._expect(TokenKind.LBRACE)

        effect: RuleEffect | None = None
        description = ""
        condition: ExprNode | None = None

        while self._peek().kind != TokenKind.RBRACE:
            field_tok = self._expect(TokenKind.IDENT)
            self._expect(TokenKind.COLON)
            if field_tok.lexeme == "effect":
                eff_tok = self._expect(TokenKind.IDENT)
                if eff_tok.lexeme not in ("permit", "forbid"):
                    raise PolicySyntaxError(
                        f"Rule effect must be 'permit' or 'forbid' at {eff_tok.line}:{eff_tok.column}"
                    )
                effect = RuleEffect(eff_tok.lexeme)
            elif field_tok.lexeme == "description":
                description = self._expect(TokenKind.STRING).lexeme
            elif field_tok.lexeme == "when":
                condition = self._parse_or()
            else:
                raise PolicySyntaxError(
                    f"Unknown rule attribute '{field_tok.lexeme}' at {field_tok.line}:{field_tok.column}"
                )

        self._expect(TokenKind.RBRACE)
        if effect is None or condition is None:
            raise PolicySyntaxError(
                f"Rule '{rule_id_tok.lexeme}' must specify both 'effect:' and 'when:' clauses"
            )
        return PolicyRule(
            rule_id=rule_id_tok.lexeme,
            effect=effect,
            description=description or rule_id_tok.lexeme,
            condition=condition,
        )

    def _parse_or(self) -> ExprNode:
        left = self._parse_and()
        while self._peek().kind == TokenKind.IDENT and self._peek().lexeme == "or":
            self._advance()
            right = self._parse_and()
            left = BinaryOpNode(op=BinaryOperator.OR, left=left, right=right)
        return left

    def _parse_and(self) -> ExprNode:
        left = self._parse_unary()
        while self._peek().kind == TokenKind.IDENT and self._peek().lexeme == "and":
            self._advance()
            right = self._parse_unary()
            left = BinaryOpNode(op=BinaryOperator.AND, left=left, right=right)
        return left

    def _parse_unary(self) -> ExprNode:
        if self._peek().kind == TokenKind.IDENT and self._peek().lexeme == "not":
            # Distinguish unary `not <expr>` from infix `<lhs> not in <rhs>` (handled in comparison)
            self._advance()
            operand = self._parse_unary()
            return UnaryOpNode(op=UnaryOperator.NOT, operand=operand)
        return self._parse_comparison()

    def _parse_comparison(self) -> ExprNode:
        left = self._parse_primary()
        tok = self._peek()

        op_map: dict[TokenKind, BinaryOperator] = {
            TokenKind.EQ: BinaryOperator.EQ,
            TokenKind.NEQ: BinaryOperator.NEQ,
            TokenKind.LT: BinaryOperator.LT,
            TokenKind.LTE: BinaryOperator.LTE,
            TokenKind.GT: BinaryOperator.GT,
            TokenKind.GTE: BinaryOperator.GTE,
        }

        if tok.kind in op_map:
            self._advance()
            right = self._parse_primary()
            return BinaryOpNode(op=op_map[tok.kind], left=left, right=right)

        if tok.kind == TokenKind.IDENT and tok.lexeme == "in":
            self._advance()
            right = self._parse_primary()
            return BinaryOpNode(op=BinaryOperator.IN, left=left, right=right)

        if tok.kind == TokenKind.IDENT and tok.lexeme == "contains":
            self._advance()
            right = self._parse_primary()
            return BinaryOpNode(op=BinaryOperator.CONTAINS, left=left, right=right)

        if tok.kind == TokenKind.IDENT and tok.lexeme == "not":
            next_tok = self._tokens[self._pos + 1] if self._pos + 1 < len(self._tokens) else tok
            if next_tok.kind == TokenKind.IDENT and next_tok.lexeme == "in":
                self._advance()
                self._advance()
                right = self._parse_primary()
                return BinaryOpNode(op=BinaryOperator.NOT_IN, left=left, right=right)

        return left

    def _parse_primary(self) -> ExprNode:
        tok = self._peek()

        if tok.kind == TokenKind.LPAREN:
            self._advance()
            expr = self._parse_or()
            self._expect(TokenKind.RPAREN)
            return expr

        if tok.kind == TokenKind.LBRACKET:
            self._advance()
            elements: list[ExprNode] = []
            if self._peek().kind != TokenKind.RBRACKET:
                elements.append(self._parse_or())
                while self._peek().kind == TokenKind.COMMA:
                    self._advance()
                    elements.append(self._parse_or())
            self._expect(TokenKind.RBRACKET)
            return ListLiteralNode(elements=tuple(elements))

        if tok.kind == TokenKind.STRING:
            self._advance()
            return LiteralNode(value=tok.lexeme)

        if tok.kind == TokenKind.NUMBER:
            self._advance()
            if "." in tok.lexeme:
                return LiteralNode(value=float(tok.lexeme))
            return LiteralNode(value=int(tok.lexeme))

        if tok.kind == TokenKind.IDENT:
            if tok.lexeme == "true":
                self._advance()
                return LiteralNode(value=True)
            if tok.lexeme == "false":
                self._advance()
                return LiteralNode(value=False)
            if tok.lexeme == "null":
                self._advance()
                return LiteralNode(value=None)

            parts = [self._advance().lexeme]
            if parts[0] not in _ALLOWED_ROOT_NAMESPACES:
                raise PolicySyntaxError(
                    f"Unknown attribute root '{parts[0]}' at {tok.line}:{tok.column}; "
                    f"allowed roots: {sorted(_ALLOWED_ROOT_NAMESPACES)}"
                )
            while self._peek().kind == TokenKind.DOT:
                self._advance()
                attr_tok = self._expect(TokenKind.IDENT)
                parts.append(attr_tok.lexeme)
            return AttributePathNode(parts=tuple(parts))

        raise PolicySyntaxError(
            f"Unexpected token {tok.kind.value}('{tok.lexeme}') at {tok.line}:{tok.column}"
        )


def compile_policy(source: str) -> PolicySet:
    """Compile `.aegis` policy source into a verified, immutable `PolicySet` AST."""
    try:
        tokens = tokenize_policy(source)
    except LexerError as exc:
        raise PolicySyntaxError(str(exc)) from exc
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    parser = _Parser(tokens)
    return parser.parse_policy_set(source_hash=source_hash)
