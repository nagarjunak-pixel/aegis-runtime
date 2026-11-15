"""Lexical analyzer for the `.aegis` Policy-as-Code DSL."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class TokenKind(StrEnum):
    IDENT = "IDENT"
    STRING = "STRING"
    NUMBER = "NUMBER"
    LBRACE = "LBRACE"
    RBRACE = "RBRACE"
    LBRACKET = "LBRACKET"
    RBRACKET = "RBRACKET"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    COLON = "COLON"
    COMMA = "COMMA"
    DOT = "DOT"
    EQ = "EQ"
    NEQ = "NEQ"
    LT = "LT"
    LTE = "LTE"
    GT = "GT"
    GTE = "GTE"
    EOF = "EOF"


@dataclass(frozen=True, slots=True)
class Token:
    kind: TokenKind
    lexeme: str
    line: int
    column: int


class LexerError(ValueError):
    """Raised when invalid lexical characters are encountered in a policy file."""


_SINGLE_CHAR_TOKENS: dict[str, TokenKind] = {
    "{": TokenKind.LBRACE,
    "}": TokenKind.RBRACE,
    "[": TokenKind.LBRACKET,
    "]": TokenKind.RBRACKET,
    "(": TokenKind.LPAREN,
    ")": TokenKind.RPAREN,
    ":": TokenKind.COLON,
    ",": TokenKind.COMMA,
    ".": TokenKind.DOT,
}


def tokenize_policy(source: str) -> list[Token]:
    """Convert `.aegis` DSL source text into a deterministic stream of tokens."""
    tokens: list[Token] = []
    idx = 0
    length = len(source)
    line = 1
    col = 1

    while idx < length:
        ch = source[idx]

        if ch in (" ", "\t", "\r"):
            idx += 1
            col += 1
            continue

        if ch == "\n":
            idx += 1
            line += 1
            col = 1
            continue

        if ch == "#":
            while idx < length and source[idx] != "\n":
                idx += 1
            continue

        if ch in _SINGLE_CHAR_TOKENS:
            tokens.append(Token(_SINGLE_CHAR_TOKENS[ch], ch, line, col))
            idx += 1
            col += 1
            continue

        if ch == "=" and idx + 1 < length and source[idx + 1] == "=":
            tokens.append(Token(TokenKind.EQ, "==", line, col))
            idx += 2
            col += 2
            continue

        if ch == "!" and idx + 1 < length and source[idx + 1] == "=":
            tokens.append(Token(TokenKind.NEQ, "!=", line, col))
            idx += 2
            col += 2
            continue

        if ch == "<":
            if idx + 1 < length and source[idx + 1] == "=":
                tokens.append(Token(TokenKind.LTE, "<=", line, col))
                idx += 2
                col += 2
            else:
                tokens.append(Token(TokenKind.LT, "<", line, col))
                idx += 1
                col += 1
            continue

        if ch == ">":
            if idx + 1 < length and source[idx + 1] == "=":
                tokens.append(Token(TokenKind.GTE, ">=", line, col))
                idx += 2
                col += 2
            else:
                tokens.append(Token(TokenKind.GT, ">", line, col))
                idx += 1
                col += 1
            continue

        if ch == '"':
            start_col = col
            idx += 1
            col += 1
            chars: list[str] = []
            while idx < length and source[idx] != '"':
                if source[idx] == "\\":
                    idx += 1
                    col += 1
                    if idx >= length:
                        raise LexerError(f"Unterminated escape sequence at {line}:{start_col}")
                    esc = source[idx]
                    escape_map = {'"': '"', "\\": "\\", "n": "\n", "t": "\t"}
                    chars.append(escape_map.get(esc, esc))
                elif source[idx] == "\n":
                    raise LexerError(f"Unterminated string literal at {line}:{start_col}")
                else:
                    chars.append(source[idx])
                idx += 1
                col += 1
            if idx >= length or source[idx] != '"':
                raise LexerError(f"Unterminated string literal at {line}:{start_col}")
            idx += 1
            col += 1
            tokens.append(Token(TokenKind.STRING, "".join(chars), line, start_col))
            continue

        if ch.isdigit() or (ch == "-" and idx + 1 < length and source[idx + 1].isdigit()):
            start_col = col
            start_idx = idx
            if ch == "-":
                idx += 1
                col += 1
            has_dot = False
            while idx < length and (source[idx].isdigit() or (source[idx] == "." and not has_dot)):
                if source[idx] == ".":
                    has_dot = True
                idx += 1
                col += 1
            tokens.append(Token(TokenKind.NUMBER, source[start_idx:idx], line, start_col))
            continue

        if ch.isalpha() or ch == "_":
            start_col = col
            start_idx = idx
            while idx < length and (source[idx].isalnum() or source[idx] == "_"):
                idx += 1
                col += 1
            ident = source[start_idx:idx]
            if ident.startswith("__"):
                raise LexerError(
                    f"Security violation: dunder identifier '{ident}' forbidden at {line}:{start_col}"
                )
            tokens.append(Token(TokenKind.IDENT, ident, line, start_col))
            continue

        raise LexerError(f"Unexpected character '{ch}' at line {line}, column {col}")

    tokens.append(Token(TokenKind.EOF, "", line, col))
    return tokens
