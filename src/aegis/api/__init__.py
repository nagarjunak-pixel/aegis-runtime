"""FastAPI Control Plane REST, MCP JSON-RPC, and Prometheus telemetry endpoints."""

from aegis.api.app import create_app

__all__ = ["create_app"]
