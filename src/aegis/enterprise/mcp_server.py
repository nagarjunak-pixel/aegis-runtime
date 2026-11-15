"""JSON-RPC 2.0 Model Context Protocol (MCP) server wrapping Enterprise ERP tools."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.enterprise.erp_systems import EnterpriseERPSandbox


class MCPToolDescriptor(BaseModel):
    """MCP specification for an enterprise tool and its compensating inverse."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    resource_type: str
    compensating_tool: str | None
    input_schema: dict[str, Any]


class EnterpriseMCPServer:
    """Standards-compliant JSON-RPC 2.0 MCP server for SAP/ERP & Treasury operations."""

    PROTOCOL_VERSION = "2025-06-18"

    def __init__(self, erp: EnterpriseERPSandbox) -> None:
        self._erp = erp
        self._descriptors: tuple[MCPToolDescriptor, ...] = (
            MCPToolDescriptor(
                name="inventory.reserve_atp",
                description="Reserve Available-to-Promise (ATP) stock in SAP plant warehouse",
                resource_type="inventory_lot",
                compensating_tool="compensate.inventory.release_atp",
                input_schema={
                    "type": "object",
                    "required": ["plant", "sku", "quantity"],
                    "properties": {
                        "plant": {"type": "string"},
                        "sku": {"type": "string"},
                        "quantity": {"type": "integer", "minimum": 1},
                    },
                },
            ),
            MCPToolDescriptor(
                name="erp.create_purchase_order",
                description="Create encumbered SAP Purchase Order against a cost-center budget",
                resource_type="purchase_order",
                compensating_tool="compensate.erp.cancel_purchase_order",
                input_schema={
                    "type": "object",
                    "required": ["vendor_id", "amount_usd", "cost_center"],
                    "properties": {
                        "vendor_id": {"type": "string"},
                        "amount_usd": {"type": "number", "exclusiveMinimum": 0},
                        "cost_center": {"type": "string"},
                    },
                },
            ),
            MCPToolDescriptor(
                name="treasury.lock_fx_hedge",
                description="Lock FX forward rate contract for cross-border procurement",
                resource_type="fx_hedge",
                compensating_tool="compensate.treasury.unwind_fx_hedge",
                input_schema={
                    "type": "object",
                    "required": ["currency_pair", "notional_usd"],
                    "properties": {
                        "currency_pair": {"type": "string"},
                        "notional_usd": {"type": "number", "exclusiveMinimum": 0},
                    },
                },
            ),
            MCPToolDescriptor(
                name="logistics.book_expedited_lane",
                description="Book priority air-freight slot on global logistics corridor",
                resource_type="logistics_shipment",
                compensating_tool="compensate.logistics.cancel_lane_booking",
                input_schema={
                    "type": "object",
                    "required": ["lane_id", "slots"],
                    "properties": {
                        "lane_id": {"type": "string"},
                        "slots": {"type": "integer", "minimum": 1},
                    },
                },
            ),
            MCPToolDescriptor(
                name="treasury.execute_wire",
                description="Settle encumbered SAP Purchase Order via SWIFT/SEPA wire transfer",
                resource_type="wire_transfer",
                compensating_tool="compensate.treasury.reverse_wire",
                input_schema={
                    "type": "object",
                    "required": ["beneficiary_iban"],
                    "properties": {
                        "po_id": {"type": "string"},
                        "po_step_ref": {"type": "string"},
                        "beneficiary_iban": {"type": "string"},
                    },
                },
            ),
            MCPToolDescriptor(
                name="vendor.update_bank_iban",
                description="Mutate vendor settlement IBAN in SAP master data (restricted)",
                resource_type="vendor_master",
                compensating_tool=None,
                input_schema={
                    "type": "object",
                    "required": ["vendor_id", "new_iban"],
                    "properties": {
                        "vendor_id": {"type": "string"},
                        "new_iban": {"type": "string"},
                    },
                },
            ),
        )

    def list_tools(self) -> list[MCPToolDescriptor]:
        return list(self._descriptors)

    async def handle_jsonrpc(self, request: dict[str, Any]) -> dict[str, Any]:
        """Process a JSON-RPC 2.0 MCP message (`initialize`, `tools/list`, `tools/call`)."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}

        if request.get("jsonrpc") != "2.0":
            return self._error(req_id, -32600, "Invalid JSON-RPC version; expected '2.0'")

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "serverInfo": {"name": "aegis-enterprise-erp-mcp", "version": "0.4.0"},
                    "capabilities": {"tools": {"listChanged": False}},
                },
            }

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": d.name,
                            "description": d.description,
                            "inputSchema": d.input_schema,
                            "x-aegis-resourceType": d.resource_type,
                            "x-aegis-compensatingTool": d.compensating_tool,
                        }
                        for d in self._descriptors
                    ]
                },
            }

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            arguments = dict(params.get("arguments") or {})
            prior = dict(params.get("prior_outputs") or {})
            dispatch = {
                "inventory.reserve_atp": self._erp.reserve_atp,
                "erp.create_purchase_order": self._erp.create_purchase_order,
                "treasury.lock_fx_hedge": self._erp.lock_fx_hedge,
                "logistics.book_expedited_lane": self._erp.book_expedited_lane,
                "treasury.execute_wire": self._erp.execute_wire,
                "vendor.update_bank_iban": self._erp.update_vendor_iban,
            }
            fn = dispatch.get(tool_name)
            if fn is None:
                return self._error(req_id, -32601, f"Unknown MCP tool '{tool_name}'")
            try:
                out = await fn(arguments, prior)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "json", "data": out}], "isError": False},
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                        "isError": True,
                    },
                }

        return self._error(req_id, -32601, f"Unsupported MCP method '{method}'")

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }
