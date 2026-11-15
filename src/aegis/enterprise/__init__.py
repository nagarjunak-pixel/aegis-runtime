"""SAP S/4HANA-inspired stateful Enterprise ERP subsystems, MCP server, and scenarios."""

from aegis.enterprise.erp_systems import EnterpriseERPSandbox, FaultProfile, InvariantAuditReport
from aegis.enterprise.mcp_server import EnterpriseMCPServer, MCPToolDescriptor
from aegis.enterprise.scenarios import EnterpriseScenarioCatalog, ScenarioDescriptor

__all__ = [
    "EnterpriseERPSandbox",
    "EnterpriseMCPServer",
    "EnterpriseScenarioCatalog",
    "FaultProfile",
    "InvariantAuditReport",
    "MCPToolDescriptor",
    "ScenarioDescriptor",
]
