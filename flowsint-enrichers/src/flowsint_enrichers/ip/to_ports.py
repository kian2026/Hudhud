import os
from typing import Any, Dict, List, Optional, Union
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_types.ip import Ip
from flowsint_types.port import Port
from flowsint_core.utils import is_valid_ip
from flowsint_core.core.logger import Logger
from tools.network.naabu import NaabuTool


@flowsint_enricher
class IpToPortsEnricher(Enricher):
    """[NAABU] Performs port scanning on IP addresses to discover open ports and services."""

    # Define types as class attributes
    InputType = Ip
    OutputType = Port

    def __init__(
        self,
        sketch_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        vault=None,
        params: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            sketch_id=sketch_id,
            scan_id=scan_id,
            params_schema=self.get_params_schema(),
            vault=vault,
            params=params,
        )

    @classmethod
    def required_params(cls) -> bool:
        return False

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        """Declare parameters for this enricher"""
        return [
            {
                "name": "mode",
                "type": "select",
                "description": "Scan mode: passive (Shodan, stealthy), active (direct scan, exposes your IP), or smart (passive first, fallback to active if no results)",
                "required": True,
                "default": "active",
                "options": [
                    {"label": "Active - Direct Scan (Exposes IP)", "value": "active"},
                    {"label": "Smart - Passive then Active", "value": "smart"},
                    {"label": "Passive - Shodan (Stealthy)", "value": "passive"},
                ],
            },
            {
                "name": "port_range",
                "type": "string",
                "description": "Port range to scan (e.g., '80,443,8080' or '1-1000'). Leave empty for default.",
                "required": False,
            },
            {
                "name": "top_ports",
                "type": "string",
                "description": "Scan top N ports (e.g., '100', '1000'). Overrides port_range if set.",
                "required": False,
                "default": "100",
            },
            {
                "name": "rate",
                "type": "number",
                "description": "Packets per second rate limit (for active scans). Default: 1000",
                "required": False,
            },
            {
                "name": "timeout",
                "type": "number",
                "description": "Timeout in milliseconds. Default: 1000",
                "required": False,
            },
            {
                "name": "service_detection",
                "type": "select",
                "description": "Enable service/version detection",
                "required": False,
                "default": "false",
                "options": [
                    {"label": "Enabled", "value": "true"},
                    {"label": "Disabled", "value": "false"},
                ],
            },
            {
                "name": "PDCP_API_KEY",
                "type": "vaultSecret",
                "description": "ProjectDiscovery Cloud Platform API key (required for passive mode)",
                "required": False,
            },
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_ports"

    @classmethod
    def category(cls) -> str:
        return "Ip"

    @classmethod
    def key(cls) -> str:
        return "address"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        results: List[OutputType] = []
        naabu = NaabuTool()

        # Get parameters from enricher config
        mode = self.params.get("mode", "active")
        port_range = self.params.get("port_range")
        top_ports = self.params.get("top_ports")
        rate = self.params.get("rate")
        timeout = self.params.get("timeout")
        service_detection = self.params.get("service_detection", "false") == "true"
        api_key = self.get_secret("PDCP_API_KEY", os.getenv("PDCP_API_KEY"))

        # Note: naabu passive mode uses Shodan InternetDB (free, no key needed, stealthy)
        # Active mode sends packets directly to the target - your IP will be visible in their logs

        for ip in data:
            try:
                # Determine effective scan mode
                effective_mode = mode
                if mode == "smart":
                    effective_mode = "passive"

                Logger.info(
                    self.sketch_id,
                    {
                        "message": f"[NAABU] Scanning {ip.address} in {effective_mode} mode..."
                    },
                )

                # Launch naabu scan
                scan_results = naabu.launch(
                    target=ip.address,
                    mode=effective_mode,
                    port_range=port_range,
                    top_ports=top_ports,
                    rate=rate,
                    timeout=timeout,
                    service_detection=service_detection,
                    api_key=api_key,
                )

                # Smart mode: fallback to active if passive returned no results
                if mode == "smart" and not scan_results:
                    Logger.warn(
                        self.sketch_id,
                        {
                            "message": f"[NAABU] Passive scan returned no data for {ip.address} (not in Shodan). Falling back to active scan. Note: your IP will be visible to the target."
                        },
                    )
                    scan_results = naabu.launch(
                        target=ip.address,
                        mode="active",
                        port_range=port_range,
                        top_ports=top_ports,
                        rate=rate,
                        timeout=timeout,
                        service_detection=service_detection,
                        api_key=api_key,
                    )

                # Parse results and create Port objects
                for result in scan_results:
                    port_number = result.get("port")
                    if not port_number:
                        continue

                    port = Port(
                        number=port_number,
                        protocol=result.get("protocol", "tcp").upper(),
                        state="open",  # Naabu only returns open ports
                        service=result.get("service"),
                        banner=result.get("version") or result.get("banner"),
                    )

                    # Store the IP address with this port for postprocess
                    setattr(port, "_ip_address", ip.address)

                    results.append(port)

                    Logger.info(
                        self.sketch_id,
                        {
                            "message": f"[NAABU] Found open port {port.number}/{port.protocol} on {ip.address}"
                            + (f" ({port.service})" if port.service else "")
                        },
                    )

            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[NAABU] Error scanning {ip.address}: {e}"},
                )
                continue

        return results

    def postprocess(
        self, results: List[OutputType], input_data: List[InputType] = None
    ) -> List[OutputType]:
        """Create Neo4j nodes for ports and relationships with IP addresses"""
        if self._graph_service and results:
            for port in results:
                # Get the IP address this port belongs to
                ip_address = getattr(port, "_ip_address", None)
                if not ip_address:
                    continue
                
                port_id = f"{ip_address}:{port.number}"
                self.create_node(port)

                # Create relationship from IP to Port
                ip_obj = Ip(address=ip_address)
                self.create_relationship(ip_obj, port, "HAS_PORT")

                service_info = f" ({port.service})" if port.service else ""
                self.log_graph_message(
                    f"Port {port.number}/{port.protocol}{service_info} found on {ip_address}"
                )

                # Clean up temporary attribute
                delattr(port, "_ip_address")

        return results


# Make types available at module level for easy access
InputType = IpToPortsEnricher.InputType
OutputType = IpToPortsEnricher.OutputType
