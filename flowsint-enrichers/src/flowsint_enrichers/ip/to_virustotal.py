import os
from typing import Any, Dict, List, Optional
import requests
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.ip import Ip
from dotenv import load_dotenv

load_dotenv()


@flowsint_enricher
class IpToVirusTotalEnricher(Enricher):
    """[VIRUSTOTAL] Analyze an IP address for malicious activity, associated URLs, and threat intelligence."""

    InputType = Ip
    OutputType = Dict[str, Any]

    VT_API_URL = "https://www.virustotal.com/api/v3"

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
        return True

    @classmethod
    def get_params_schema(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "VT_API_KEY",
                "type": "vaultSecret",
                "description": "VirusTotal API key (free tier available at virustotal.com).",
                "required": True,
            },
        ]

    @classmethod
    def name(cls) -> str:
        return "ip_to_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Security"

    @classmethod
    def key(cls) -> str:
        return "address"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Query VirusTotal API v3 for IP address analysis."""
        results: List[OutputType] = []
        api_key = self.get_secret("VT_API_KEY", os.getenv("VT_API_KEY"))

        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "[VIRUSTOTAL] No API key provided. Get one at https://www.virustotal.com"},
            )
            return [{"error": "No VT_API_KEY configured"}]

        headers = {"x-apikey": api_key}

        for ip_obj in data:
            ip_address = ip_obj.address
            try:
                response = requests.get(
                    f"{self.VT_API_URL}/ip_addresses/{ip_address}",
                    headers=headers,
                    timeout=15,
                )

                if response.status_code == 200:
                    data_resp = response.json().get("data", {})
                    attributes = data_resp.get("attributes", {})
                    last_analysis = attributes.get("last_analysis_stats", {})

                    results.append({
                        "ip": ip_address,
                        "analysis_stats": {
                            "malicious": last_analysis.get("malicious", 0),
                            "suspicious": last_analysis.get("suspicious", 0),
                            "harmless": last_analysis.get("harmless", 0),
                            "undetected": last_analysis.get("undetected", 0),
                            "timeout": last_analysis.get("timeout", 0),
                        },
                        "reputation": attributes.get("reputation", 0),
                        "country": attributes.get("country", ""),
                        "continent": attributes.get("continent", ""),
                        "as_owner": attributes.get("as_owner", ""),
                        "asn": attributes.get("asn", 0),
                        "network": attributes.get("network", ""),
                        "total_votes": attributes.get("total_votes", {}),
                        "last_analysis_date": attributes.get("last_analysis_date", 0),
                    })

                    Logger.info(
                        self.sketch_id,
                        {
                            "message": f"[VIRUSTOTAL] IP {ip_address}: "
                            f"malicious={last_analysis.get('malicious', 0)}, "
                            f"country={attributes.get('country', 'N/A')}"
                        },
                    )

                elif response.status_code == 404:
                    Logger.warn(
                        self.sketch_id,
                        {"message": f"[VIRUSTOTAL] IP {ip_address} not found"},
                    )
                    results.append({"ip": ip_address, "error": "Not found in VT"})
                elif response.status_code == 429:
                    Logger.warn(
                        self.sketch_id,
                        {"message": "[VIRUSTOTAL] Rate limited"},
                    )
                    results.append({"ip": ip_address, "error": "Rate limited"})
                else:
                    results.append({"ip": ip_address, "error": f"HTTP {response.status_code}"})

            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[VIRUSTOTAL] Error for IP {ip_address}: {e}"},
                )
                results.append({"ip": ip_address, "error": str(e)})

        return results

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        """Create Neo4j nodes with VirusTotal IP analysis."""
        if not self._graph_service:
            return results

        for result in results:
            if "error" in result:
                continue

            ip_address = result.get("ip", "")
            if not ip_address:
                continue

            ip_obj = Ip(
                address=ip_address,
                country=result.get("country") or None,
                isp=result.get("as_owner") or None,
            )
            self.create_node(ip_obj)

            stats = result.get("analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            status = "clean"
            if malicious > 0:
                status = "malicious"
            elif suspicious > 0:
                status = "suspicious"

            self.log_graph_message(
                f"VirusTotal IP: {ip_address} -> {status} "
                f"(malicious: {malicious}, suspicious: {suspicious}, "
                f"ASN: {result.get('asn', 'N/A')}, owner: {result.get('as_owner', 'N/A')})"
            )

        return results


InputType = IpToVirusTotalEnricher.InputType
OutputType = IpToVirusTotalEnricher.OutputType
