import os
from typing import Any, Dict, List, Optional
import requests
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.domain import Domain
from dotenv import load_dotenv

load_dotenv()


@flowsint_enricher
class DomainToVirusTotalEnricher(Enricher):
    """[VIRUSTOTAL] Analyze URLs and domains for malware, phishing, and security threats."""

    InputType = Domain
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
        return "domain_to_virustotal"

    @classmethod
    def category(cls) -> str:
        return "Security"

    @classmethod
    def key(cls) -> str:
        return "domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Query VirusTotal API v3 for domain/URL analysis."""
        results: List[OutputType] = []
        api_key = self.get_secret("VT_API_KEY", os.getenv("VT_API_KEY"))

        if not api_key:
            Logger.error(
                self.sketch_id,
                {"message": "[VIRUSTOTAL] No API key provided. Get one at https://www.virustotal.com"},
            )
            return [{"error": "No VT_API_KEY configured"}]

        headers = {"x-apikey": api_key}

        for domain_obj in data:
            domain_name = domain_obj.domain
            try:
                # Try domain report first
                vt_result = self.__get_domain_report(domain_name, headers)
                if vt_result:
                    results.append(vt_result)
                else:
                    results.append({"domain": domain_name, "error": "No data from VirusTotal"})

            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[VIRUSTOTAL] Error for {domain_name}: {e}"},
                )
                results.append({"domain": domain_name, "error": str(e)})

        return results

    def __get_domain_report(self, domain: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Get domain analysis report from VirusTotal."""
        try:
            response = requests.get(
                f"{self.VT_API_URL}/domains/{domain}",
                headers=headers,
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                last_analysis = attributes.get("last_analysis_stats", {})
                categories = attributes.get("categories", {})
                reputation = attributes.get("reputation", 0)
                whois = attributes.get("whois", "")

                return {
                    "domain": domain,
                    "analysis_stats": {
                        "malicious": last_analysis.get("malicious", 0),
                        "suspicious": last_analysis.get("suspicious", 0),
                        "harmless": last_analysis.get("harmless", 0),
                        "undetected": last_analysis.get("undetected", 0),
                        "timeout": last_analysis.get("timeout", 0),
                    },
                    "reputation": reputation,
                    "categories": categories,
                    "registrar": attributes.get("registrar", ""),
                    "creation_date": attributes.get("creation_date", 0),
                    "last_analysis_date": attributes.get("last_analysis_date", 0),
                    "total_votes": attributes.get("total_votes", {}),
                    "dns_records": attributes.get("last_dns_records", []),
                }

            elif response.status_code == 404:
                Logger.warn(
                    self.sketch_id,
                    {"message": f"[VIRUSTOTAL] Domain {domain} not found in VT database"},
                )
                return None
            elif response.status_code == 429:
                Logger.warn(
                    self.sketch_id,
                    {"message": "[VIRUSTOTAL] Rate limited. Wait before retrying."},
                )
                return {"domain": domain, "error": "Rate limited"}
            else:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[VIRUSTOTAL] API error: {response.status_code}"},
                )
                return None

        except Exception as e:
            Logger.error(
                self.sketch_id,
                {"message": f"[VIRUSTOTAL] Request error for {domain}: {e}"},
            )
            return None

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        """Create Neo4j nodes with VirusTotal analysis results."""
        if not self._graph_service:
            return results

        for result in results:
            if "error" in result:
                continue

            domain_name = result.get("domain", "")
            if not domain_name:
                continue

            domain_obj = Domain(domain=domain_name)
            self.create_node(domain_obj)

            stats = result.get("analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            status = "clean"
            if malicious > 0:
                status = "malicious"
            elif suspicious > 0:
                status = "suspicious"

            self.log_graph_message(
                f"VirusTotal: {domain_name} -> {status} "
                f"(malicious: {malicious}, suspicious: {suspicious}, "
                f"reputation: {result.get('reputation', 0)})"
            )

        return results


InputType = DomainToVirusTotalEnricher.InputType
OutputType = DomainToVirusTotalEnricher.OutputType
