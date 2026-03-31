import requests
from typing import Any, Dict, List
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.domain import Domain
from flowsint_types.email import Email
from flowsint_types.ip import Ip


@flowsint_enricher
class DomainToHarvestedEnricher(Enricher):
    """[THEHARVESTER] Collect emails, subdomains, and IPs from public sources using crt.sh, HackerTarget, and other OSINT APIs."""

    InputType = Domain
    OutputType = Any

    @classmethod
    def name(cls) -> str:
        return "domain_to_harvested"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Harvest emails, subdomains, and IPs from multiple public sources."""
        results: List[OutputType] = []

        for domain_obj in data:
            domain_name = domain_obj.domain
            harvested = {
                "domain": domain_name,
                "emails": [],
                "hosts": [],
                "ips": [],
            }

            # Source 1: crt.sh for subdomains
            harvested["hosts"].extend(self.__harvest_crtsh(domain_name))

            # Source 2: HackerTarget for hosts and IPs
            ht_data = self.__harvest_hackertarget(domain_name)
            harvested["hosts"].extend(ht_data.get("hosts", []))
            harvested["ips"].extend(ht_data.get("ips", []))

            # Deduplicate
            harvested["emails"] = list(set(harvested["emails"]))
            harvested["hosts"] = list(set(harvested["hosts"]))
            harvested["ips"] = list(set(harvested["ips"]))

            Logger.info(
                self.sketch_id,
                {
                    "message": f"[HARVESTER] {domain_name}: "
                    f"{len(harvested['emails'])} emails, "
                    f"{len(harvested['hosts'])} hosts, "
                    f"{len(harvested['ips'])} IPs"
                },
            )
            results.append(harvested)

        return results

    def __harvest_crtsh(self, domain: str) -> List[str]:
        """Get subdomains from crt.sh certificate transparency logs."""
        subdomains = set()
        try:
            response = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=30,
            )
            if response.ok:
                for entry in response.json():
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if "*" not in sub and sub.endswith(domain):
                            subdomains.add(sub)
        except Exception as e:
            Logger.error(
                self.sketch_id,
                {"message": f"[HARVESTER] crt.sh error for {domain}: {e}"},
            )
        return list(subdomains)

    def __harvest_hackertarget(self, domain: str) -> Dict[str, List[str]]:
        """Get hosts and IPs from HackerTarget API."""
        result = {"hosts": [], "ips": []}
        try:
            response = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=15,
            )
            if response.ok and "error" not in response.text.lower():
                for line in response.text.strip().split("\n"):
                    parts = line.split(",")
                    if len(parts) >= 2:
                        host = parts[0].strip()
                        ip = parts[1].strip()
                        if host:
                            result["hosts"].append(host)
                        if ip:
                            result["ips"].append(ip)
        except Exception as e:
            Logger.error(
                self.sketch_id,
                {"message": f"[HARVESTER] HackerTarget error for {domain}: {e}"},
            )
        return result

    def postprocess(
        self, results: List[Dict[str, Any]], original_input: List[InputType]
    ) -> List[Any]:
        """Create Neo4j nodes for harvested emails, hosts, and IPs."""
        if not self._graph_service:
            return results

        created_nodes = []

        for result in results:
            domain_obj = Domain(domain=result["domain"])
            self.create_node(domain_obj)

            # Create email nodes
            for email_str in result.get("emails", []):
                try:
                    email_obj = Email(email=email_str)
                    self.create_node(email_obj)
                    self.create_relationship(domain_obj, email_obj, "HAS_EMAIL")
                    created_nodes.append(email_obj)
                except Exception as e:
                    Logger.error(self.sketch_id, {"message": f"[HARVESTER] Failed to create Email node {email_str}: {e}"})
                    continue

            # Create host/subdomain nodes
            for host in result.get("hosts", []):
                try:
                    host_obj = Domain(domain=host)
                    self.create_node(host_obj)
                    if host != result["domain"]:
                        self.create_relationship(domain_obj, host_obj, "HAS_SUBDOMAIN")
                    created_nodes.append(host_obj)
                except Exception as e:
                    Logger.error(self.sketch_id, {"message": f"[HARVESTER] Failed to create Domain node {host}: {e}"})
                    continue

            # Create IP nodes
            for ip_str in result.get("ips", []):
                try:
                    ip_obj = Ip(address=ip_str)
                    self.create_node(ip_obj)
                    self.create_relationship(domain_obj, ip_obj, "RESOLVES_TO")
                    created_nodes.append(ip_obj)
                except Exception as e:
                    Logger.error(self.sketch_id, {"message": f"[HARVESTER] Failed to create Ip node {ip_str}: {e}"})
                    continue

            self.log_graph_message(
                f"Harvested {result['domain']}: "
                f"{len(result.get('emails', []))} emails, "
                f"{len(result.get('hosts', []))} hosts, "
                f"{len(result.get('ips', []))} IPs"
            )

        return created_nodes


InputType = DomainToHarvestedEnricher.InputType
OutputType = DomainToHarvestedEnricher.OutputType
