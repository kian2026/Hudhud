import dns.resolver
from typing import Any, Dict, List
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.domain import Domain
from flowsint_types.ip import Ip
from flowsint_types.dns_record import DNSRecord


@flowsint_enricher
class DomainToDnsRecordsEnricher(Enricher):
    """[DNSDUMPSTER] DNS reconnaissance — resolves A, AAAA, MX, NS, TXT, CNAME, SOA records for a domain."""

    InputType = Domain
    OutputType = Any

    @classmethod
    def name(cls) -> str:
        return "domain_to_dns_records"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Resolve DNS records for each domain."""
        results: List[OutputType] = []
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        for domain_obj in data:
            domain_name = domain_obj.domain
            domain_result = {
                "domain": domain_name,
                "records": [],
            }

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain_name, rtype)
                    for rdata in answers:
                        record = {
                            "type": rtype,
                            "value": str(rdata),
                            "ttl": answers.rrset.ttl,
                        }
                        if rtype == "MX":
                            record["priority"] = rdata.preference
                        domain_result["records"].append(record)
                except dns.resolver.NoAnswer:
                    continue
                except dns.resolver.NXDOMAIN:
                    Logger.warn(
                        self.sketch_id,
                        {"message": f"[DNS] Domain {domain_name} does not exist (NXDOMAIN)"},
                    )
                    domain_result["error"] = "NXDOMAIN"
                    break
                except dns.resolver.NoNameservers:
                    Logger.warn(
                        self.sketch_id,
                        {"message": f"[DNS] No nameservers for {domain_name}"},
                    )
                    continue
                except Exception as e:
                    Logger.error(
                        self.sketch_id,
                        {"message": f"[DNS] Error resolving {rtype} for {domain_name}: {e}"},
                    )
                    continue

            Logger.info(
                self.sketch_id,
                {"message": f"[DNS] Found {len(domain_result['records'])} records for {domain_name}"},
            )
            results.append(domain_result)

        return results

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        """Create Neo4j DNS record nodes and link them to domains."""
        if not self._graph_service:
            return results

        created_nodes = []
        for result in results:
            if "error" in result:
                continue

            domain_obj = Domain(domain=result["domain"])
            self.create_node(domain_obj)

            for record in result.get("records", []):
                rtype = record["type"]
                value = record["value"]
                
                # Extract the actual domain string from MX and SOA records
                if rtype == "MX":
                    # e.g., "10 mail.example.com." -> "mail.example.com."
                    value = value.split()[-1]
                elif rtype == "SOA":
                    # e.g., "ns1.example.com. admin.example.com. ..." -> "ns1.example.com."
                    value = value.split()[0]

                # Strip trailing dots from DNS values (e.g. "ns1.example.com.")
                if value.endswith("."):
                    value = value[:-1]

                if rtype in ["A", "AAAA"]:
                    # These resolve to IPs
                    target_obj = Ip(address=value, ttl=record.get("ttl"))
                    self.create_node(target_obj)
                    self.create_relationship(domain_obj, target_obj, f"HAS_{rtype}_RECORD")
                    created_nodes.append(target_obj)
                elif rtype in ["MX", "NS", "CNAME", "SOA"]:
                    # These resolve to Domains
                    target_obj = Domain(domain=value, ttl=record.get("ttl"), priority=record.get("priority"))
                        
                    self.create_node(target_obj)
                    self.create_relationship(domain_obj, target_obj, f"HAS_{rtype}_RECORD")
                    created_nodes.append(target_obj)
                else:
                    # Keep DNSRecord for TXT and unknown types
                    dns_record = DNSRecord(
                        value=value,
                        record_type=rtype,
                        ttl=record.get("ttl"),
                        priority=record.get("priority"),
                        source="dnspython",
                    )
                    self.create_node(dns_record)
                    self.create_relationship(
                        domain_obj, dns_record, f"HAS_{rtype}_RECORD"
                    )
                    created_nodes.append(dns_record)

            self.log_graph_message(
                f"Domain {result['domain']} -> {len(result.get('records', []))} DNS record(s)"
            )

        return created_nodes


InputType = DomainToDnsRecordsEnricher.InputType
OutputType = DomainToDnsRecordsEnricher.OutputType
