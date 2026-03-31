import os
from typing import Any, Dict, List, Optional
import requests
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.email import Email
from dotenv import load_dotenv

load_dotenv()


@flowsint_enricher
class EmailToReputationEnricher(Enricher):
    """[EMAILREP] Analyze the reputation and risk of an email address."""

    InputType = Email
    OutputType = Dict[str, Any]

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
        return [
            {
                "name": "EMAILREP_API_KEY",
                "type": "vaultSecret",
                "description": "Optional EmailRep API key for higher rate limits.",
                "required": False,
            },
        ]

    @classmethod
    def name(cls) -> str:
        return "email_to_reputation"

    @classmethod
    def category(cls) -> str:
        return "Email"

    @classmethod
    def key(cls) -> str:
        return "email"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Query EmailRep.io API to get email reputation data."""
        results: List[OutputType] = []
        api_key = self.get_secret("EMAILREP_API_KEY", os.getenv("EMAILREP_API_KEY"))

        headers = {"User-Agent": "Hudhud-OSINT/1.0"}
        if api_key:
            headers["Key"] = api_key

        for email in data:
            try:
                response = requests.get(
                    f"https://emailrep.io/{email.email}",
                    headers=headers,
                    timeout=15,
                )

                if response.status_code == 200:
                    rep_data = response.json()
                    results.append(
                        {
                            "email": email.email,
                            "reputation": rep_data.get("reputation", "unknown"),
                            "suspicious": rep_data.get("suspicious", False),
                            "references": rep_data.get("references", 0),
                            "details": rep_data.get("details", {}),
                        }
                    )
                elif response.status_code == 429:
                    Logger.warn(
                        self.sketch_id,
                        {"message": f"[EMAILREP] Rate limited for {email.email}"},
                    )
                    results.append({"email": email.email, "error": "Rate limited"})
                else:
                    Logger.error(
                        self.sketch_id,
                        {
                            "message": f"[EMAILREP] API error for {email.email}: {response.status_code}"
                        },
                    )
                    results.append(
                        {"email": email.email, "error": f"HTTP {response.status_code}"}
                    )

            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[EMAILREP] Error for {email.email}: {e}"},
                )
                results.append({"email": email.email, "error": str(e)})

        return results

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        """Create Neo4j nodes and relationships for email reputation."""
        if not self._graph_service:
            return results

        for result in results:
            if "error" in result:
                continue

            email_obj = Email(email=result["email"])
            self.create_node(email_obj)

            self.log_graph_message(
                f"Email {result['email']} reputation: {result.get('reputation', 'unknown')} "
                f"(suspicious: {result.get('suspicious', False)}, "
                f"references: {result.get('references', 0)})"
            )

        return results


InputType = EmailToReputationEnricher.InputType
OutputType = EmailToReputationEnricher.OutputType
