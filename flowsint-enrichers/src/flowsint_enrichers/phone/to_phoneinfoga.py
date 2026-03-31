from typing import Any, Dict, List, Optional
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.phone import Phone
from tools.dockertool import DockerTool
import json


class PhoneInfogaTool(DockerTool):
    """Docker wrapper for PhoneInfoga — phone number OSINT scanner."""

    image = "sundowndev/phoneinfoga"
    default_tag = "latest"

    def __init__(self):
        super().__init__(self.image, self.default_tag)

    @classmethod
    def name(cls) -> str:
        return "phoneinfoga"

    @classmethod
    def description(cls) -> str:
        return "Gather information from phone numbers."

    @classmethod
    def category(cls) -> str:
        return "Phone Analysis"

    def scan_number(self, phone_number: str) -> Dict[str, Any]:
        """Run phoneinfoga scan on a phone number."""
        try:
            result = super().launch(f"scan -n {phone_number}")
            return self.__parse_output(result, phone_number)
        except Exception as e:
            return {"number": phone_number, "error": str(e)}

    def __parse_output(self, output: str, phone_number: str) -> Dict[str, Any]:
        """Parse phoneinfoga text output into structured data."""
        result = {
            "number": phone_number,
            "valid": False,
            "country": None,
            "carrier": None,
            "line_type": None,
            "international_format": None,
            "local_format": None,
            "country_code": None,
            "raw_output": output,
        }

        for line in output.split("\n"):
            line = line.strip()
            if not line or ":" not in line:
                continue

            key_part, val_part = line.split(":", 1)
            key = key_part.strip().lower()
            val = val_part.strip()

            if "valid" in key:
                result["valid"] = val.lower() in ("true", "yes")
            elif key == "country name" or key == "country":
                result["country"] = val
            elif key == "carrier":
                result["carrier"] = val
            elif key == "line type":
                result["line_type"] = val
            elif key == "international":
                result["international_format"] = val
            elif key == "local":
                result["local_format"] = val
            elif key == "country code":
                result["country_code"] = val

        return result


@flowsint_enricher
class PhoneToPhoneInfogaEnricher(Enricher):
    """[PHONEINFOGA] Gather information from phone numbers using PhoneInfoga scanner."""

    InputType = Phone
    OutputType = Dict[str, Any]

    @classmethod
    def name(cls) -> str:
        return "phone_to_phoneinfoga"

    @classmethod
    def category(cls) -> str:
        return "phones"

    @classmethod
    def key(cls) -> str:
        return "number"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Scan phone numbers using PhoneInfoga Docker container."""
        results: List[OutputType] = []
        phoneinfoga = PhoneInfogaTool()

        for phone_obj in data:
            try:
                result = phoneinfoga.scan_number(phone_obj.number)
                results.append(result)

                Logger.info(
                    self.sketch_id,
                    {
                        "message": f"[PHONEINFOGA] Scanned {phone_obj.number}: "
                        f"valid={result.get('valid')}, country={result.get('country')}"
                    },
                )
            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[PHONEINFOGA] Error scanning {phone_obj.number}: {e}"},
                )
                results.append({"number": phone_obj.number, "error": str(e)})

        return results

    def postprocess(
        self, results: List[OutputType], original_input: List[InputType]
    ) -> List[OutputType]:
        """Create Neo4j nodes for phone scan results."""
        if not self._graph_service:
            return results

        for result in results:
            if "error" in result:
                continue

            phone_obj = Phone(
                number=result["number"],
                country=result.get("country"),
                carrier=result.get("carrier"),
                line_type=result.get("line_type"),
                valid=result.get("valid")
            )
            self.create_node(phone_obj)

            self.log_graph_message(
                f"Phone {result['number']}: "
                f"valid={result.get('valid')}, "
                f"country={result.get('country')}, "
                f"carrier={result.get('carrier')}, "
                f"type={result.get('line_type')}"
            )

        return results


InputType = PhoneToPhoneInfogaEnricher.InputType
OutputType = PhoneToPhoneInfogaEnricher.OutputType
