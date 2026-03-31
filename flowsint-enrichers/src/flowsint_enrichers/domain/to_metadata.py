import re
import json
import tempfile
import os
import requests
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse
from flowsint_core.core.enricher_base import Enricher
from flowsint_enrichers.registry import flowsint_enricher
from flowsint_core.core.logger import Logger
from flowsint_types.domain import Domain
from flowsint_types.individual import Individual
from flowsint_types.email import Email
from tools.dockertool import DockerTool


# File extensions that ExifTool can extract metadata from
INTERESTING_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
}

# ExifTool metadata keys that may contain author/person names
AUTHOR_KEYS = ["Author", "Creator", "Artist", "By-line", "Owner", "LastModifiedBy"]
# ExifTool metadata keys that may contain email addresses
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


class ExifToolDocker(DockerTool):
    """Docker wrapper for ExifTool."""

    image = "exiftool/exiftool"
    default_tag = "latest"

    def __init__(self):
        super().__init__(self.image, self.default_tag)

    @classmethod
    def name(cls) -> str:
        return "exiftool"

    @classmethod
    def description(cls) -> str:
        return "Extract metadata from files."

    @classmethod
    def category(cls) -> str:
        return "Metadata"

    def extract_metadata(self, file_path: str) -> Dict[str, Any]:
        """Run exiftool on a local file and return JSON metadata."""
        abs_path = os.path.abspath(file_path)
        file_dir = os.path.dirname(abs_path)
        file_name = os.path.basename(abs_path)

        volumes = {file_dir: {"bind": "/data", "mode": "ro"}}

        try:
            result = super().launch(f"-json /data/{file_name}", volumes=volumes)
            parsed = json.loads(result)
            meta = parsed[0] if parsed else {}
            meta.pop("SourceFile", None)
            meta.pop("Directory", None)
            return meta
        except json.JSONDecodeError:
            return {"error": "Failed to parse ExifTool output"}
        except Exception as e:
            return {"error": str(e)}


@flowsint_enricher
class DomainToFilesMetadataEnricher(Enricher):
    """[EXIFTOOL] Discover files on a domain and extract their metadata, creating Individual and Email entities from authors found."""

    InputType = Domain
    OutputType = Any

    @classmethod
    def name(cls) -> str:
        return "domain_to_files_metadata"

    @classmethod
    def category(cls) -> str:
        return "Domain"

    @classmethod
    def key(cls) -> str:
        return "domain"

    async def scan(self, data: List[InputType]) -> List[OutputType]:
        """Discover files on domain and extract metadata with ExifTool."""
        results: List[OutputType] = []
        exiftool = ExifToolDocker()

        for domain_obj in data:
            domain_name = domain_obj.domain
            base_url = f"https://{domain_name}"

            try:
                file_urls = self.__discover_file_urls(base_url)

                Logger.info(
                    self.sketch_id,
                    {"message": f"[EXIFTOOL] Found {len(file_urls)} files on {domain_name}"},
                )

                files_with_metadata = []
                for file_info in file_urls:
                    metadata = self.__download_and_extract(exiftool, file_info["url"], file_info["filename"])
                    files_with_metadata.append({
                        "filename": file_info["filename"],
                        "url": file_info["url"],
                        "extension": file_info["extension"],
                        "metadata": metadata,
                    })

                results.append({
                    "domain": domain_name,
                    "files_count": len(files_with_metadata),
                    "files": files_with_metadata,
                })

            except Exception as e:
                Logger.error(
                    self.sketch_id,
                    {"message": f"[EXIFTOOL] Error on {domain_name}: {e}"},
                )
                results.append({"domain": domain_name, "error": str(e)})

        return results

    def __discover_file_urls(self, base_url: str) -> List[Dict[str, str]]:
        """Scrape page HTML for file links."""
        files = []
        seen = set()

        try:
            resp = requests.get(
                base_url, timeout=15,
                headers={"User-Agent": "Hudhud-OSINT/1.0"},
                allow_redirects=True,
            )
            if not resp.ok:
                return files

            url_pattern = re.compile(r'(?:href|src)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

            for match in url_pattern.finditer(resp.text):
                link = match.group(1).strip()
                if not link:
                    continue

                full_url = urljoin(base_url, link)
                path_lower = urlparse(full_url).path.lower()

                ext = next((e for e in INTERESTING_EXTENSIONS if path_lower.endswith(e)), None)
                if ext and full_url not in seen:
                    seen.add(full_url)
                    filename = urlparse(full_url).path.split("/")[-1] or f"file{ext}"
                    files.append({"url": full_url, "filename": filename, "extension": ext})

        except Exception as e:
            Logger.error(self.sketch_id, {"message": f"[EXIFTOOL] Crawl error: {e}"})

        return files

    def __download_and_extract(self, exiftool: ExifToolDocker, url: str, filename: str) -> Dict[str, Any]:
        """Download a file and extract metadata."""
        try:
            resp = requests.get(url, timeout=30, stream=True, headers={"User-Agent": "Hudhud-OSINT/1.0"})
            resp.raise_for_status()

            suffix = os.path.splitext(filename)[-1] or ".tmp"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                for chunk in resp.iter_content(chunk_size=8192):
                    tmp.write(chunk)
                tmp_path = tmp.name

            try:
                return exiftool.extract_metadata(tmp_path)
            finally:
                os.unlink(tmp_path)

        except Exception as e:
            return {"error": f"Download/extract failed: {e}"}

    def __extract_authors(self, metadata: Dict[str, Any]) -> List[str]:
        """Extract author/person names from metadata fields."""
        authors = set()
        for key in AUTHOR_KEYS:
            value = metadata.get(key)
            if value and isinstance(value, str):
                name = value.strip()
                # Skip generic/system values
                if name and len(name) > 1 and name.lower() not in {"unknown", "root", "admin", "user", "default"}:
                    authors.add(name)
        return list(authors)

    def __extract_emails(self, metadata: Dict[str, Any]) -> List[str]:
        """Scan all metadata values for email addresses."""
        emails = set()
        for value in metadata.values():
            if isinstance(value, str):
                found = EMAIL_PATTERN.findall(value)
                emails.update(found)
        return list(emails)

    def postprocess(self, results: List[Dict[str, Any]], original_input: List[InputType]) -> List[Any]:
        """Extract Individual and Email entities from metadata and create graph nodes."""
        if not self._graph_service:
            return results

        created_nodes = []

        for result in results:
            if "error" in result:
                continue

            domain_obj = Domain(domain=result["domain"])
            self.create_node(domain_obj)

            seen_authors: Set[str] = set()
            seen_emails: Set[str] = set()

            for file_data in result.get("files", []):
                metadata = file_data.get("metadata", {})
                if "error" in metadata:
                    continue

                filename = file_data["filename"]

                # Extract and create Individual nodes from author names
                authors = self.__extract_authors(metadata)
                for author_name in authors:
                    if author_name in seen_authors:
                        continue
                    seen_authors.add(author_name)

                    try:
                        parts = author_name.split(maxsplit=1)
                        first_name = parts[0]
                        last_name = parts[1] if len(parts) > 1 else ""

                        individual = Individual(
                            first_name=first_name,
                            last_name=last_name,
                            full_name=author_name,
                            source=f"ExifTool metadata from {filename}",
                        )
                        self.create_node(individual)
                        self.create_relationship(domain_obj, individual, "METADATA_AUTHOR")
                        created_nodes.append(individual)

                        self.log_graph_message(
                            f"Author found in {filename}: {author_name}"
                        )
                    except Exception:
                        continue

                # Extract and create Email nodes from metadata
                emails = self.__extract_emails(metadata)
                for email_str in emails:
                    if email_str in seen_emails:
                        continue
                    seen_emails.add(email_str)

                    try:
                        email_obj = Email(email=email_str)
                        self.create_node(email_obj)
                        self.create_relationship(domain_obj, email_obj, "METADATA_EMAIL")
                        created_nodes.append(email_obj)

                        self.log_graph_message(
                            f"Email found in {filename} metadata: {email_str}"
                        )
                    except Exception:
                        continue

                # Log software info
                software = metadata.get("Software") or metadata.get("Producer")
                if software:
                    self.log_graph_message(
                        f"Software used for {filename}: {software}"
                    )

            # Summary
            self.log_graph_message(
                f"[{result['domain']}] ExifTool: {result['files_count']} files, "
                f"{len(seen_authors)} author(s), {len(seen_emails)} email(s) extracted"
            )

        return created_nodes


InputType = DomainToFilesMetadataEnricher.InputType
OutputType = DomainToFilesMetadataEnricher.OutputType
