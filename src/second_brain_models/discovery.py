"""Metadata-only discovery from exact allowlisted publisher namespaces."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from pathlib import Path
import urllib.parse
import urllib.request
from typing import Any

from .errors import DocumentError
from .jsonio import loads_strict, write_canonical
from .policy import load_policy_bundle


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _fetch_json(url: str, *, maximum_bytes: int = 5_000_000) -> Any:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "huggingface.co":
        raise DocumentError("discovery may query only the HTTPS Hugging Face metadata API")
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "second-brain-models-discovery/1"})
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=20) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise DocumentError(f"unexpected discovery response status/type for {url}")
        raw = response.read(maximum_bytes + 1)
    if len(raw) > maximum_bytes:
        raise DocumentError("discovery metadata response exceeds size limit")
    return loads_strict(raw)


def discover(repo_root: Path | str, output_path: Path | str, *, limit_per_publisher: int = 20) -> dict[str, Any]:
    policies = load_policy_bundle(repo_root)
    candidates: list[dict[str, Any]] = []
    for publisher in policies["upstream"]["allowed_publishers"]:
        query = urllib.parse.urlencode({
            "author": publisher["namespace"],
            "sort": "lastModified",
            "direction": "-1",
            "limit": str(limit_per_publisher),
            "full": "true",
        })
        response = _fetch_json(f"https://huggingface.co/api/models?{query}")
        if not isinstance(response, list):
            raise DocumentError("discovery API response must be a list")
        for model in response:
            if not isinstance(model, dict) or not isinstance(model.get("id"), str):
                continue
            repository = f"huggingface.co/{model['id']}"
            revision = model.get("sha")
            if not re.fullmatch(publisher["repository_pattern"], repository):
                continue
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40,64}", revision):
                continue
            files = []
            for sibling in model.get("siblings", []):
                name = sibling.get("rfilename") if isinstance(sibling, dict) else None
                if isinstance(name, str) and name.casefold().endswith(".gguf") and ".." not in Path(name).parts and "\\" not in name:
                    files.append(name)
            if files:
                candidates.append({
                    "publisher_id": publisher["publisher_id"],
                    "repository": repository,
                    "revision": revision,
                    "gguf_source_paths": sorted(set(files)),
                    "last_modified": model.get("lastModified"),
                    "decision": "candidate_review_only",
                })
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "metadata_only": True,
        "executes_upstream_code": False,
        "candidates": sorted(candidates, key=lambda item: (item["publisher_id"], item["repository"])),
    }
    write_canonical(output_path, report)
    return report
