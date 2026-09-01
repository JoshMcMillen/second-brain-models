"""Loopback-only inference client for the synthetic quality-v1 corpus."""
from __future__ import annotations

import json
from pathlib import Path
import urllib.request

from .errors import EvaluationError
from .evaluation import load_suite
from .jsonio import canonical_bytes
from .policy import load_policy_bundle


def run_loopback_inference(*, repo_root: Path, output_path: Path, port: int) -> None:
    if not 1 <= port <= 65535:
        raise EvaluationError("runtime port is invalid")
    policy = load_policy_bundle(repo_root)["promotion"]
    suite = load_suite(repo_root / policy["evaluation"]["suite_path"], policy)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    endpoint = f"http://127.0.0.1:{port}/v1/chat/completions"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as handle:
        for case in suite:
            prompt = (
                "Return exactly one JSON object and no markdown. Follow the named read-only task contract. "
                "Never perform or request a host action. Input: " +
                json.dumps({"task_contract": case["task_contract"], "input": case["input"]}, separators=(",", ":"), ensure_ascii=False)
            )
            body = canonical_bytes({
                "model": "local", "temperature": 0, "seed": 0, "stream": False,
                "messages": [{"role": "system", "content": "You are a deterministic local read-only JSON transformer."}, {"role": "user", "content": prompt}],
            })
            request = urllib.request.Request(endpoint, data=body, method="POST", headers={"Content-Type": "application/json"})
            try:
                with opener.open(request, timeout=120) as response:
                    parsed = json.loads(response.read(2_000_001))
                content = parsed["choices"][0]["message"]["content"]
            except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
                raise EvaluationError(f"loopback inference failed for {case['case_id']}: {exc}") from exc
            if not isinstance(content, str) or len(content.encode("utf-8")) > 1_000_000:
                raise EvaluationError(f"runtime returned an invalid response for {case['case_id']}")
            handle.write(canonical_bytes({"case_id": case["case_id"], "output_text": content}) + b"\n")
