from __future__ import annotations

from pathlib import Path

import pytest

from second_brain_models import cli
from second_brain_models.errors import ModelCatalogError


def test_build_canary_reports_a_clear_error_when_fixture_manifest_is_missing(
    tmp_path: Path,
) -> None:
    # This contract-only change does not commit fixtures/test-channel/ at
    # all (it follows in a dedicated pull request), so build-canary must
    # fail with a clear, actionable ModelCatalogError naming exactly what is
    # missing and why -- not a generic filesystem/JSON error from load_json.
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    staging_root = tmp_path / "staging"

    with pytest.raises(ModelCatalogError, match="canary fixture manifest is missing"):
        cli.run([
            "build-canary",
            "--repo-root", str(repo_root),
            "--staging-root", str(staging_root),
        ])
