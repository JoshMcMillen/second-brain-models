"""Pluggable asset-hosting backends for publishing a signed catalog release.

V1 ships exactly one working backend, ``github-release``, used as an interim
distribution host while Cloudflare R2 is not yet enabled for this project (see
``docs/cloudflare-setup.md``). A second backend name, ``r2``, is reserved and
documented here so callers can select it later without changing any call
site; selecting it today fails closed with a clear pointer at the R2 runbook
instead of silently doing nothing.

Every function here is pure and offline: it computes names and URLs from
inputs only. Nothing in this module performs network I/O; that lives in
``second_brain_models.publishing`` behind an injectable transport so the
publish flow stays unit-testable without a real GitHub API.
"""
from __future__ import annotations

import re

from .errors import ModelCatalogError


SUPPORTED_HOSTS = ("github-release", "r2")

_OWNER_REPO = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?/[A-Za-z0-9._-]+$")
_RELEASE_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")
_CHANNELS = ("beta", "stable", "revoked", "test")


def release_name(channel: str, catalog_version: int) -> str:
    """Compute the immutable-once-published GitHub Release name for a catalog build."""
    if channel not in _CHANNELS:
        raise ModelCatalogError(f"unsupported catalog channel for release naming: {channel!r}")
    if not isinstance(catalog_version, int) or isinstance(catalog_version, bool) or catalog_version < 1:
        raise ModelCatalogError("catalog_version must be a positive integer")
    name = f"catalog-{channel}-v{catalog_version}"
    if not _RELEASE_NAME.fullmatch(name):
        raise ModelCatalogError(f"computed release name is not well-formed: {name!r}")
    return name


def asset_filename(repository_relative_path: str) -> str:
    """Flatten a repository-relative path into one unique flat release-asset name.

    GitHub release assets share one flat namespace per release and forbid path
    separators in asset names. The flattening (replacing every ``/`` with
    ``-``) is deterministic and, in practice, collision-free for every path
    shape this repository actually produces (content-addressed by SHA-256, or
    a committed schema/fixture path) -- but it is not injective in general:
    two different repository-relative paths that differ only in where a ``/``
    falls relative to a literal ``-`` can flatten to the same name (e.g.
    ``a/b-c`` and ``a-b/c`` both flatten to ``a-b-c``). Callers that assemble
    a release from more than one path (see
    ``second_brain_models.publishing.plan_release``) must check for that
    themselves before relying on this being unique.
    """
    if not isinstance(repository_relative_path, str) or not repository_relative_path:
        raise ModelCatalogError(f"unsafe repository-relative asset path: {repository_relative_path!r}")
    if "\\" in repository_relative_path or repository_relative_path.startswith("/"):
        raise ModelCatalogError(f"unsafe repository-relative asset path: {repository_relative_path!r}")
    parts = repository_relative_path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise ModelCatalogError(f"unsafe repository-relative asset path: {repository_relative_path!r}")
    flattened = "-".join(parts)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}", flattened):
        raise ModelCatalogError(f"flattened asset filename is not safe: {flattened!r}")
    return flattened


def github_release_asset_url(*, repository: str, release: str, filename: str) -> str:
    if not _OWNER_REPO.fullmatch(repository):
        raise ModelCatalogError(f"repository must be an exact owner/name: {repository!r}")
    if not _RELEASE_NAME.fullmatch(release):
        raise ModelCatalogError(f"release name is not well-formed: {release!r}")
    return f"https://github.com/{repository}/releases/download/{release}/{filename}"


def resolve_asset_url(
    *, host: str, repository: str, release: str, repository_relative_path: str,
) -> str:
    """Compute the final, deterministic download URL for one repository object.

    The result depends only on the selected host, the repository identity, the
    immutable release name, and the object's own repository-relative path --
    never on any network call -- so it can be computed once, baked into the
    catalog, and signed before a single byte is uploaded.
    """
    filename = asset_filename(repository_relative_path)
    if host == "github-release":
        return github_release_asset_url(repository=repository, release=release, filename=filename)
    if host == "r2":
        raise ModelCatalogError(
            "the r2 hosting backend is documented but not implemented; see "
            "docs/cloudflare-setup.md and docs/publishing-interface-v1.md for the "
            "artifact-first receipt required before it may be enabled"
        )
    raise ModelCatalogError(f"unknown asset host {host!r}; expected one of {SUPPORTED_HOSTS}")
