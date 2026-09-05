"""Deterministic bytes for the non-model install-flow canary fixture.

Second Brain needs something small it can install end to end -- fetch a
signed catalog, verify it, download a content-addressed artifact, verify its
SHA-256 and size, and install it -- without downloading a multi-gigabyte real
model just to exercise that mechanism. This module builds that artifact.

The artifact is a structurally valid, zero-tensor GGUF container (so it
passes the exact same static admission checks as a real model, per
``second_brain_models.candidate.validate_gguf_structure``) carrying only a
few metadata strings that say what it is. Its bytes are reconstructed by this
pure function rather than committed to Git, exactly like a real model's
weights: ``.gguf`` bytes are always forbidden in this repository (see
``second_brain_models.repository.check_repository`` and ``.gitignore``).
Only this generator, the fixture's manifest, and its evaluation result are
committed.
"""
from __future__ import annotations

import struct

CANARY_MODEL_ID = "second-brain-install-canary"
CANARY_ARCHITECTURE = "second-brain-canary"
CANARY_DESCRIPTION = (
    "Deterministic non-model fixture that exercises signed-catalog fetch, "
    "verify, download, and install without downloading a real model."
)


def _pack_gguf_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<Q", len(raw)) + raw


def _pack_gguf_string_metadata(key: str, value: str) -> bytes:
    # Metadata value type 8 is GGUF's STRING tag; see candidate._GGUF_STRING.
    return _pack_gguf_string(key) + struct.pack("<I", 8) + _pack_gguf_string(value)


def build_canary_artifact_bytes() -> bytes:
    """Return the exact, deterministic bytes of the tiny canary artifact.

    The result is a minimal GGUF v3 container with zero tensors and three
    ASCII-keyed string metadata fields. It is intentionally only a few
    hundred bytes and never changes for a given version of this function, so
    its SHA-256 digest committed in the fixture manifest is reproducible by
    anyone from source.
    """
    fields = (
        ("general.architecture", CANARY_ARCHITECTURE),
        ("general.name", "Second Brain Install Canary"),
        ("general.description", CANARY_DESCRIPTION),
    )
    header = b"GGUF" + struct.pack("<I", 3) + struct.pack("<Q", 0) + struct.pack("<Q", len(fields))
    body = b"".join(_pack_gguf_string_metadata(key, value) for key, value in fields)
    return header + body
