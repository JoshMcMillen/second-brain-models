from __future__ import annotations

from pathlib import Path

import pytest

from second_brain_models.errors import DocumentError, SignatureError
from second_brain_models.jsonio import canonical_bytes, loads_strict, write_canonical
from second_brain_models.signing import (
    generate_keypair, load_private_key, load_public_key, sign_document, verify_document,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_canonical_json_is_order_and_whitespace_independent(tmp_path: Path) -> None:
    assert canonical_bytes(loads_strict('{"b": 2, "a": "é"}')) == b'{"a":"\xc3\xa9","b":2}'
    with pytest.raises(DocumentError, match="duplicate"):
        loads_strict('{"a":1,"a":2}')
    with pytest.raises(DocumentError, match="non-finite"):
        loads_strict('{"a":NaN}')


def test_ed25519_detached_signature_covers_canonical_document(tmp_path: Path) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    document = tmp_path / "catalog.json"
    signature = tmp_path / "catalog.json.sig"
    generate_keypair(private, public)
    document.write_text('{"b":2,"a":1}\n', encoding="utf-8")
    sign_document(document, signature, private_key=load_private_key(private))
    document.write_text('{ "a": 1, "b": 2 }\n', encoding="utf-8")
    verify_document(document, signature, public_key=load_public_key(public))
    document.write_text('{"a":1,"b":3}\n', encoding="utf-8")
    with pytest.raises(SignatureError, match="does not match"):
        verify_document(document, signature, public_key=load_public_key(public))


def test_committed_catalog_signature_fixture() -> None:
    verify_document(
        REPO_ROOT / "fixtures" / "signing" / "catalog-v1.json",
        REPO_ROOT / "fixtures" / "signing" / "catalog-v1.json.sig",
        public_key=load_public_key(REPO_ROOT / "fixtures" / "signing" / "catalog-fixture-public.pem"),
    )


def test_committed_invalid_signing_fixtures_fail_verification() -> None:
    """Two invalid fixtures a consumer's own tests can exercise (docs/consumer-contract-v1.md)."""
    public_key = load_public_key(REPO_ROOT / "fixtures" / "signing" / "catalog-fixture-public.pem")

    with pytest.raises(SignatureError, match="does not match"):
        verify_document(
            REPO_ROOT / "fixtures" / "signing" / "catalog-v1.json",
            REPO_ROOT / "fixtures" / "signing" / "catalog-v1.bad-signature.json.sig",
            public_key=public_key,
        )

    with pytest.raises(SignatureError, match="does not match"):
        verify_document(
            REPO_ROOT / "fixtures" / "signing" / "catalog-v1.tampered.json",
            REPO_ROOT / "fixtures" / "signing" / "catalog-v1.json.sig",
            public_key=public_key,
        )
