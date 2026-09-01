"""Detached Ed25519 signatures over canonical JSON bytes."""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import SignatureError
from .jsonio import atomic_write, canonical_file_bytes


def generate_keypair(private_path: Path | str, public_path: Path | str) -> None:
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    atomic_write(private_path, private_pem, private=True)
    atomic_write(public_path, public_pem)


def _private_from_bytes(raw: bytes) -> Ed25519PrivateKey:
    try:
        if raw.startswith(b"-----BEGIN"):
            key = serialization.load_pem_private_key(raw, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise SignatureError("private key is not Ed25519")
            return key
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise SignatureError("invalid Ed25519 private key") from exc
    raise SignatureError("private key must be PKCS8 PEM or a raw 32-byte Ed25519 seed")


def _public_from_bytes(raw: bytes) -> Ed25519PublicKey:
    try:
        if raw.startswith(b"-----BEGIN"):
            key = serialization.load_pem_public_key(raw)
            if not isinstance(key, Ed25519PublicKey):
                raise SignatureError("public key is not Ed25519")
            return key
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    except (TypeError, ValueError) as exc:
        raise SignatureError("invalid Ed25519 public key") from exc
    raise SignatureError("public key must be SubjectPublicKeyInfo PEM or raw Ed25519 bytes")


def private_key_from_env(name: str) -> Ed25519PrivateKey:
    encoded = os.environ.get(name, "")
    if not encoded:
        raise SignatureError(f"required signing key environment variable {name} is empty")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureError(f"{name} is not strict base64") from exc
    return _private_from_bytes(raw)


def load_private_key(path: Path | str) -> Ed25519PrivateKey:
    try:
        return _private_from_bytes(Path(path).read_bytes())
    except OSError as exc:
        raise SignatureError(f"could not read private key: {exc}") from exc


def load_public_key(path: Path | str) -> Ed25519PublicKey:
    try:
        return _public_from_bytes(Path(path).read_bytes())
    except OSError as exc:
        raise SignatureError(f"could not read public key: {exc}") from exc


def sign_document(
    document: Path | str,
    signature_path: Path | str,
    *,
    private_key: Ed25519PrivateKey,
) -> None:
    signature = private_key.sign(canonical_file_bytes(document))
    atomic_write(signature_path, base64.b64encode(signature) + b"\n")


def read_signature(path: Path | str) -> bytes:
    try:
        encoded = Path(path).read_bytes().strip()
        signature = base64.b64decode(encoded, validate=True)
    except (OSError, binascii.Error, ValueError) as exc:
        raise SignatureError(f"invalid detached signature: {exc}") from exc
    if len(signature) != 64:
        raise SignatureError("an Ed25519 detached signature must be exactly 64 bytes")
    return signature


def verify_document(
    document: Path | str,
    signature_path: Path | str,
    *,
    public_key: Ed25519PublicKey,
) -> None:
    try:
        public_key.verify(read_signature(signature_path), canonical_file_bytes(document))
    except InvalidSignature as exc:
        raise SignatureError("detached signature does not match canonical document") from exc


def public_key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()
