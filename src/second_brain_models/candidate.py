"""Static admission checks for an exact, already-downloaded model artifact.

This module never imports, deserializes, launches, or otherwise executes any
candidate content.  It operates on paths, bytes, strict metadata, and hashes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
from typing import Any, BinaryIO, Iterable

from .errors import DocumentError, PolicyError
from .license import validate_license_binding
from .policy import load_policy_bundle
from .schema import validate_file


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")

_FORBIDDEN_SUFFIXES = {
    ".exe", ".dll", ".so", ".dylib", ".msi", ".app", ".com", ".scr",
    ".bat", ".cmd", ".ps1", ".sh", ".bash", ".zsh", ".py", ".pyc", ".pyo",
    ".pkl", ".pickle", ".pt", ".pth", ".ckpt", ".joblib", ".bin",
    ".whl", ".egg", ".jar", ".wasm", ".node", ".deb", ".rpm", ".apk",
    ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".tgz", ".zst",
}
_FORBIDDEN_FILENAMES = {
    "setup.py", "setup.cfg", "pyproject.toml", "requirements.txt", "pipfile",
    "environment.yml", "environment.yaml", "dockerfile", "makefile",
}
_FORBIDDEN_KEYS = {
    "auto_map", "trust_remote_code", "custom_pipelines", "code_revision",
    "plugin", "plugins", "entrypoint", "entry_point", "command", "commands",
    "install_command", "post_install", "hook", "hooks", "script", "scripts",
    "executable", "dynamic_module", "library_path", "remote_model_url",
}

# These limits are intentionally well above ordinary GGUF metadata while still
# bounding work on an untrusted candidate. Tensor bytes themselves are never
# loaded; only headers, metadata values, descriptors, and alignment padding are
# inspected.
_GGUF_MAX_METADATA_COUNT = 100_000
_GGUF_MAX_TENSOR_COUNT = 250_000
_GGUF_MAX_METADATA_BYTES = 512 * 1024 * 1024
_GGUF_MAX_STRING_BYTES = 16 * 1024 * 1024
_GGUF_MAX_KEY_BYTES = 65_535
_GGUF_MAX_TENSOR_NAME_BYTES = 64
_GGUF_MAX_ARRAY_ELEMENTS = 2_000_000
_GGUF_MAX_TOTAL_ARRAY_ELEMENTS = 4_000_000
_GGUF_MAX_ARRAY_DEPTH = 8
_GGUF_MAX_ALIGNMENT = 1024 * 1024
_GGUF_MAX_DIMENSION = (1 << 63) - 1
_GGUF_PADDING_CHUNK = 64 * 1024

_GGUF_KEY = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)*(?:\.[a-z0-9]+(?:_[a-z0-9]+)*)*$")

# GGUF metadata value type -> serialized scalar byte width. STRING (8) and
# ARRAY (9) are variable-width and are handled separately.
_GGUF_SCALAR_SIZES = {
    0: 1,   # UINT8
    1: 1,   # INT8
    2: 2,   # UINT16
    3: 2,   # INT16
    4: 4,   # UINT32
    5: 4,   # INT32
    6: 4,   # FLOAT32
    7: 1,   # BOOL
    10: 8,  # UINT64
    11: 8,  # INT64
    12: 8,  # FLOAT64
}
_GGUF_STRING = 8
_GGUF_ARRAY = 9
_GGUF_VALUE_TYPES = frozenset((*_GGUF_SCALAR_SIZES, _GGUF_STRING, _GGUF_ARRAY))

# GGML tensor type -> (logical elements per storage block, stored block bytes).
# Values mirror the supported GGUF types and GGML_QUANT_SIZES in llama.cpp.
# Removed/reserved IDs are deliberately absent so admission fails closed.
_GGML_STORAGE = {
    0: (1, 4),       # F32
    1: (1, 2),       # F16
    2: (32, 18),     # Q4_0
    3: (32, 20),     # Q4_1
    6: (32, 22),     # Q5_0
    7: (32, 24),     # Q5_1
    8: (32, 34),     # Q8_0
    9: (32, 40),     # Q8_1
    10: (256, 84),   # Q2_K
    11: (256, 110),  # Q3_K
    12: (256, 144),  # Q4_K
    13: (256, 176),  # Q5_K
    14: (256, 210),  # Q6_K
    15: (256, 292),  # Q8_K
    16: (256, 66),   # IQ2_XXS
    17: (256, 74),   # IQ2_XS
    18: (256, 98),   # IQ3_XXS
    19: (256, 50),   # IQ1_S
    20: (32, 18),    # IQ4_NL
    21: (256, 110),  # IQ3_S
    22: (256, 82),   # IQ2_S
    23: (256, 136),  # IQ4_XS
    24: (1, 1),      # I8
    25: (1, 2),      # I16
    26: (1, 4),      # I32
    27: (1, 8),      # I64
    28: (1, 8),      # F64
    29: (256, 56),   # IQ1_M
    30: (1, 2),      # BF16
    34: (256, 54),   # TQ1_0
    35: (256, 66),   # TQ2_0
    39: (32, 17),    # MXFP4
    40: (64, 36),    # NVFP4
    41: (128, 18),   # Q1_0
    42: (64, 18),    # Q2_0
}


def sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def validate_content_path(path: str, digest: str) -> PurePosixPath:
    if not isinstance(path, str) or not _DIGEST.fullmatch(digest):
        raise DocumentError("artifact path and SHA-256 must be strings using a lowercase 64-hex digest")
    if "\\" in path or any(ord(char) < 32 for char in path):
        raise DocumentError("artifact path must use safe POSIX path characters")
    relative = PurePosixPath(path)
    parts = relative.parts
    if relative.is_absolute() or len(parts) != 4 or parts[:2] != ("models", "sha256"):
        raise DocumentError("artifact path must be models/sha256/<digest>/model.gguf")
    if parts[2] != digest or parts[3] != "model.gguf":
        raise DocumentError("artifact path digest or filename is unsafe")
    return relative


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _reject_symlink_components(root: Path, target: Path) -> None:
    current = root
    for part in target.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise DocumentError(f"symlinks are forbidden in artifact paths: {current}")


def _walk_metadata(value: Any, location: str = "manifest") -> Iterable[tuple[str, str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            yield location, normalized, child
            yield from _walk_metadata(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_metadata(child, f"{location}[{index}]")


def _reject_remote_code_metadata(manifest: dict[str, Any]) -> None:
    for location, key, value in _walk_metadata(manifest):
        if key in _FORBIDDEN_KEYS:
            raise DocumentError(f"remote code or executable metadata is forbidden: {location}.{key}")
        if isinstance(value, str):
            lowered = value.casefold()
            name = PurePosixPath(lowered.replace("\\", "/")).name
            if name in _FORBIDDEN_FILENAMES or PurePosixPath(name).suffix in _FORBIDDEN_SUFFIXES:
                raise DocumentError(f"manifest references forbidden executable, pickle, plugin, or archive content at {location}.{key}")


def _reject_forbidden_name(path: Path) -> None:
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    if name in _FORBIDDEN_FILENAMES or suffix in _FORBIDDEN_SUFFIXES:
        raise DocumentError(f"forbidden executable, pickle, plugin, package, or archive file: {path.name}")


class _GGUFReader:
    """Small bounded reader for non-executing GGUF structural inspection."""

    def __init__(self, handle: BinaryIO, file_size: int) -> None:
        self.handle = handle
        self.file_size = file_size

    def tell(self) -> int:
        return self.handle.tell()

    def remaining(self) -> int:
        return self.file_size - self.tell()

    def read_exact(self, length: int, label: str) -> bytes:
        if length < 0 or length > self.remaining():
            raise DocumentError(f"truncated GGUF while reading {label}")
        value = self.handle.read(length)
        if len(value) != length:
            raise DocumentError(f"truncated GGUF while reading {label}")
        return value

    def skip_exact(self, length: int, label: str) -> None:
        if length < 0 or length > self.remaining():
            raise DocumentError(f"truncated GGUF while reading {label}")
        self.handle.seek(self.tell() + length)

    def uint32(self, label: str) -> int:
        return struct.unpack("<I", self.read_exact(4, label))[0]

    def uint64(self, label: str) -> int:
        return struct.unpack("<Q", self.read_exact(8, label))[0]

    def string(self, limit: int, label: str, *, ascii_only: bool = False) -> str:
        length = self.uint64(f"{label} length")
        if length > limit:
            raise DocumentError(f"GGUF {label} length {length} exceeds limit {limit}")
        raw = self.read_exact(length, label)
        encoding = "ascii" if ascii_only else "utf-8"
        try:
            return raw.decode(encoding, errors="strict")
        except UnicodeDecodeError as exc:
            raise DocumentError(f"GGUF {label} is not valid {encoding.upper()}") from exc


def _align_up(value: int, alignment: int) -> int:
    return value + (-value % alignment)


def _check_metadata_budget(reader: _GGUFReader, metadata_start: int) -> None:
    consumed = reader.tell() - metadata_start
    if consumed > _GGUF_MAX_METADATA_BYTES:
        raise DocumentError(
            f"GGUF metadata exceeds {_GGUF_MAX_METADATA_BYTES} byte inspection limit"
        )


def _check_bool_bytes(reader: _GGUFReader, length: int, label: str) -> None:
    remaining = length
    while remaining:
        chunk = reader.read_exact(min(remaining, _GGUF_PADDING_CHUNK), label)
        if any(value not in (0, 1) for value in chunk):
            raise DocumentError("GGUF boolean metadata must contain only 0 or 1")
        remaining -= len(chunk)


def _parse_gguf_value(
    reader: _GGUFReader,
    value_type: int,
    *,
    depth: int,
    total_array_elements: list[int],
    metadata_start: int,
) -> int | None:
    if value_type not in _GGUF_VALUE_TYPES:
        raise DocumentError(f"unsupported GGUF metadata value type {value_type}")

    scalar_size = _GGUF_SCALAR_SIZES.get(value_type)
    if scalar_size is not None:
        raw = reader.read_exact(scalar_size, "metadata scalar")
        if value_type == 7 and raw not in (b"\x00", b"\x01"):
            raise DocumentError("GGUF boolean metadata must be encoded as 0 or 1")
        _check_metadata_budget(reader, metadata_start)
        if value_type == 4:
            return struct.unpack("<I", raw)[0]
        return None

    if value_type == _GGUF_STRING:
        reader.string(_GGUF_MAX_STRING_BYTES, "metadata string")
        _check_metadata_budget(reader, metadata_start)
        return None

    if depth >= _GGUF_MAX_ARRAY_DEPTH:
        raise DocumentError(f"GGUF metadata array nesting exceeds depth {_GGUF_MAX_ARRAY_DEPTH}")
    element_type = reader.uint32("metadata array element type")
    if element_type not in _GGUF_VALUE_TYPES:
        raise DocumentError(f"unsupported GGUF metadata array element type {element_type}")
    length = reader.uint64("metadata array length")
    if length > _GGUF_MAX_ARRAY_ELEMENTS:
        raise DocumentError(
            f"GGUF metadata array length {length} exceeds limit {_GGUF_MAX_ARRAY_ELEMENTS}"
        )
    total_array_elements[0] += length
    if total_array_elements[0] > _GGUF_MAX_TOTAL_ARRAY_ELEMENTS:
        raise DocumentError(
            "GGUF metadata arrays exceed total element inspection limit "
            f"{_GGUF_MAX_TOTAL_ARRAY_ELEMENTS}"
        )

    element_size = _GGUF_SCALAR_SIZES.get(element_type)
    if element_size is not None:
        byte_count = length * element_size
        if element_type == 7:
            _check_bool_bytes(reader, byte_count, "metadata boolean array")
        else:
            reader.skip_exact(byte_count, "metadata scalar array")
        _check_metadata_budget(reader, metadata_start)
        return None

    for _ in range(length):
        _parse_gguf_value(
            reader,
            element_type,
            depth=depth + 1,
            total_array_elements=total_array_elements,
            metadata_start=metadata_start,
        )
    _check_metadata_budget(reader, metadata_start)
    return None


def _ggml_tensor_nbytes(dimensions: list[int], tensor_type: int, file_size: int) -> int:
    storage = _GGML_STORAGE.get(tensor_type)
    if storage is None:
        raise DocumentError(f"unsupported or removed GGML tensor type {tensor_type}")
    block_size, type_size = storage
    if dimensions[0] % block_size != 0:
        raise DocumentError(
            f"GGUF tensor first dimension is not divisible by block size {block_size} "
            f"for GGML type {tensor_type}"
        )

    byte_count = (dimensions[0] // block_size) * type_size
    for dimension in dimensions[1:]:
        if byte_count > file_size // dimension:
            raise DocumentError("GGUF tensor byte size exceeds artifact size")
        byte_count *= dimension
    if byte_count <= 0 or byte_count > file_size:
        raise DocumentError("GGUF tensor byte size exceeds artifact size")
    return byte_count


def _require_zero_bytes(handle: BinaryIO, start: int, end: int, label: str) -> None:
    handle.seek(start)
    remaining = end - start
    while remaining:
        chunk = handle.read(min(remaining, _GGUF_PADDING_CHUNK))
        if not chunk or any(chunk):
            raise DocumentError(f"GGUF {label} must contain only zero padding")
        remaining -= len(chunk)


def validate_gguf_structure(path: Path) -> None:
    """Validate a GGUF v2/v3 container without interpreting tensor contents."""

    file_size = path.stat().st_size
    with path.open("rb") as handle:
        reader = _GGUFReader(handle, file_size)
        if reader.read_exact(4, "magic") != b"GGUF":
            raise DocumentError("GGUF artifact does not start with GGUF magic")
        version = reader.uint32("version")
        if version not in {2, 3}:
            raise DocumentError(f"unsupported GGUF version {version}")

        tensor_count = reader.uint64("tensor count")
        metadata_count = reader.uint64("metadata count")
        if tensor_count > _GGUF_MAX_TENSOR_COUNT:
            raise DocumentError(
                f"GGUF tensor count {tensor_count} exceeds limit {_GGUF_MAX_TENSOR_COUNT}"
            )
        if metadata_count > _GGUF_MAX_METADATA_COUNT:
            raise DocumentError(
                f"GGUF metadata count {metadata_count} exceeds limit {_GGUF_MAX_METADATA_COUNT}"
            )

        metadata_start = reader.tell()
        total_array_elements = [0]
        metadata_keys: set[str] = set()
        alignment = 32
        for _ in range(metadata_count):
            key = reader.string(_GGUF_MAX_KEY_BYTES, "metadata key", ascii_only=True)
            if not _GGUF_KEY.fullmatch(key):
                raise DocumentError(f"GGUF metadata key is not canonical lower_snake_case: {key!r}")
            if key in metadata_keys:
                raise DocumentError(f"duplicate GGUF metadata key {key!r}")
            metadata_keys.add(key)
            value_type = reader.uint32("metadata value type")
            value = _parse_gguf_value(
                reader,
                value_type,
                depth=0,
                total_array_elements=total_array_elements,
                metadata_start=metadata_start,
            )
            if key == "general.alignment":
                if value_type != 4 or value is None:
                    raise DocumentError("GGUF general.alignment must be a UINT32 scalar")
                alignment = value
            _check_metadata_budget(reader, metadata_start)

        if alignment < 8 or alignment > _GGUF_MAX_ALIGNMENT or alignment & (alignment - 1):
            raise DocumentError(
                "GGUF alignment must be a power of two between 8 and "
                f"{_GGUF_MAX_ALIGNMENT}"
            )

        tensor_names: set[str] = set()
        expected_offset = 0
        padding_ranges: list[tuple[int, int]] = []
        for _ in range(tensor_count):
            name = reader.string(_GGUF_MAX_TENSOR_NAME_BYTES, "tensor name")
            if not name or "\x00" in name:
                raise DocumentError("GGUF tensor name must be non-empty and contain no NUL")
            if name in tensor_names:
                raise DocumentError(f"duplicate GGUF tensor name {name!r}")
            tensor_names.add(name)

            dimension_count = reader.uint32("tensor dimension count")
            if not 1 <= dimension_count <= 4:
                raise DocumentError("GGUF tensor dimension count must be between 1 and 4")
            dimensions = [
                reader.uint64(f"tensor dimension {index}")
                for index in range(dimension_count)
            ]
            if any(dimension == 0 or dimension > _GGUF_MAX_DIMENSION for dimension in dimensions):
                raise DocumentError("GGUF tensor dimensions must be between 1 and INT64_MAX")
            tensor_type = reader.uint32("tensor type")
            offset = reader.uint64("tensor offset")
            if offset % alignment:
                raise DocumentError(f"GGUF tensor offset {offset} is not aligned to {alignment}")
            if offset != expected_offset:
                raise DocumentError(
                    f"GGUF tensor offset {offset} is non-contiguous; expected {expected_offset}"
                )

            raw_size = _ggml_tensor_nbytes(dimensions, tensor_type, file_size)
            padded_size = _align_up(raw_size, alignment)
            if expected_offset > file_size - padded_size:
                raise DocumentError("GGUF tensor data ranges exceed artifact size")
            if padded_size > raw_size:
                padding_ranges.append((expected_offset + raw_size, expected_offset + padded_size))
            expected_offset += padded_size

        descriptor_end = reader.tell()
        if tensor_count == 0:
            if descriptor_end != file_size:
                raise DocumentError("GGUF has trailing bytes after a zero-tensor structure")
            return

        data_start = _align_up(descriptor_end, alignment)
        expected_file_size = data_start + expected_offset
        if data_start > file_size or expected_file_size > file_size:
            raise DocumentError("truncated GGUF tensor data section")
        if expected_file_size < file_size:
            raise DocumentError("GGUF has trailing bytes after the tensor data section")

        _require_zero_bytes(handle, descriptor_end, data_start, "metadata alignment padding")
        for relative_start, relative_end in padding_ranges:
            _require_zero_bytes(
                handle,
                data_start + relative_start,
                data_start + relative_end,
                "tensor alignment padding",
            )


def _inspect_magic(path: Path, artifact_format: str) -> None:
    with path.open("rb") as handle:
        head = handle.read(4096)
    executable_magic = (
        head.startswith(b"MZ"),
        head.startswith(b"\x7fELF"),
        head.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")),
        head.startswith(b"#!"),
        head.startswith(b"\x00asm"),
    )
    if any(executable_magic):
        raise DocumentError("artifact has executable or script magic")
    if head.startswith((b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!")):
        raise DocumentError("archive artifacts are forbidden")
    if len(head) >= 2 and head[0] == 0x80 and 0 <= head[1] <= 5:
        raise DocumentError("pickle-like artifact content is forbidden")
    if artifact_format != "gguf":
        raise DocumentError(f"unsupported artifact format {artifact_format!r}; v1 permits only gguf")
    validate_gguf_structure(path)


def _semver_tuple(value: str) -> tuple[int, int, int]:
    match = _SEMVER.fullmatch(value)
    if not match:
        raise PolicyError(f"invalid semantic version {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def check_candidate(manifest_path: Path | str, artifact_root: Path | str, repo_root: Path | str) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    manifest = validate_file(manifest_path, "manifest", root)
    if not isinstance(manifest, dict):
        raise DocumentError("manifest must be an object")
    policies = load_policy_bundle(root)
    _reject_remote_code_metadata(manifest)
    validate_license_binding(manifest_path, manifest["license"], root)

    upstream = manifest["upstream"]
    revision_pattern = policies["upstream"]["repository_identity"]["revision_pattern"]
    if not re.fullmatch(revision_pattern, upstream["revision"]):
        raise PolicyError("upstream revision is not an immutable digest")
    publisher_matches = [
        entry for entry in policies["upstream"]["allowed_publishers"]
        if re.fullmatch(entry["repository_pattern"], upstream["repository"])
    ]
    if len(publisher_matches) != 1:
        raise PolicyError("upstream repository is not exactly allowlisted")

    runtime = manifest["runtime"]
    runtime_matches = [
        entry for entry in policies["runtime"]["allowed_runtime_families"]
        if entry["runtime_id"] == runtime["runtime_id"] and entry["decision"] == "candidate_review_only"
    ]
    if len(runtime_matches) != 1:
        raise PolicyError("runtime is not approved")
    approved_runtime = runtime_matches[0]
    if runtime["api_contract"] != approved_runtime["api_contract"]:
        raise PolicyError("runtime API contract differs from allowlist")
    from .runtime import validate_model_runtime_reference

    validate_model_runtime_reference(manifest, root)

    artifact = manifest["artifact"]
    if artifact["format"] not in approved_runtime["artifact_formats"]:
        raise PolicyError("artifact format is not approved for the runtime")
    relative = validate_content_path(artifact["path"], artifact["sha256"])
    artifact_root_path = Path(artifact_root).resolve()
    target = (artifact_root_path / Path(*relative.parts)).resolve()
    if not _within(artifact_root_path, target):
        raise DocumentError("artifact resolves outside the staging root")
    _reject_symlink_components(artifact_root_path, target)
    if not target.is_file():
        raise DocumentError(f"artifact is missing or not a regular file: {relative.as_posix()}")
    _reject_forbidden_name(target)

    digest_dir = target.parent
    for child in digest_dir.iterdir():
        if child.is_symlink():
            raise DocumentError(f"symlink companion is forbidden: {child.name}")
        if child != target:
            raise DocumentError(f"unexpected companion file beside artifact: {child.name}")

    actual_size = target.stat().st_size
    if actual_size != artifact["size_bytes"]:
        raise DocumentError(f"artifact size mismatch: expected {artifact['size_bytes']}, got {actual_size}")
    actual_digest = sha256_file(target)
    if actual_digest != artifact["sha256"]:
        raise DocumentError(f"artifact digest mismatch: expected {artifact['sha256']}, got {actual_digest}")
    _inspect_magic(target, artifact["format"])

    license_data = manifest["license"]
    if license_data["redistribution_allowed"] is not True or license_data["commercial_use_allowed"] is not True:
        raise PolicyError("redistribution and commercial use must both be explicitly approved")
    if manifest["suggested_tasks_advisory"] is not True:
        raise PolicyError("suggested tasks must remain explicitly advisory")
    promotion = manifest["promotion"]
    if promotion["human_review_required"] is not True:
        raise PolicyError("promotion must require human review")

    return {
        "schema_version": 1,
        "model_id": manifest["model_id"],
        "release": manifest["release"],
        "artifact_sha256": actual_digest,
        "checks": {
            "schema": "pass",
            "policy": "pass",
            "upstream": "pass",
            "runtime": "pass",
            "license": "pass",
            "content_address": "pass",
            "static_format": "pass",
            "remote_code": "pass",
        },
        "executes_upstream_code": False,
    }
