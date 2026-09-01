from __future__ import annotations

from pathlib import Path
import struct

import pytest

from second_brain_models.candidate import validate_gguf_structure
from second_brain_models.errors import DocumentError


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _u64(len(encoded)) + encoded


def _header(tensors: int = 0, metadata: int = 0, *, version: int = 3) -> bytes:
    return b"GGUF" + _u32(version) + _u64(tensors) + _u64(metadata)


def _tensor(
    name: str = "weight",
    dimensions: tuple[int, ...] = (1,),
    tensor_type: int = 0,
    offset: int = 0,
) -> bytes:
    return (
        _string(name)
        + _u32(len(dimensions))
        + b"".join(_u64(dimension) for dimension in dimensions)
        + _u32(tensor_type)
        + _u64(offset)
    )


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


@pytest.mark.parametrize("version", [2, 3])
def test_small_zero_tensor_gguf_is_valid(tmp_path: Path, version: int) -> None:
    path = _write(tmp_path / f"empty-v{version}.gguf", _header(version=version))
    validate_gguf_structure(path)


def test_small_f32_tensor_with_zero_alignment_padding_is_valid(tmp_path: Path) -> None:
    raw = _header(tensors=1) + _tensor()
    raw += b"\0" * (-len(raw) % 32)
    raw += b"\x01\x02\x03\x04" + b"\0" * 28
    validate_gguf_structure(_write(tmp_path / "one.gguf", raw))


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (_header(tensors=250_001), "tensor count"),
        (_header(metadata=100_001), "metadata count"),
    ],
)
def test_absurd_header_counts_are_rejected(tmp_path: Path, raw: bytes, message: str) -> None:
    with pytest.raises(DocumentError, match=message):
        validate_gguf_structure(_write(tmp_path / "absurd.gguf", raw))


@pytest.mark.parametrize(
    "raw",
    [
        b"GGUF\x03",
        _header(metadata=1) + _u64(8) + b"short",
        _header(tensors=1) + _string("weight"),
    ],
)
def test_truncated_structures_are_rejected(tmp_path: Path, raw: bytes) -> None:
    with pytest.raises(DocumentError, match="truncated"):
        validate_gguf_structure(_write(tmp_path / "truncated.gguf", raw))


def test_absurd_metadata_array_length_is_rejected(tmp_path: Path) -> None:
    metadata = _string("test.values") + _u32(9) + _u32(0) + _u64(2_000_001)
    with pytest.raises(DocumentError, match="array length"):
        validate_gguf_structure(
            _write(tmp_path / "array.gguf", _header(metadata=1) + metadata)
        )


def test_excessive_metadata_array_nesting_is_rejected(tmp_path: Path) -> None:
    value = _u32(0) + _u64(0)
    for _ in range(9):
        value = _u32(9) + _u64(1) + value
    metadata = _string("test.nested") + _u32(9) + value
    with pytest.raises(DocumentError, match="nesting"):
        validate_gguf_structure(
            _write(tmp_path / "nested.gguf", _header(metadata=1) + metadata)
        )


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        (_tensor(dimensions=()), "dimension count"),
        (_tensor(dimensions=(1, 1, 1, 1, 1)), "dimension count"),
        (_tensor(dimensions=(0,)), "dimensions"),
        (_tensor(dimensions=(1 << 63,)), "dimensions"),
        (_tensor(dimensions=(31,), tensor_type=2), "block size"),
    ],
)
def test_hostile_tensor_dimensions_are_rejected(
    tmp_path: Path, descriptor: bytes, message: str
) -> None:
    with pytest.raises(DocumentError, match=message):
        validate_gguf_structure(
            _write(tmp_path / "dimensions.gguf", _header(tensors=1) + descriptor)
        )


@pytest.mark.parametrize(
    ("descriptor", "message"),
    [
        (_tensor(offset=1), "not aligned"),
        (_tensor(offset=32), "non-contiguous"),
        (_tensor(tensor_type=4), "unsupported or removed"),
        (_tensor(tensor_type=0, dimensions=(8,)), "data section"),
    ],
)
def test_bad_tensor_offsets_types_and_ranges_are_rejected(
    tmp_path: Path, descriptor: bytes, message: str
) -> None:
    raw = _header(tensors=1) + descriptor
    raw += b"\0" * (-len(raw) % 32)
    if message == "data section":
        raw += b"\0" * 4
    with pytest.raises(DocumentError, match=message):
        validate_gguf_structure(_write(tmp_path / "tensor.gguf", raw))


def test_nonzero_padding_and_trailing_bytes_are_rejected(tmp_path: Path) -> None:
    raw = _header(tensors=1) + _tensor()
    raw += b"\x01" + b"\0" * ((-len(raw) % 32) - 1)
    raw += b"\0" * 32
    with pytest.raises(DocumentError, match="metadata alignment padding"):
        validate_gguf_structure(_write(tmp_path / "padding.gguf", raw))

    with pytest.raises(DocumentError, match="trailing bytes"):
        validate_gguf_structure(
            _write(tmp_path / "trailing.gguf", _header() + b"unexpected")
        )
