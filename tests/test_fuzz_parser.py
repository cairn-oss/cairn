"""Property-based fuzzing of the parser's untrusted-input contract.

``parse_file`` promises to never raise on hostile input (see SECURITY.md).
These tests feed random unicode, HCL-shaped token soup, and arbitrary bytes,
then assert the promise holds: a result is always returned, and malformed
input yields a *contained* error with no partial resources.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from cairn.terraform import FileParse, parse_file

_UNICODE = st.text(
    alphabet=st.characters(min_codepoint=1, max_codepoint=0x2FFF), max_size=400
)
_HCL_TOKENS = st.lists(
    st.sampled_from(
        [
            "resource", '"aws_s3_bucket"', '"n"', "{", "}", "=", "[", "]",
            "true", "false", "0.0.0.0/0", '"gp2"', "\n", "encrypted",
            "deletion_protection", "#", "cairn:ignore", "COST002", "reason=x",
        ]
    ),
    max_size=80,
).map(" ".join)
_BINARY = st.binary(max_size=400).map(lambda raw: raw.decode("utf-8", "replace"))


def _parse(src: str) -> FileParse:
    fd, name = tempfile.mkstemp(suffix=".tf")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(src)
        return parse_file(Path(name))
    finally:
        os.unlink(name)


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.one_of(_UNICODE, _HCL_TOKENS, _BINARY))
def test_parse_file_never_raises_on_hostile_input(src: str) -> None:
    result = _parse(src)
    assert isinstance(result, FileParse)
    if result.error is not None:
        assert result.resources == ()


@settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_HCL_TOKENS)
def test_parsed_resources_are_well_formed(src: str) -> None:
    for resource in _parse(src).resources:
        assert isinstance(resource.type, str) and resource.type
        assert isinstance(resource.name, str) and resource.name
        assert isinstance(resource.body, dict)
