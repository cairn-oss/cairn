from pathlib import Path

from cairn.terraform import discover_files, parse_file, parse_path


def test_parses_resources_with_lines(tmp_path: Path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "a" {\n  bucket = "x"\n}\n\n'
        'resource "aws_instance" "b" {\n  instance_type = "t3.micro"\n}\n'
    )
    parsed = parse_file(tmp_path / "main.tf")
    assert parsed.error is None
    assert [(r.type, r.name, r.line) for r in parsed.resources] == [
        ("aws_s3_bucket", "a", 1),
        ("aws_instance", "b", 5),
    ]
    # values are unquoted by normalization
    assert parsed.resources[0].body["bucket"] == "x"


def test_parse_error_is_reported_not_raised(tmp_path: Path):
    bad = tmp_path / "broken.tf"
    bad.write_text('resource "aws_s3_bucket" {{{ nope')
    parsed = parse_file(bad)
    assert parsed.resources == ()
    assert parsed.error is not None and "broken.tf" in parsed.error.file


def test_one_bad_file_does_not_abort_the_scan(tmp_path: Path):
    (tmp_path / "good.tf").write_text('resource "aws_s3_bucket" "a" {}\n')
    (tmp_path / "bad.tf").write_text("resource {{{{")
    result = parse_path(tmp_path)
    assert result.files_scanned == 2
    assert len(result.resources) == 1
    assert len(result.errors) == 1


def test_discovery_skips_vendored_dirs(tmp_path: Path):
    (tmp_path / "main.tf").write_text("")
    hidden = tmp_path / ".terraform" / "modules"
    hidden.mkdir(parents=True)
    (hidden / "mod.tf").write_text("")
    files = discover_files(tmp_path)
    assert [f.name for f in files] == ["main.tf"]


def test_discovery_single_file(tmp_path: Path):
    file = tmp_path / "solo.tf"
    file.write_text("")
    assert discover_files(file) == [file]


def test_non_terraform_noise_is_ignored(tmp_path: Path):
    (tmp_path / "readme.md").write_text("# not terraform")
    (tmp_path / "main.tf").write_text('variable "x" { type = string }\n')
    result = parse_path(tmp_path)
    assert result.files_scanned == 1
    assert result.resources == []  # variables are not resources
    assert result.errors == []


def test_oversized_file_is_skipped_and_reported(tmp_path: Path):
    from cairn import terraform

    big = tmp_path / "big.tf"
    big.write_text("# " + "x" * (terraform.MAX_FILE_BYTES + 10))
    parsed = parse_file(big)
    assert parsed.resources == ()
    assert parsed.error is not None and "skipped" in parsed.error.message


def test_directory_symlinks_are_not_followed(tmp_path: Path):
    import os

    import pytest

    if not hasattr(os, "symlink"):
        pytest.skip("no symlink support")
    real = tmp_path / "repo"
    real.mkdir()
    (real / "main.tf").write_text('resource "aws_s3_bucket" "a" {}\n')
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "other.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    try:
        (real / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted")
    files = discover_files(real)
    assert [f.name for f in files] == ["main.tf"]
