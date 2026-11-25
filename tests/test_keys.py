from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tamperlog.keys import KeyError_, generate, load_public_key, load_signing_key, public_hex


def test_generated_keys_round_trip_and_the_private_file_is_owner_only(tmp_path: Path) -> None:
    priv, pub = tmp_path / "a.key", tmp_path / "a.pub"
    key = generate(priv, pub)
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert public_hex(load_public_key(pub)) == public_hex(key)
    assert public_hex(load_signing_key(priv).public_key()) == public_hex(key)


def test_existing_key_files_are_never_overwritten(tmp_path: Path) -> None:
    priv, pub = tmp_path / "a.key", tmp_path / "a.pub"
    generate(priv, pub)
    with pytest.raises(FileExistsError):
        generate(priv, tmp_path / "b.pub")
    assert not (tmp_path / "b.pub").exists()


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o700 | 0o070])
def test_a_private_key_others_can_read_or_write_is_refused(tmp_path: Path, mode: int) -> None:
    priv = tmp_path / "a.key"
    generate(priv, tmp_path / "a.pub")
    os.chmod(priv, mode)
    with pytest.raises(KeyError_, match="chmod 600"):
        load_signing_key(priv)


def test_malformed_key_files_are_reported_clearly(tmp_path: Path) -> None:
    bad = tmp_path / "bad.pub"
    bad.write_text("not hex")
    with pytest.raises(KeyError_, match="not hexadecimal"):
        load_public_key(bad)
    bad.write_text("abcd")
    with pytest.raises(KeyError_, match="32 bytes"):
        load_public_key(bad)
    with pytest.raises(KeyError_, match="cannot read"):
        load_public_key(tmp_path / "missing.pub")
