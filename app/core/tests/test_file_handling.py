# ------------------------------------------------------------------------------------------------ #
# Copyright (c) 2026 Carmenda. All rights reserved.                                                #
# This program is distributed under the terms of the GNU General Public License: GPL-3.0-or-later  #
# ------------------------------------------------------------------------------------------------ #

"""Tests for file handling utilities."""

from __future__ import annotations

import logging
from pathlib import Path

import polars as pl

import pytest
from core.utils.crypto import MAGIC, read_encrypted, write_encrypted
from core.utils.file_handling import load_datafile, load_datakey, save_datafile, save_datakey
from core.utils.progress_tracker import ProgressTracker

# ----------------------------------- FIXTURES ------------------------------------ #


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    """Create output directory."""
    out = tmp_path / 'output'
    out.mkdir(parents=True, exist_ok=True)
    return out


# ------------------------------ SAVE DATAFILE TESTS ------------------------------ #


class TestSaveDatafile:
    """Tests for save_datafile function."""

    def test_saves_with_deidentified_suffix(self, tmp_path: Path) -> None:
        """Output file is created with _pseudonymised suffix."""
        df = pl.DataFrame({'name': ['Alice', 'Bob'], 'age': [30, 25]})
        output_folder = tmp_path / 'output'

        save_datafile(df, 'test.csv', str(output_folder))

        saved = output_folder / 'test_pseudonymised.csv'
        assert saved.exists()
        assert saved.read_bytes().startswith(MAGIC)
        assert b'Alice' not in saved.read_bytes()

        result = pl.read_csv(read_encrypted(saved))
        assert result['name'].to_list() == ['Alice', 'Bob']

    def test_creates_output_folder(self, tmp_path: Path) -> None:
        """Output folder is created if it doesn't exist."""
        df = pl.DataFrame({'name': ['Alice']})
        output_folder = tmp_path / 'new_folder' / 'subfolder'

        assert not output_folder.exists()
        save_datafile(df, 'test.csv', str(output_folder))

        assert (output_folder / 'test_pseudonymised.csv').exists()

    def test_ignores_parent_writes_flat_into_output(self, tmp_path: Path) -> None:
        """Filename with a parent path is written flat into the output folder, ignoring the parent."""
        df = pl.DataFrame({'name': ['Alice']})

        save_datafile(df, 'job123/data.csv', str(tmp_path / 'output'))

        assert (tmp_path / 'output' / 'data_pseudonymised.csv').exists()
        assert not (tmp_path / 'output' / 'job123').exists()

    def test_oserror_logs_warning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """OSError is caught and logged as warning."""
        df = pl.DataFrame({'name': ['Alice']})

        def mock_mkdir(_self: Path, *_args: object, **_kwargs: object) -> None:
            raise OSError

        monkeypatch.setattr(Path, 'mkdir', mock_mkdir)

        with caplog.at_level(logging.WARNING):
            save_datafile(df, 'test.csv', str(tmp_path / 'output'))

        assert 'Cannot write' in caplog.text


# ------------------------------- SAVE DATAKEY TESTS ------------------------------- #


class TestSaveDatakey:
    """Tests for save_datakey function."""

    def test_saves_with_dutch_columns(self, tmp_path: Path) -> None:
        """Datakey is saved with Dutch column names and comma delimiter."""
        df = pl.DataFrame({'clientname': ['Jan'], 'synonyms': ['J'], 'code': ['C001']})

        save_datakey(df, 'test.csv', str(tmp_path))

        raw = (tmp_path / 'test_key.csv').read_bytes()
        assert raw.startswith(MAGIC)
        assert b'Jan' not in raw

        content = read_encrypted(tmp_path / 'test_key.csv').decode('utf-8')
        assert 'Clientnaam,Synoniemen,Code' in content
        assert 'Jan,J,C001' in content

    def test_custom_datakey_name(self, tmp_path: Path) -> None:
        """Custom key_name is used as output filename."""
        df = pl.DataFrame({'clientname': ['Jan'], 'synonyms': ['J'], 'code': ['C001']})

        save_datakey(df, 'test.csv', str(tmp_path), key_name='custom.csv')

        assert (tmp_path / 'custom.csv').exists()
        assert not (tmp_path / 'test_key.csv').exists()

    def test_oserror_logs_warning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """OSError is caught and logged as warning."""
        df = pl.DataFrame({'clientname': ['Jan'], 'synonyms': ['J'], 'code': ['C001']})

        def mock_write(*_args: object, **_kwargs: object) -> None:
            raise OSError

        monkeypatch.setattr(pl.DataFrame, 'write_csv', mock_write)

        with caplog.at_level(logging.WARNING):
            save_datakey(df, 'test.csv', str(tmp_path))

        assert 'Cannot write datakey' in caplog.text


# --------------------------------- LOAD TESTS ---------------------------------- #


class TestLoadEncrypted:
    """Inputs are read from encrypted containers and decrypted in memory only."""

    def test_load_datafile_csv(self, tmp_path: Path) -> None:
        """An encrypted CSV input is loaded into a DataFrame."""
        source = tmp_path / 'input.csv'
        write_encrypted(source, b'name,report\nAlice,visited\nBob,discharged\n')

        df = load_datafile(str(source), ProgressTracker())

        assert df is not None
        assert df['name'].to_list() == ['Alice', 'Bob']

    def test_load_datafile_missing(self, tmp_path: Path) -> None:
        """A missing input returns None."""
        assert load_datafile(str(tmp_path / 'missing.csv'), ProgressTracker()) is None

    def test_load_datakey(self, tmp_path: Path) -> None:
        """An encrypted datakey is loaded with normalised column names."""
        source = tmp_path / 'key.csv'
        write_encrypted(source, b'Clientnaam,Synoniemen,Code\nJan Jansen,Jantje,C001\n ,x,C002\n')

        df = load_datakey(str(source))

        assert df is not None
        assert df.columns == ['clientname', 'synonyms', 'code']
        assert df['clientname'].to_list() == ['Jan Jansen']

    def test_roundtrip_through_save_and_load(self, tmp_path: Path) -> None:
        """What save_datakey writes, load_datakey reads back."""
        df = pl.DataFrame({'clientname': ['Jan'], 'synonyms': ['J'], 'code': ['C001']})
        save_datakey(df, 'test.csv', str(tmp_path))

        loaded = load_datakey(str(tmp_path / 'test_key.csv'))

        assert loaded is not None
        assert loaded.to_dicts() == [{'clientname': 'Jan', 'synonyms': 'J', 'code': 'C001'}]
