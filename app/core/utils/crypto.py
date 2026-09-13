# ------------------------------------------------------------------------------------------------ #
# Copyright (c) 2026 Carmenda. All rights reserved.                                                #
# This program is distributed under the terms of the GNU General Public License: GPL-3.0-or-later  #
# ------------------------------------------------------------------------------------------------ #

"""Streaming XChaCha20-Poly1305 (libsodium secretstream) encryption for files and blobs at rest."""

from __future__ import annotations

import base64
import io
import struct
from pathlib import Path
from typing import IO, Any

import nacl.bindings as sodium
import nacl.exceptions

from main.config import settings

KEY_SIZE = sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES

MAGIC = b'CARM'
VERSION = 2
STREAM_HEADER_SIZE = sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES
HEADER_SIZE = len(MAGIC) + 1 + STREAM_HEADER_SIZE

CHUNK_SIZE = 1024 * 1024
CHUNK_LENGTH = struct.Struct('>I')

TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL


def _load_key() -> bytes:
    print('*** LOADING KEY ***')
    """Decode the raw key from settings."""
    encoded = settings.data_encryption_key.get_secret_value().strip()

    if not encoded:
        message = 'Encryption key is not set: cannot encrypt or decrypt data'
        raise ValueError(message)

    try:
        key = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    except ValueError as error:
        message = 'Encryption key is not valid url-safe base64'
        raise ValueError(message) from error

    if len(key) != KEY_SIZE:
        message = f'Encryption key must decode to {KEY_SIZE} bytes, got {len(key)}'
        raise ValueError(message)

    return key


class EncryptedWriter(io.RawIOBase):
    """Write-only binary stream that encrypts into ``raw`` chunk by chunk."""

    def __init__(self, raw: IO[bytes], *, close_raw: bool = True) -> None:
        """Wrap a writable binary stream."""
        super().__init__()
        self._raw = raw
        self._close_raw = close_raw
        self._state = sodium.crypto_secretstream_xchacha20poly1305_state()
        stream_header = sodium.crypto_secretstream_xchacha20poly1305_init_push(self._state, _load_key())
        self._buffer = bytearray()
        self._raw.write(MAGIC + bytes([VERSION]) + stream_header)

    def writable(self) -> bool:
        """Stream is writable."""
        return True

    def _seal(self, plaintext: bytes, *, final: bool) -> None:
        tag = TAG_FINAL if final else TAG_MESSAGE
        ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(self._state, plaintext, tag=tag)
        self._raw.write(CHUNK_LENGTH.pack(len(ciphertext)) + ciphertext)

    def write(self, data: Any) -> int:  # noqa: ANN401 (any bytes-like buffer)
        """Buffer plaintext and seal full chunks."""
        if self.closed:
            message = 'I/O operation on closed file'
            raise ValueError(message)

        view = memoryview(data).cast('B')
        self._buffer += view

        while len(self._buffer) >= CHUNK_SIZE:
            self._seal(bytes(self._buffer[:CHUNK_SIZE]), final=False)
            del self._buffer[:CHUNK_SIZE]

        return len(view)

    def flush(self) -> None:
        """Flush the underlying stream (buffered plaintext stays until close)."""
        if not self.closed:
            self._raw.flush()

    def close(self) -> None:
        """Seal the final chunk and close."""
        if self.closed:
            return

        try:
            self._seal(bytes(self._buffer), final=True)
            self._buffer.clear()
        finally:
            try:
                super().close()  # flushes the underlying stream first
            finally:
                if self._close_raw:
                    self._raw.close()


class EncryptedReader(io.RawIOBase):
    """Read-only binary stream that decrypts from ``raw`` chunk by chunk."""

    def __init__(self, raw: IO[bytes], *, close_raw: bool = True) -> None:
        """Wrap a readable binary stream positioned at the container header."""
        super().__init__()
        self._raw = raw
        self._close_raw = close_raw
        self._state = sodium.crypto_secretstream_xchacha20poly1305_state()
        self._buffer = bytearray()
        self._finished = False

        header = self._raw.read(HEADER_SIZE)
        if len(header) != HEADER_SIZE or header[: len(MAGIC)] != MAGIC:
            message = 'Not an encrypted container'
            raise ValueError(message)
        if header[len(MAGIC)] != VERSION:
            message = f'Unsupported container version {header[len(MAGIC)]}'
            raise ValueError(message)

        stream_header = header[len(MAGIC) + 1 :]
        sodium.crypto_secretstream_xchacha20poly1305_init_pull(self._state, stream_header, _load_key())

    def readable(self) -> bool:
        """Stream is readable."""
        return True

    def _read_exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            part = self._raw.read(size - len(data))
            if not part:
                break
            data += part
        return bytes(data)

    def _open_chunk(self) -> None:
        """Decrypt the next chunk into the buffer."""
        header = self._read_exact(CHUNK_LENGTH.size)
        if not header:
            message = 'Encrypted data is truncated: final chunk missing'
            raise ValueError(message)
        if len(header) != CHUNK_LENGTH.size:
            message = 'Encrypted data is truncated: incomplete chunk header'
            raise ValueError(message)

        (length,) = CHUNK_LENGTH.unpack(header)
        ciphertext = self._read_exact(length)
        if len(ciphertext) != length:
            message = 'Encrypted data is truncated: incomplete chunk'
            raise ValueError(message)

        try:
            plaintext, tag = sodium.crypto_secretstream_xchacha20poly1305_pull(self._state, ciphertext)
        except nacl.exceptions.CryptoError as error:
            message = 'Encrypted data is corrupt or was encrypted with another key'
            raise ValueError(message) from error

        self._buffer += plaintext
        self._finished = tag == TAG_FINAL

    def readinto(self, buffer: Any) -> int:  # noqa: ANN401 (any writable buffer)
        """Fill ``buffer`` with decrypted bytes, returning 0 at EOF."""
        if self.closed:
            message = 'I/O operation on closed file'
            raise ValueError(message)

        target = memoryview(buffer).cast('B')
        while not self._buffer and not self._finished:
            self._open_chunk()

        count = min(len(target), len(self._buffer))
        target[:count] = self._buffer[:count]
        del self._buffer[:count]
        return count

    def read(self, size: int | None = -1) -> bytes:
        """Read up to ``size`` decrypted bytes (all remaining when negative)."""
        if size is None or size < 0:
            while not self._finished:
                self._open_chunk()
            data = bytes(self._buffer)
            self._buffer.clear()
            return data

        result = bytearray(size)
        count = self.readinto(result)
        return bytes(result[:count])

    def close(self) -> None:
        """Close the underlying stream."""
        if self.closed:
            return
        try:
            super().close()
        finally:
            if self._close_raw:
                self._raw.close()


def encrypt_bytes(data: bytes) -> bytes:
    """Encrypt an in-memory blob."""
    sink = io.BytesIO()
    with EncryptedWriter(sink, close_raw=False) as writer:
        writer.write(data)
    return sink.getvalue()


def decrypt_bytes(data: bytes) -> bytes:
    """Decrypt an in-memory blob."""
    with EncryptedReader(io.BytesIO(data), close_raw=False) as reader:
        return reader.read()


def open_encrypted(path: str | Path, mode: str) -> IO[bytes]:
    """Open an encrypted file like ``open()``: modes ``rb`` and ``wb`` only."""
    if mode == 'rb':
        raw_in = Path(path).open('rb')  # noqa: SIM115 (ownership passes to the reader)
        try:
            return io.BufferedReader(EncryptedReader(raw_in))
        except Exception:
            raw_in.close()
            raise

    if mode == 'wb':
        raw_out = Path(path).open('wb')  # noqa: SIM115 (ownership passes to the writer)
        try:
            return io.BufferedWriter(EncryptedWriter(raw_out))
        except Exception:
            raw_out.close()
            raise

    message = f'Unsupported mode {mode!r}, only "rb" and "wb" are supported'
    raise ValueError(message)


def read_encrypted(path: str | Path) -> bytes:
    """Read and decrypt a whole file."""
    with open_encrypted(path, 'rb') as file:
        return file.read()


def write_encrypted(path: str | Path, data: bytes) -> None:
    """Encrypt and write a whole file."""
    with open_encrypted(path, 'wb') as file:
        file.write(data)
