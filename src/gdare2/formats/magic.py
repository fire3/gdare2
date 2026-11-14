"""Small deterministic magic-signature scanner used by ``iT``/``/m``/``Cm``."""

from __future__ import annotations

SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit little-endian"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little-endian"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip compressed data"),
    (b"BZh", "bzip2 compressed data"),
    (b"\xfd7zXZ\x00", "XZ compressed data"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"%PDF-", "PDF document"),
    (b"SQLite format 3\x00", "SQLite database"),
)

CRYPTO_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"-----BEGIN RSA PRIVATE KEY-----", "PEM RSA private key"),
    (b"-----BEGIN PRIVATE KEY-----", "PEM private key"),
    (b"-----BEGIN CERTIFICATE-----", "PEM certificate"),
    (b"-----BEGIN PUBLIC KEY-----", "PEM public key"),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key"),
    (b"ssh-rsa", "OpenSSH RSA public key"),
    (b"\x30\x82", "ASN.1 DER sequence"),
)


def scan(data: bytes, *, crypto: bool = False, limit: int = 4096) -> list[dict]:
    signatures = CRYPTO_SIGNATURES if crypto else SIGNATURES
    hits: list[dict] = []
    for offset in range(len(data)):
        for magic, name in signatures:
            if data.startswith(magic, offset):
                hits.append({"offset": offset, "name": name})
                if len(hits) >= limit:
                    return hits
                break
    return hits
