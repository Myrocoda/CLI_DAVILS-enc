#!/usr/bin/env python3
import sys, io
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
"""
DAVILS Packaging Tool — Sprint 1
=================================
Encrypts a video file with AES-256-CTR and signs the output with HMAC-SHA256.

Usage:
    python package.py --input lesson1.mp4 --output lesson1.enc --key output_key.json

Header layout (128 bytes, fixed):
    [0:4]   Magic: b"DAVL"
    [4]     Version: 0x01
    [5:8]   Reserved (3 zero bytes)
    [8:12]  Chunk count (uint32 LE)
    [12:16] Chunk size in bytes (uint32 LE)
    [16:24] Total plaintext size (uint64 LE)
    [24:40] AES-CTR nonce (16 bytes, random)
    [40:72] HMAC-SHA256 (32 bytes) over header[0:40] || ciphertext
    [72:128] Reserved / zero-padded

AES-CTR preserves plaintext length, so:
    output size = input size + 128 bytes (header only)
"""

import argparse
import hashlib
import hmac
import json
import math
import os
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Constants ────────────────────────────────────────────────────────────────

MAGIC           = b"DAVL"
VERSION         = 0x01
HEADER_SIZE     = 128          # bytes, fixed forever
CHUNK_SIZE      = 1_048_576   # 1 MiB — seek granularity for Android DataSource
STREAM_CHUNK    = 4 * 1_048_576  # 4 MiB read/write buffer


# ── Key helpers ───────────────────────────────────────────────────────────────

def load_or_create_key(key_path: str) -> dict:
    """
    Load keys from key_path if it exists, otherwise generate fresh ones
    and write them to key_path.  Returns a dict with 'file_key_hex' and
    'hmac_key_hex'.
    """
    if os.path.exists(key_path):
        with open(key_path, "r") as f:
            keys = json.load(f)
        # Validate
        file_key = bytes.fromhex(keys["file_key_hex"])
        hmac_key = bytes.fromhex(keys["hmac_key_hex"])
        if len(file_key) != 32:
            sys.exit(f"[ERROR] file_key in {key_path} must be 32 bytes (AES-256)")
        if len(hmac_key) != 32:
            sys.exit(f"[ERROR] hmac_key in {key_path} must be 32 bytes")
        print(f"[key]  Loaded existing keys from: {key_path}")
    else:
        file_key = os.urandom(32)
        hmac_key = os.urandom(32)
        keys = {
            "file_key_hex":  file_key.hex(),
            "hmac_key_hex":  hmac_key.hex(),
            "file_key_b64":  __import__("base64").b64encode(file_key).decode(),
            "hmac_key_b64":  __import__("base64").b64encode(hmac_key).decode(),
            "_note": "Sprint 1: hardcoded keys. Replace with Android Keystore in Sprint 2."
        }
        with open(key_path, "w") as f:
            json.dump(keys, f, indent=2)
        print(f"[key]  Generated fresh keys → {key_path}")

    return {
        "file_key": bytes.fromhex(keys["file_key_hex"]),
        "hmac_key": bytes.fromhex(keys["hmac_key_hex"]),
    }


# ── Core encrypt ─────────────────────────────────────────────────────────────

def encrypt_file(input_path: str, output_path: str, key_path: str) -> None:
    """Main encryption routine."""

    # ── 1. Validate input ───────────────────────────────────────────────────
    if not os.path.isfile(input_path):
        sys.exit(f"[ERROR] Input file not found: {input_path}")

    plaintext_size = os.path.getsize(input_path)
    chunk_count    = math.ceil(plaintext_size / CHUNK_SIZE) if plaintext_size > 0 else 1

    print(f"\n{'='*60}")
    print(f"  DAVILS Packaging Tool -- Sprint 1")
    print(f"{'='*60}")
    print(f"  Input : {input_path}")
    print(f"  Output: {output_path}")
    print(f"  Key   : {key_path}")
    print(f"{'-'*60}")
    print(f"  Plaintext size : {plaintext_size:>15,} bytes")
    print(f"  Chunk size     : {CHUNK_SIZE:>15,} bytes (1 MiB)")
    print(f"  Chunk count    : {chunk_count:>15,}")
    print(f"{'-'*60}\n")

    # ── 2. Load / generate keys ─────────────────────────────────────────────
    keys     = load_or_create_key(key_path)
    file_key = keys["file_key"]
    hmac_key = keys["hmac_key"]

    # ── 3. Build header prefix (bytes 0–39, 40 bytes) ───────────────────────
    nonce = os.urandom(16)

    header_prefix = (
        MAGIC
        + struct.pack("<B",  VERSION)
        + b"\x00" * 3                          # reserved
        + struct.pack("<I",  chunk_count)      # uint32 LE
        + struct.pack("<I",  CHUNK_SIZE)       # uint32 LE
        + struct.pack("<Q",  plaintext_size)   # uint64 LE
        + nonce                                # 16 bytes
    )
    assert len(header_prefix) == 40, f"Header prefix must be 40 bytes, got {len(header_prefix)}"

    # ── 4. Encrypt payload and accumulate HMAC ──────────────────────────────
    print("[enc]  Encrypting …", end="", flush=True)
    t0 = time.perf_counter()

    cipher    = Cipher(algorithms.AES(file_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    mac       = hmac.new(hmac_key, header_prefix, hashlib.sha256)

    # Write to a temp file so we can splice in the HMAC once known
    tmp_path = output_path + ".tmp"
    try:
        with open(input_path, "rb") as fin, open(tmp_path, "wb") as ftmp:
            # Reserve space for header
            ftmp.write(b"\x00" * HEADER_SIZE)

            processed = 0
            while True:
                chunk = fin.read(STREAM_CHUNK)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                mac.update(ct)
                ftmp.write(ct)
                processed += len(chunk)
                pct = processed / plaintext_size * 100 if plaintext_size else 100
                print(f"\r[enc]  Encrypting … {pct:5.1f}%", end="", flush=True)

            ct_tail = encryptor.finalize()
            if ct_tail:
                mac.update(ct_tail)
                ftmp.write(ct_tail)

        elapsed = time.perf_counter() - t0
        print(f"\r[enc]  Encrypted in {elapsed:.2f}s ({plaintext_size / 1e6 / elapsed:.1f} MB/s)  ")

        # ── 5. Finalise HMAC and write full header ──────────────────────────
        hmac_digest = mac.digest()   # 32 bytes
        assert len(hmac_digest) == 32

        header = (
            header_prefix        # 40 bytes
            + hmac_digest        # 32 bytes  → total 72
            + b"\x00" * 56      # padding   → total 128
        )
        assert len(header) == HEADER_SIZE, f"Header must be {HEADER_SIZE} bytes, got {len(header)}"

        # Splice header into position 0 of the temp file
        with open(tmp_path, "r+b") as ftmp:
            ftmp.seek(0)
            ftmp.write(header)

        # Rename to final output
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(tmp_path, output_path)

    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    # ── 6. Size comparison ───────────────────────────────────────────────────
    output_size = os.path.getsize(output_path)
    delta       = output_size - plaintext_size

    print(f"\n{'='*60}")
    print(f"  Input : {os.path.basename(input_path):<30s} {plaintext_size:>15,} bytes")
    print(f"  Output: {os.path.basename(output_path):<30s} {output_size:>15,} bytes")
    if delta >= 0:
        print(f"  Difference: +{delta} bytes", end="")
    else:
        print(f"  Difference: {delta} bytes", end="")

    if delta == HEADER_SIZE:
        print(f" (header only -- PASS)")
    else:
        print(f" <- UNEXPECTED -- expected +{HEADER_SIZE}")

    print(f"{'='*60}")

    # Hard stop if delta is too large
    if abs(delta - HEADER_SIZE) > 200:
        sys.exit(
            f"\n[FATAL] Size delta is {delta} bytes; expected exactly {HEADER_SIZE}. "
            "Something is wrong. Fix before handing off."
        )

    if delta != HEADER_SIZE:
        print(
            f"[WARN]  Delta is {delta}, not exactly {HEADER_SIZE}. "
            "Check for filesystem block-size rounding."
        )

    print(f"\n[done] Output written to: {output_path}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DAVILS — AES-256-CTR video packager (Sprint 1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input",  required=True, help="Path to source .mp4 file")
    parser.add_argument("--output", required=True, help="Path to output .enc file")
    parser.add_argument("--key",    required=True, help="Path to key JSON (created if absent)")
    args = parser.parse_args()

    encrypt_file(args.input, args.output, args.key)


if __name__ == "__main__":
    main()
