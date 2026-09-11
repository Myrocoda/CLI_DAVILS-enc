#!/usr/bin/env python3
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
"""
DAVILS Verifier -- Sprint 1
============================
Decrypts a .enc file, verifies the HMAC-SHA256, and optionally checks that the
decrypted bytes exactly match the original plaintext.

Usage:
    python verify.py --input lesson1.enc --key output_key.json [--original lesson1.mp4]

Exit codes:
    0  -- HMAC OK (and byte-match OK if --original supplied)
    1  -- HMAC FAIL or other error
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HEADER_SIZE  = 128
STREAM_CHUNK = 4 * 1_048_576


def verify_file(enc_path: str, key_path: str, original_path: str | None) -> bool:
    if not os.path.isfile(enc_path):
        sys.exit(f"[ERROR] Encrypted file not found: {enc_path}")
    if not os.path.isfile(key_path):
        sys.exit(f"[ERROR] Key file not found: {key_path}")

    print(f"\n{'='*60}")
    print(f"  DAVILS Verifier -- Sprint 1")
    print(f"{'='*60}")

    # -- Load keys
    with open(key_path, "r") as f:
        keys = json.load(f)
    file_key = bytes.fromhex(keys["file_key_hex"])
    hmac_key = bytes.fromhex(keys["hmac_key_hex"])

    # -- Read header
    with open(enc_path, "rb") as f:
        header = f.read(HEADER_SIZE)

    if len(header) < HEADER_SIZE:
        sys.exit(f"[ERROR] File too short to contain full header ({len(header)} < {HEADER_SIZE})")

    magic         = header[0:4]
    version       = header[4]
    chunk_count   = struct.unpack_from("<I", header,  8)[0]
    chunk_size    = struct.unpack_from("<I", header, 12)[0]
    plaintext_sz  = struct.unpack_from("<Q", header, 16)[0]
    nonce         = header[24:40]
    stored_hmac   = header[40:72]
    header_prefix = header[0:40]

    print(f"  Magic        : {magic}")
    print(f"  Version      : 0x{version:02X}")
    print(f"  Chunk count  : {chunk_count:,}")
    print(f"  Chunk size   : {chunk_size:,} bytes")
    print(f"  Plaintext sz : {plaintext_sz:,} bytes")
    print(f"  Nonce        : {nonce.hex()}")
    print(f"  Stored HMAC  : {stored_hmac.hex()}")
    print(f"{'='*60}")

    if magic != b"DAVL":
        sys.exit(f"[ERROR] Bad magic: {magic!r} -- not a DAVL file")

    # -- Stream decrypt + recompute HMAC
    print("[verify] Streaming decrypt + HMAC recompute ...", end="", flush=True)
    t0 = time.perf_counter()

    cipher    = Cipher(algorithms.AES(file_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    mac       = hmac.new(hmac_key, header_prefix, hashlib.sha256)

    enc_size   = os.path.getsize(enc_path)
    ct_size    = enc_size - HEADER_SIZE
    processed  = 0
    plaintext_chunks = []

    with open(enc_path, "rb") as f:
        f.seek(HEADER_SIZE)
        while True:
            chunk = f.read(STREAM_CHUNK)
            if not chunk:
                break
            mac.update(chunk)
            pt = decryptor.update(chunk)
            plaintext_chunks.append(pt)
            processed += len(chunk)
            pct = processed / ct_size * 100 if ct_size else 100
            print(f"\r[verify] Streaming decrypt + HMAC recompute ... {pct:5.1f}%", end="", flush=True)

    pt_tail = decryptor.finalize()
    if pt_tail:
        plaintext_chunks.append(pt_tail)

    elapsed = time.perf_counter() - t0
    print(f"\r[verify] Done in {elapsed:.2f}s ({ct_size / 1e6 / elapsed:.1f} MB/s)      ")

    # -- HMAC check
    computed_hmac = mac.digest()
    hmac_ok = hmac.compare_digest(computed_hmac, stored_hmac)

    if hmac_ok:
        print(f"[HMAC]  PASS -- digests match")
    else:
        print(f"[HMAC]  FAIL")
        print(f"        Stored  : {stored_hmac.hex()}")
        print(f"        Computed: {computed_hmac.hex()}")

    # -- Optional byte-match against original
    byte_match_ok = True
    if original_path:
        if not os.path.isfile(original_path):
            print(f"[WARN]  Original file not found: {original_path} -- skipping byte match")
        else:
            print(f"[match] Comparing with original: {original_path} ...", end="", flush=True)
            decrypted = b"".join(plaintext_chunks)
            with open(original_path, "rb") as f:
                original = f.read()
            if decrypted == original:
                print(f"\r[match] PASS -- decrypted bytes exactly match original ({len(original):,} bytes)    ")
            else:
                print(f"\r[match] FAIL -- mismatch (decrypted={len(decrypted):,}, original={len(original):,})")
                byte_match_ok = False

    print(f"{'='*60}\n")

    return hmac_ok and byte_match_ok


def main():
    parser = argparse.ArgumentParser(
        description="DAVILS -- .enc verifier (Sprint 1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--input",    required=True, help="Path to .enc file")
    parser.add_argument("--key",      required=True, help="Path to key JSON")
    parser.add_argument("--original", default=None,  help="Original plaintext file for byte-match check")
    args = parser.parse_args()

    ok = verify_file(args.input, args.key, args.original)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
