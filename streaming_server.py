#!/usr/bin/env python3
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
"""
DAVILS Local Streaming Server -- Sprint 1 Playback Test
=========================================================
Mirrors the exact protocol the Android DataSource will implement:

  1. Read 128-byte header from .enc file
  2. Verify HMAC-SHA256 (header[0:40] || ciphertext)
  3. Serve decrypted video bytes over HTTP with full Range request support
  4. AES-CTR seeking: any byte offset maps to the correct CTR block

Open in VLC, mpv, or any browser:
    http://localhost:8080/lesson1

Seeking works because AES-CTR is a stream cipher with random-access:
    ciphertext_offset = 128 + plaintext_offset
    ctr_block         = int(nonce) + plaintext_offset // 16
    skip_bytes        = plaintext_offset % 16

Usage:
    python streaming_server.py [--port 8080] [--layout hdd_layout/valid]
                               [--key output_key.json] [--no-hmac-verify]

Args:
    --port          Port to listen on (default: 8080)
    --layout        Path to HDD layout variant (default: hdd_layout/valid)
    --key           Override key file (default: reads from layout/license/license.json)
    --no-hmac-verify  Skip full HMAC pre-verification (faster start, less safe)
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import struct
import threading
import time
import urllib.parse

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Constants (must match package.py) ────────────────────────────────────────
HEADER_SIZE  = 128
READ_CHUNK   = 256 * 1024    # 256 KB per HTTP read — balance latency vs syscalls

# ── Global state ─────────────────────────────────────────────────────────────
_config = {}   # populated in main()


# ── CTR seek helper ──────────────────────────────────────────────────────────

def make_seek_cipher(file_key: bytes, nonce: bytes, plaintext_offset: int):
    """
    Return (cipher_encryptor, skip_bytes) for seeking to plaintext_offset.

    AES-CTR with a 128-bit nonce/counter:
      - Each 16-byte block uses counter = int(nonce_be) + block_index
      - To seek to byte N: block_index = N // 16, skip = N % 16
      - We re-construct the nonce for that block, init a fresh cipher,
        then discard the first `skip` bytes of its output.
    """
    block_index  = plaintext_offset // 16
    skip_bytes   = plaintext_offset % 16

    nonce_int    = int.from_bytes(nonce, 'big')
    seek_counter = (nonce_int + block_index) & ((1 << 128) - 1)
    seek_nonce   = seek_counter.to_bytes(16, 'big')

    cipher = Cipher(algorithms.AES(file_key), modes.CTR(seek_nonce))
    return cipher.encryptor(), skip_bytes


# ── Header parser ─────────────────────────────────────────────────────────────

def parse_header(header: bytes) -> dict:
    if header[0:4] != b"DAVL":
        raise ValueError(f"Bad magic: {header[0:4]!r}")
    version      = header[4]
    chunk_count  = struct.unpack_from("<I", header,  8)[0]
    chunk_size   = struct.unpack_from("<I", header, 12)[0]
    plaintext_sz = struct.unpack_from("<Q", header, 16)[0]
    nonce        = header[24:40]
    stored_hmac  = header[40:72]
    return {
        "version":      version,
        "chunk_count":  chunk_count,
        "chunk_size":   chunk_size,
        "plaintext_sz": plaintext_sz,
        "nonce":        nonce,
        "stored_hmac":  stored_hmac,
        "header_prefix": header[0:40],
    }


# ── HMAC verifier ─────────────────────────────────────────────────────────────

def verify_hmac(enc_path: str, hmac_key: bytes, header_prefix: bytes,
                stored_hmac: bytes) -> bool:
    """Full streaming HMAC verification. Returns True if valid."""
    mac = hmac.new(hmac_key, header_prefix, hashlib.sha256)
    enc_size = os.path.getsize(enc_path)
    processed = 0
    ct_size   = enc_size - HEADER_SIZE

    print(f"  [hmac] Verifying HMAC for {os.path.basename(enc_path)} ({ct_size / 1e6:.0f} MB)...",
          end="", flush=True)
    t0 = time.perf_counter()

    with open(enc_path, "rb") as f:
        f.seek(HEADER_SIZE)
        while True:
            chunk = f.read(READ_CHUNK)
            if not chunk:
                break
            mac.update(chunk)
            processed += len(chunk)
            pct = processed / ct_size * 100 if ct_size else 100
            print(f"\r  [hmac] Verifying {os.path.basename(enc_path)} ... {pct:5.1f}%",
                  end="", flush=True)

    elapsed = time.perf_counter() - t0
    ok = hmac.compare_digest(mac.digest(), stored_hmac)
    status = "PASS" if ok else "FAIL"
    print(f"\r  [hmac] {os.path.basename(enc_path)} -- {status} ({elapsed:.1f}s)          ")
    return ok


# ── HTTP Request Handler ──────────────────────────────────────────────────────

class DAVILSHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        # Cleaner logging
        print(f"  [http] {self.address_string()} -- {fmt % args}")

    def do_GET(self):
        self._serve(send_body=True)

    def do_HEAD(self):
        self._serve(send_body=False)

    def _serve(self, send_body: bool):
        # Parse URL: /lesson1  or  /lesson1.enc  or  /content/lesson1.enc
        path = urllib.parse.unquote(self.path.lstrip("/").split("?")[0])

        # Normalise: strip leading "content/"
        if path.startswith("content/"):
            path = path[len("content/"):]

        # Add .enc if missing
        if not path.endswith(".enc"):
            path += ".enc"

        enc_path = os.path.join(_config["content_dir"], path)

        if not os.path.isfile(enc_path):
            self.send_error(404, f"Not found: {path}")
            return

        keys     = _config["keys"]
        file_key = keys["file_key"]
        hmac_key = keys["hmac_key"]

        # ── Read & parse header ──────────────────────────────────────────────
        try:
            with open(enc_path, "rb") as f:
                raw_header = f.read(HEADER_SIZE)
            h = parse_header(raw_header)
        except Exception as e:
            self.send_error(400, f"Header parse error: {e}")
            return

        plaintext_sz = h["plaintext_sz"]

        # ── HMAC verification ────────────────────────────────────────────────
        if _config.get("verify_hmac"):
            ok = verify_hmac(enc_path, hmac_key, h["header_prefix"], h["stored_hmac"])
            if not ok:
                self.send_error(403, "HMAC verification FAILED -- file tampered or wrong key")
                return

        # ── Parse Range header ───────────────────────────────────────────────
        range_header = self.headers.get("Range", "")
        start = 0
        end   = plaintext_sz - 1   # inclusive

        partial = False
        if range_header.startswith("bytes="):
            partial = True
            rng = range_header[6:].split("-")
            try:
                if rng[0]:
                    start = int(rng[0])
                if rng[1]:
                    end = int(rng[1])
                else:
                    end = plaintext_sz - 1
            except (ValueError, IndexError):
                self.send_error(400, "Bad Range header")
                return

            # Clamp
            start = max(0, min(start, plaintext_sz - 1))
            end   = max(start, min(end,   plaintext_sz - 1))

        length = end - start + 1

        # ── Send HTTP headers ────────────────────────────────────────────────
        if partial:
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{plaintext_sz}")
        else:
            self.send_response(200)

        self.send_header("Content-Type",   "video/mp4")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges",  "bytes")
        self.send_header("Cache-Control",  "no-cache")
        # Expose filename for players
        basename = path.replace(".enc", ".mp4")
        self.send_header("Content-Disposition", f'inline; filename="{basename}"')
        self.end_headers()

        if not send_body:
            return

        # ── Stream decrypted bytes ───────────────────────────────────────────
        print(f"  [stream] {path} bytes={start}-{end} ({length / 1e6:.1f} MB)")

        try:
            encryptor, skip_bytes = make_seek_cipher(file_key, h["nonce"], start)

            with open(enc_path, "rb") as f:
                # Seek in the ciphertext file to the right block
                file_seek = HEADER_SIZE + (start - skip_bytes)
                f.seek(file_seek)

                remaining  = length
                first_read = True

                while remaining > 0:
                    to_read = min(READ_CHUNK + (skip_bytes if first_read else 0), remaining + (skip_bytes if first_read else 0))
                    ct_chunk = f.read(to_read)
                    if not ct_chunk:
                        break

                    pt_chunk = encryptor.update(ct_chunk)

                    if first_read and skip_bytes:
                        pt_chunk  = pt_chunk[skip_bytes:]
                        first_read = False

                    # Clamp to remaining bytes
                    if len(pt_chunk) > remaining:
                        pt_chunk = pt_chunk[:remaining]

                    self.wfile.write(pt_chunk)
                    remaining -= len(pt_chunk)

        except (BrokenPipeError, ConnectionResetError):
            # Client seeked away -- normal for video players
            pass
        except Exception as e:
            print(f"  [error] Stream error: {e}")


# ── Key loader ────────────────────────────────────────────────────────────────

def load_keys(layout_dir: str, key_override: str | None) -> dict:
    if key_override and os.path.isfile(key_override):
        key_path = key_override
    else:
        key_path = os.path.join(layout_dir, "license", "license.json")

    if not os.path.isfile(key_path):
        sys.exit(f"[ERROR] License/key file not found: {key_path}")

    with open(key_path) as f:
        data = json.load(f)

    # Support both key JSON formats (package.py output_key.json OR license.json)
    if "file_key_hex" in data:
        file_key = bytes.fromhex(data["file_key_hex"])
        hmac_key = bytes.fromhex(data["hmac_key_hex"])
    elif "fileKey" in data:
        file_key = base64.b64decode(data["fileKey"])
        hmac_key = base64.b64decode(data["hmacKey"])
    else:
        sys.exit(f"[ERROR] Unrecognised key format in {key_path}")

    print(f"  [keys] Loaded from: {key_path}")
    return {"file_key": file_key, "hmac_key": hmac_key}


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DAVILS local streaming server -- play .enc files in VLC/mpv",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--port",           type=int, default=8080,
                        help="HTTP port (default: 8080)")
    parser.add_argument("--layout",         default="hdd_layout/valid",
                        help="HDD layout variant dir (default: hdd_layout/valid)")
    parser.add_argument("--key",            default=None,
                        help="Override key file path (default: layout/license/license.json)")
    parser.add_argument("--no-hmac-verify", action="store_true",
                        help="Skip full HMAC pre-check (faster start for large files)")
    args = parser.parse_args()

    layout_dir  = args.layout
    content_dir = os.path.join(layout_dir, "content")

    if not os.path.isdir(content_dir):
        sys.exit(f"[ERROR] Content directory not found: {content_dir}")

    keys = load_keys(layout_dir, args.key)

    _config["content_dir"]  = content_dir
    _config["keys"]         = keys
    _config["verify_hmac"]  = not args.no_hmac_verify

    # List available files
    enc_files = [f for f in os.listdir(content_dir) if f.endswith(".enc")]

    print(f"""
============================================================
  DAVILS Streaming Server -- Sprint 1 Playback Test
============================================================
  Layout    : {os.path.abspath(layout_dir)}
  Content   : {content_dir}
  HMAC check: {"enabled (full pre-verify)" if _config["verify_hmac"] else "DISABLED (--no-hmac-verify)"}
  Port      : {args.port}
------------------------------------------------------------
  Available files:
""")
    for ef in sorted(enc_files):
        size = os.path.getsize(os.path.join(content_dir, ef))
        slug = ef.replace(".enc", "")
        print(f"    http://localhost:{args.port}/{slug}   ({size / 1e6:.0f} MB)")

    print(f"""
------------------------------------------------------------
  Open in VLC:
    vlc http://localhost:{args.port}/lesson1

  Open in mpv:
    mpv http://localhost:{args.port}/lesson1

  Open in browser (Chrome/Edge/Firefox):
    http://localhost:{args.port}/lesson1

  Test wrong-key layout (expect 403 HMAC failure):
    python streaming_server.py --layout hdd_layout/wrong_key --port 8081

  Test Range/seek (curl):
    curl -v -H "Range: bytes=1048576-2097151" http://localhost:{args.port}/lesson1.enc -o /dev/null
============================================================
""")

    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), DAVILSHandler)
    print(f"  Listening on http://0.0.0.0:{args.port} -- Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [stop] Server stopped.")


if __name__ == "__main__":
    main()
