#!/usr/bin/env python3
"""
Generate dummy test files for DAVILS Sprint 1 smoke tests.

Produces three files with realistic random-ish byte patterns:
    test_50mb.mp4   —   50 MB
    test_300mb.mp4  —  300 MB
    test_2gb.mp4    —    2 GB

Usage:
    python generate_test_files.py [--outdir .]
"""

import argparse
import os
import sys
import time

TARGETS = [
    ("test_50mb.mp4",  50  * 1_048_576),
    ("test_300mb.mp4", 300 * 1_048_576),
    ("test_2gb.mp4",   2   * 1_073_741_824),
]

WRITE_CHUNK = 4 * 1_048_576   # 4 MiB write buffer


def make_file(path: str, size: int) -> None:
    if os.path.exists(path) and os.path.getsize(path) == size:
        print(f"  [skip] {path} already exists at {size:,} bytes")
        return

    print(f"  [gen]  {path}  ({size / 1e6:.0f} MB) …", end="", flush=True)
    t0 = time.perf_counter()

    with open(path, "wb") as f:
        written = 0
        # Use os.urandom for the first chunk so the file isn't all zeros
        # (compressors/tools treat zero files specially). Repeat a pattern
        # for the rest to keep generation fast.
        seed_chunk = os.urandom(min(WRITE_CHUNK, size))
        while written < size:
            remaining = size - written
            to_write  = min(WRITE_CHUNK, remaining)
            if written == 0:
                f.write(seed_chunk[:to_write])
            else:
                # Cycle the seed chunk to fill fast without re-randomising
                repeats = (to_write + len(seed_chunk) - 1) // len(seed_chunk)
                f.write((seed_chunk * repeats)[:to_write])
            written += to_write
            pct = written / size * 100
            print(f"\r  [gen]  {os.path.basename(path)}  ({size / 1e6:.0f} MB) … {pct:5.1f}%",
                  end="", flush=True)

    elapsed = time.perf_counter() - t0
    print(f"\r  [gen]  {os.path.basename(path)}  — done in {elapsed:.1f}s            ")


def main():
    parser = argparse.ArgumentParser(description="Generate DAVILS test files")
    parser.add_argument("--outdir", default=".", help="Directory to write test files into")
    args = parser.parse_args()

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    print(f"\nGenerating test files in: {os.path.abspath(outdir)}\n")
    for name, size in TARGETS:
        make_file(os.path.join(outdir, name), size)

    print(f"\n[done] All test files ready.\n")


if __name__ == "__main__":
    main()
