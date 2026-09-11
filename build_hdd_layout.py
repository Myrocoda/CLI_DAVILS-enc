#!/usr/bin/env python3
import sys
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
"""
Build the three reference HDD layout variants for DAVILS Sprint 1.

Variants produced under hdd_layout/:
    valid/       -- correct keys, ready for playback
    no_license/  -- no license/ directory at all (unlicensed device test)
    wrong_key/   -- license.json present but with incorrect keys (tamper test)

Usage:
    python build_hdd_layout.py [--key output_key.json]

The --key file must already exist (run package.py first, or pass the path to
an existing key JSON).  The valid/ license.json will contain the real keys;
the wrong_key/ license.json will contain random garbage keys.
"""

import argparse
import base64
import json
import os
import shutil

BASE_DIR = "hdd_layout"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


COURSE_JSON = {
    "title": "Introduction to Secure Video Delivery",
    "version": "1.0",
    "lessons": [
        {
            "id": "lesson1",
            "title": "Lesson 1 - Foundations",
            "filename": "lesson1.enc",
            "durationSeconds": 1800
        },
        {
            "id": "lesson2",
            "title": "Lesson 2 - Advanced Concepts",
            "filename": "lesson2.enc",
            "durationSeconds": 2400
        }
    ]
}


def make_license(file_key_b64: str, hmac_key_b64: str, label: str) -> dict:
    return {
        "_variant": label,
        "customerId": "TEST-001",
        "customerName": "Test User",
        "fileKey": file_key_b64,
        "hmacKey": hmac_key_b64,
        "deviceFingerprint": "ANY",
        "_note": "Sprint 1: deviceFingerprint=ANY means no device binding. Real binding is Sprint 2."
    }


def scaffold(variant: str, subdirs: list) -> str:
    """Create a variant directory with the given subdirs. Return the variant root."""
    root = os.path.join(BASE_DIR, variant)
    for d in subdirs:
        os.makedirs(os.path.join(root, d), exist_ok=True)
    return root


def write_json(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
    print(f"  [write] {path}")


def write_placeholder_enc(path: str, label: str) -> None:
    """
    Write a tiny placeholder .enc so the directory isn't empty.
    In a real handoff these are replaced by output from package.py.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(
            f"# PLACEHOLDER -- replace with real .enc output from package.py\n"
            f"# Variant: {label}\n"
        )
    print(f"  [write] {path}  (placeholder)")


def main():
    parser = argparse.ArgumentParser(description="Build DAVILS reference HDD layouts")
    parser.add_argument("--key", default="output_key.json",
                        help="Key JSON produced by package.py (default: output_key.json)")
    args = parser.parse_args()

    # -- Load real keys
    if not os.path.isfile(args.key):
        sys.exit(
            f"[ERROR] Key file not found: {args.key}\n"
            "Run  python package.py --input <file> --output <out> --key output_key.json  first."
        )

    with open(args.key) as f:
        keys = json.load(f)

    real_file_key_b64 = keys.get("file_key_b64") or base64.b64encode(bytes.fromhex(keys["file_key_hex"])).decode()
    real_hmac_key_b64 = keys.get("hmac_key_b64") or base64.b64encode(bytes.fromhex(keys["hmac_key_hex"])).decode()

    # Wrong keys = fresh random bytes, base64-encoded
    wrong_file_key_b64 = b64(os.urandom(32))
    wrong_hmac_key_b64 = b64(os.urandom(32))

    os.makedirs(BASE_DIR, exist_ok=True)
    print(f"\nBuilding HDD layout under: {os.path.abspath(BASE_DIR)}\n")

    # -- VARIANT 1: valid
    print("-- valid/ --------------------------------------------------")
    v1 = scaffold("valid", ["content", "metadata", "license"])

    write_placeholder_enc(os.path.join(v1, "content", "lesson1.enc"), "valid")
    write_placeholder_enc(os.path.join(v1, "content", "lesson2.enc"), "valid")
    write_json(os.path.join(v1, "metadata", "course.json"), COURSE_JSON)
    write_json(
        os.path.join(v1, "license", "license.json"),
        make_license(real_file_key_b64, real_hmac_key_b64, "VALID -- correct keys")
    )

    # -- VARIANT 2: no_license
    print("\n-- no_license/ ---------------------------------------------")
    v2 = scaffold("no_license", ["content", "metadata"])
    # Deliberately NO license/ directory

    write_placeholder_enc(os.path.join(v2, "content", "lesson1.enc"), "no_license")
    write_placeholder_enc(os.path.join(v2, "content", "lesson2.enc"), "no_license")
    write_json(os.path.join(v2, "metadata", "course.json"), COURSE_JSON)
    # Confirm no license dir was created
    license_path = os.path.join(v2, "license")
    if os.path.exists(license_path):
        shutil.rmtree(license_path)
    print(f"  [skip]  {os.path.join(v2, 'license/')}  <- intentionally absent")

    # -- VARIANT 3: wrong_key
    print("\n-- wrong_key/ ----------------------------------------------")
    v3 = scaffold("wrong_key", ["content", "metadata", "license"])

    write_placeholder_enc(os.path.join(v3, "content", "lesson1.enc"), "wrong_key")
    write_placeholder_enc(os.path.join(v3, "content", "lesson2.enc"), "wrong_key")
    write_json(os.path.join(v3, "metadata", "course.json"), COURSE_JSON)
    write_json(
        os.path.join(v3, "license", "license.json"),
        make_license(wrong_file_key_b64, wrong_hmac_key_b64,
                     "WRONG KEY -- intentionally incorrect for HMAC-fail testing")
    )

    # -- Summary
    print(f"""
{'='*60}
  HDD layout complete.

  hdd_layout/
    valid/        -- correct keys, device=ANY  <- Android happy path
    no_license/   -- no license dir            <- expect "No License" error
    wrong_key/    -- license.json w/ bad keys  <- expect HMAC failure

  Next step: copy real .enc files from package.py into each
  variant's content/ directory to replace the placeholders.
{'='*60}
""")


if __name__ == "__main__":
    main()
