# DAVILS Offline Video Security System - Sprint 1

This repository contains the Security Engineer deliverables for Sprint 1. It provides the tools necessary to encrypt video files, generate the physical hard drive (HDD) layout, and validate the streaming protocol.

## Tools Provided

### 1. The Packaging Tool (`davils_gui.py`)
This is the core encryption tool used to prepare content for the hard drives.
- **Input:** Standard `.mp4` video files.
- **Cryptography:** Encrypts the payload with **AES-256-CTR** and signs the file header with **HMAC-SHA256**.
- **Output:** Generates the exact `hdd_layout/valid` folder structure required for the Android app, including the `.enc` files and the hardcoded `license.json` for Sprint 1.

### 2. The QA Tester / Protocol Reference (`davils_qa_tester.py`)
A developer and QA tool that independently verifies the encrypted files without needing the Android app. 
**Crucially for the Android Engineer**, this tool contains a Python implementation of the `DataSource` local HTTP server. It demonstrates exactly how to handle HTTP Range requests and map them to AES-CTR counter offsets.
- **Mode A (Export):** Validates HMAC and decrypts the file to disk for QA validation.
- **Mode B (Stream):** Runs a local HTTP server that decrypts the `.enc` file in-memory on-the-fly, allowing a standard player (like VLC) to seek and play the file with zero lag.

## Setup Instructions

1. Ensure Python 3.10+ is installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Packaging Tool:
   ```bash
   python davils_gui.py
   ```
4. Run the QA Tester:
   ```bash
   python davils_qa_tester.py
   ```

## Cryptography & Protocol Details (For Android Engineer)

The `.enc` file format is highly specific to allow O(1) random access seeking.

### File Header (128 bytes)
- `[0:4]` Magic bytes: `DAVL`
- `[4:5]` Version byte: `\x01`
- `[5:8]` Padding
- `[8:12]` Chunk count (UInt32)
- `[12:16]` Chunk size (UInt32, usually 1MB)
- `[16:24]` Total plaintext size (UInt64)
- `[24:40]` AES-CTR Nonce (16 bytes)
- `[40:72]` HMAC-SHA256 Signature (32 bytes)
- `[72:128]` Reserved padding

### HMAC Verification
The HMAC signature in the header signs the **first 40 bytes** of the header (Magic through Nonce) PLUS the entire encrypted payload. 
*Note: In `davils_qa_tester.py`, you can see how this is verified progressively as the file is streamed or exported.*

### AES-CTR Seeking Math
When ExoPlayer sends an HTTP `Range` request (e.g., `bytes=1000000-`), your Kotlin `DataSource` must calculate the exact block to decrypt:
1. Divide the byte offset by 16 to find the block number.
2. Add that block number to the 16-byte `nonce` found in the file header.
3. Use that new counter value to initialize your AES-CTR cipher.
4. Discard the first `offset % 16` bytes of the resulting decrypted block.
*(See `make_seek_cipher` in `davils_qa_tester.py` for the exact bitwise math).*

## HDD Layout Structure
The Android app expects the following structure on the external drive:
```text
[USB_ROOT]/
└── hdd_layout/
    └── valid/
        ├── content/
        │   └── lesson1.enc
        └── license/
            └── license.json
```
*In Sprint 1, `license.json` contains the raw Base64 keys and `deviceFingerprint = "ANY"`.*
