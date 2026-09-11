# DAVILS `.enc` File Format — Sprint 1 Header Specification

> **Audience**: Android engineer integrating the Kotlin `DataSource` and HMAC verifier.
> This document is authoritative. All byte offsets are exact.

---

## Overview

Every `.enc` file produced by `package.py` begins with a **fixed 128-byte header**,
followed immediately by AES-256-CTR ciphertext.

```
┌──────────────────────────────────────────────────────┐
│  HEADER  (128 bytes, fixed, always at offset 0)      │
├──────────────────────────────────────────────────────┤
│  CIPHERTEXT  (same length as original plaintext)     │
└──────────────────────────────────────────────────────┘
```

**File size relationship**:

```
output_file_size = plaintext_size + 128
```

AES-CTR is a stream cipher — it **never** pads or changes the payload length.
The `+128` is entirely the header. If you observe any other delta, the file is corrupt.

---

## Header Byte Layout

| Offset | Size (bytes) | Type | Field | Notes |
|--------|-------------|------|-------|-------|
| 0 | 4 | ASCII | **Magic** | Always `0x44 0x41 0x56 0x4C` = `"DAVL"` |
| 4 | 1 | uint8 | **Version** | `0x01` for Sprint 1. Increment for breaking changes. |
| 5 | 3 | — | Reserved | Zero bytes. Do not interpret. |
| 8 | 4 | uint32 LE | **Chunk count** | `ceil(plaintext_size / chunk_size)` |
| 12 | 4 | uint32 LE | **Chunk size** | Fixed at `1,048,576` (1 MiB) for Sprint 1 |
| 16 | 8 | uint64 LE | **Plaintext size** | Original file size in bytes |
| 24 | 16 | bytes | **AES-CTR Nonce** | Randomly generated per file. Feed directly to `CTR(nonce)`. |
| 40 | 32 | bytes | **HMAC-SHA256** | See computation below |
| 72 | 56 | — | Reserved | Zero bytes. Do not interpret. |

**Total: 128 bytes.**

---

## HMAC-SHA256 Computation

The HMAC covers two regions concatenated:

```
HMAC_input = header[0:40]  ‖  ciphertext[0:end]
```

That is: the first 40 bytes of the header (magic through nonce, **not** including the HMAC
field itself) followed by the entire ciphertext.

**Algorithm**: HMAC-SHA256
**Key**: `hmacKey` from `license.json` (raw 32 bytes, base64-decoded)
**Digest size**: 32 bytes, stored at header offset 40

### Verification pseudocode (Kotlin)

```kotlin
val hmacKey: ByteArray = Base64.decode(license.hmacKey, Base64.DEFAULT)
val mac = Mac.getInstance("HmacSHA256")
mac.init(SecretKeySpec(hmacKey, "HmacSHA256"))

// Feed header prefix (bytes 0..39, excludes the HMAC field itself)
mac.update(header, 0, 40)

// Stream ciphertext
fileInputStream.skip(128)             // skip full header
val buffer = ByteArray(4 * 1024 * 1024)
var n: Int
while (fileInputStream.read(buffer).also { n = it } != -1) {
    mac.update(buffer, 0, n)
}

val computed = mac.doFinal()
val stored   = header.copyOfRange(40, 72)

if (!MessageDigest.isEqual(computed, stored)) {
    throw SecurityException("HMAC verification failed — file tampered or wrong key")
}
```

---

## Decryption (AES-256-CTR)

```kotlin
val fileKey: ByteArray = Base64.decode(license.fileKey, Base64.DEFAULT)  // 32 bytes
val nonce:   ByteArray = header.copyOfRange(24, 40)                       // 16 bytes

val cipher = Cipher.getInstance("AES/CTR/NoPadding")
cipher.init(
    Cipher.DECRYPT_MODE,
    SecretKeySpec(fileKey, "AES"),
    IvParameterSpec(nonce)
)
// Ciphertext starts at file offset 128
```

> **Important**: Always verify HMAC **before** decrypting. Never expose partially
> decrypted bytes if verification fails.

---

## Seek Support (DataSource)

The header encodes chunk boundaries so the Android `DataSource` can seek without
scanning the file:

```
chunk_size  = header[12:16] as uint32 LE   // always 1,048,576 in Sprint 1
chunk_count = header[8:12]  as uint32 LE

// To seek to chunk N (0-indexed):
file_offset = 128 + (N * chunk_size)
```

**CTR seek**: AES-CTR allows seeking by initialising the cipher with the correct
block counter. The counter advances by 1 per 16-byte AES block:

```kotlin
val blockOffset = (N.toLong() * chunk_size) / 16
// Construct an IvParameterSpec with nonce incremented by blockOffset
// (standard Java/Bouncy Castle CTR seek pattern)
```

The last chunk may be smaller than `chunk_size`; use `plaintext_size` (header[16:24])
to determine the exact byte count of the last chunk.

---

## `license.json` Schema

```json
{
  "customerId":        "TEST-001",
  "customerName":      "Test User",
  "fileKey":           "<base64, 32 raw bytes>",
  "hmacKey":           "<base64, 32 raw bytes>",
  "deviceFingerprint": "ANY"
}
```

- `fileKey` → AES-256 decryption key (raw 32 bytes, base64-encoded)
- `hmacKey` → HMAC-SHA256 key (raw 32 bytes, base64-encoded)
- `deviceFingerprint` = `"ANY"` → accept all devices in Sprint 1. Sprint 2 will
  replace this with a real fingerprint; your Kotlin code should already check for
  the `"ANY"` sentinel and skip binding validation when present.

---

## Reference HDD Layout

```
/content/
    lesson1.enc      ← encrypted with package.py
    lesson2.enc
/metadata/
    course.json      ← title, lessons list, durations
/license/
    license.json     ← keys + deviceFingerprint
```

Three variants are provided for integration testing:

| Variant | `license/` present | Keys correct | Expected Android behaviour |
|---------|--------------------|--------------|---------------------------|
| `valid/` | ✓ | ✓ | Playback succeeds |
| `no_license/` | ✗ | — | "No license found" error |
| `wrong_key/` | ✓ | ✗ | HMAC failure → reject playback |

---

## Changelog

| Version | Date | Change |
|---------|------|--------|
| 0x01 | 2026-09-10 | Initial Sprint 1 definition |

---

*Questions? Contact the Security Engineer before writing any parsing code against this spec.*
