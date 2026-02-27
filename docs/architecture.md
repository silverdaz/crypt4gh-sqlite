---
layout: default
title: Architecture
description: Technical architecture of crypt4gh-sqlite.
permalink: /architecture/
---

# Architecture

## High-level overview

```
User process (read)
        │
        ▼
  Linux VFS (kernel)
        │
        ▼
  FUSE kernel module
        │  (passes syscalls over /dev/fuse)
        ▼
  crypt4gh-sqlite.fs  ◄──── SQLite database  (directory tree, file metadata, headers)
        │
        ├─── libsodium   (ChaCha20-Poly1305 decryption, X25519 key exchange)
        ├─── OpenSSL     (hash helpers)
        └─── payload files on disk  (raw .c4gh ciphertext)
```

When a process opens a file under the mount point, the FUSE driver:

1. Looks up the file entry in the SQLite database using the virtual path.
2. Fetches the re-encrypted Crypt4GH header for the requesting user from the database.
3. Derives the file encryption key using the user's secret key and libsodium.
4. Opens the physical payload file on disk.
5. For `read()` calls, decrypts only the requested byte range — Crypt4GH's block
   structure allows random access without full-file decryption.
6. Prepends or appends static data stored in the database as required.

---

## Key design decisions

### SQLite as a control plane

Storing the file system metadata in SQLite gives you a standard, queryable,
transactional store that is easy to inspect, backup, and manipulate with any
SQLite tool.  No custom daemon, no network service.

### Per-user headers in the database

Rather than storing a single header in each `.c4gh` file, crypt4gh-sqlite keeps
one header row per (file, user) in the database.  This allows a single physical
payload to be shared among many users — each user's row contains a header
encrypted to their public key.  Revocation is a simple `DELETE`.

### Block-level random access

The Crypt4GH format divides ciphertext into 65 536-byte blocks, each independently
authenticated.  The FUSE driver exploits this to decrypt only the blocks
overlapping a requested byte range, making random reads (e.g., `seek()` + `read()`)
efficient without buffering the entire file.

### Prepend / Append as virtual streams

Some genomic formats require a metadata header before the data payload
(e.g., BAM BGZF headers, SAM headers).  Rather than physically concatenating files,
crypt4gh-sqlite lets you store those static bytes in the database and present a
seamless logical file to the reader.  This avoids duplicating data on disk.

---

## Source layout

```
crypt4gh-sqlite/
├── src/
│   ├── main.c          ← entry point, option parsing, FUSE session setup
│   ├── fs.c / fs.h     ← FUSE operation implementations (lookup, read, readdir, …)
│   ├── db.c / db.h     ← SQLite query helpers
│   ├── crypt4gh.c / .h ← Crypt4GH header parsing and block decryption
│   └── …
├── example/
│   ├── Makefile        ← test database setup and mount/unmount targets
│   └── …
├── configure.ac        ← Autoconf configuration
├── Makefile.in         ← Automake template
└── .github/workflows/
    └── build.yml       ← CI definition
```

---

## Security properties

| Property | Status |
|---|---|
| Plaintext written to disk | ❌ Never |
| Encrypted payload files modified | ❌ Never (read-only) |
| Per-user access control | ✅ Via database header rows |
| Authenticated encryption | ✅ ChaCha20-Poly1305 (AEAD) |
| Forward secrecy of file keys | ✅ Ephemeral X25519 exchange per header |
| Mount accessible to root only | Configurable (`allow_other`, `allow_root`) |

<div class="warning">
<strong>Warning:</strong> The secret key file (<code>--sk</code>) must be protected with
appropriate file permissions (<code>600</code>).  The file system reads it at mount time;
the key is held in process memory while the mount is active.
</div>
