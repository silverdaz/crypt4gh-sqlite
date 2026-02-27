---
layout: default
title: Home
description: crypt4gh-sqlite — A FUSE file system backed by SQLite, serving Crypt4GH-encrypted genomic files with on-the-fly decryption.
---

<div class="hero">
  <h1>crypt4gh-sqlite</h1>
  <p class="subtitle">
    A FUSE file system that exposes Crypt4GH-encrypted files through a virtual directory tree,
    driven entirely by a single SQLite database.
  </p>

  <div class="badge-row">
    <a href="https://github.com/silverdaz/crypt4gh-sqlite/actions/workflows/build.yml">
      <img src="https://github.com/silverdaz/crypt4gh-sqlite/actions/workflows/build.yml/badge.svg" alt="GitHub CI" />
    </a>
    <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License: AGPL-3.0" />
    <img src="https://img.shields.io/badge/language-C-blue" alt="Language: C" />
    <img src="https://img.shields.io/badge/FUSE-3.x-brightgreen" alt="FUSE 3.x" />
  </div>

  <div class="cta-row">
    <a class="btn btn-primary" href="{{ '/installation/' | relative_url }}">Get Started</a>
    <a class="btn btn-secondary" href="https://github.com/silverdaz/crypt4gh-sqlite" target="_blank">View on GitHub</a>
  </div>
</div>

## What is crypt4gh-sqlite?

**crypt4gh-sqlite** mounts a read-only virtual file system whose directory layout and file
metadata live in a single SQLite database.  Each virtual file points to one or more
[Crypt4GH](https://crypt4gh.readthedocs.io/)-encrypted payloads on disk, along with
user-specific re-encrypted headers.  When a process reads a file through the mount point,
the kernel driver decrypts the relevant segments on the fly — no plaintext ever hits disk.

The project is written in C and uses [libfuse 3](https://github.com/libfuse/libfuse),
[libsodium](https://doc.libsodium.org), and OpenSSL.

<div class="cards">
  <div class="card">
    <div class="card-icon">🔒</div>
    <h3>Crypt4GH-native</h3>
    <p>Files are decrypted transparently at read time using per-user re-encrypted headers. Plaintext is never written to disk.</p>
  </div>
  <div class="card">
    <div class="card-icon">🗄️</div>
    <h3>SQLite-backed</h3>
    <p>The entire virtual file system tree — directories, files, metadata — is defined by a single SQLite database file.</p>
  </div>
  <div class="card">
    <div class="card-icon">⚙️</div>
    <h3>FUSE 3</h3>
    <p>Mounts as a standard Linux FUSE 3 file system. Any POSIX application can read files without any modification.</p>
  </div>
  <div class="card">
    <div class="card-icon">✂️</div>
    <h3>Prepend / Append</h3>
    <p>Virtual files can have static data prepended or appended to the encrypted payload — useful for wrapping genomic data in custom formats.</p>
  </div>
  <div class="card">
    <div class="card-icon">🚀</div>
    <h3>Lightweight</h3>
    <p>Pure C, no heavy runtime dependencies beyond libsodium, OpenSSL and libfuse 3.</p>
  </div>
  <div class="card">
    <div class="card-icon">🧪</div>
    <h3>CI-tested</h3>
    <p>Every push is automatically built, mounted, and tested via GitHub Actions on Ubuntu.</p>
  </div>
</div>

## Quick start

```bash
# 1. Install dependencies (Debian / Ubuntu)
sudo apt-get install libsodium-dev libssl-dev libfuse3-dev

# 2. Build & install
autoreconf -i
./configure
make
sudo make install

# 3. Run
crypt4gh-sqlite.fs /path/to/db.sqlite /mnt/data
```

See the [Installation]({{ '/installation/' | relative_url }}) and
[Usage]({{ '/usage/' | relative_url }}) pages for full details.
