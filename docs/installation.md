---
layout: default
title: Installation
description: How to build and install crypt4gh-sqlite from source.
permalink: /installation/
---

# Installation

crypt4gh-sqlite is distributed as source code and must be compiled from source.  
The build system uses the standard GNU Autotools chain.

## Requirements

| Dependency | Minimum version | Purpose |
|---|---|---|
| GCC / Clang | any recent | C compiler |
| GNU Autotools (`autoconf`, `automake`, `make`) | — | Build system |
| [libsodium](https://doc.libsodium.org) | 1.0.18+ | ChaCha20-Poly1305 and X25519 crypto |
| OpenSSL | 1.1+ | Used for hashing and helper routines |
| [libfuse 3](https://github.com/libfuse/libfuse) | 3.10+ | FUSE kernel interface |
| pkg-config | — | Library detection at configure time |

<div class="note">
<strong>Note:</strong> libfuse 3 is required — libfuse 2 is not supported.
On some distributions you may need to build libfuse from source (see below).
</div>

---

## 1. Install system dependencies

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  libsodium-dev libssl-dev \
  autoconf automake make gcc pkg-config
```

### Fedora / RHEL

```bash
sudo dnf install -y \
  libsodium-devel openssl-devel \
  autoconf automake make gcc pkg-config
```

---

## 2. Install libfuse 3

Many distributions ship libfuse 3, but if yours does not (or ships an older version),
build it from source:

```bash
# Install meson + ninja first
sudo apt-get install -y meson ninja-build wget   # Debian/Ubuntu

# Download and build libfuse 3.16.2
wget https://github.com/libfuse/libfuse/releases/download/fuse-3.16.2/fuse-3.16.2.tar.gz
tar xzf fuse-3.16.2.tar.gz
cd fuse-3.16.2

mkdir build && cd build
meson setup ..
meson configure -D disable-mtab=true
meson configure -D prefix=/usr/local
meson configure -D tests=false
meson configure -D examples=false
ninja
sudo ninja install
sudo ldconfig -v
```

Allow non-root users to use FUSE mounts (optional but recommended for testing):

```bash
sudo sed -i '/user_allow_other/s/^#.*user_allow_other$/user_allow_other/' \
  /usr/local/etc/fuse.conf
```

---

## 3. Build crypt4gh-sqlite

```bash
git clone https://github.com/silverdaz/crypt4gh-sqlite.git
cd crypt4gh-sqlite

autoreconf -i
./configure
make
sudo make install
```

The installed binary is named **`crypt4gh-sqlite.fs`**.

### Verify the installation

```bash
crypt4gh-sqlite.fs -V
```

---

## 4. (Optional) Install the Python crypt4gh tool

The example tests use the Python reference implementation of Crypt4GH for
generating test files and verifying round-trips:

```bash
pip install crypt4gh
```

---

## Uninstall

```bash
sudo make uninstall
```
