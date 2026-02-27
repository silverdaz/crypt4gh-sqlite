---
layout: default
title: CI / Build
description: Continuous integration and build details for crypt4gh-sqlite.
permalink: /ci/
---

# CI / Build

Every push to the repository triggers the GitHub Actions workflow defined in
[`.github/workflows/build.yml`](https://github.com/silverdaz/crypt4gh-sqlite/blob/main/.github/workflows/build.yml).

[![Build Status](https://github.com/silverdaz/crypt4gh-sqlite/actions/workflows/build.yml/badge.svg)](https://github.com/silverdaz/crypt4gh-sqlite/actions/workflows/build.yml)

---

## Workflow summary

The workflow runs on `ubuntu-latest` and walks through these stages:

<ol class="steps">
  <li>
    <strong>Checkout</strong> — clone the repository at the pushed commit.
  </li>
  <li>
    <strong>Install system dependencies</strong> — libsodium, OpenSSL, pkg-config, autoconf, automake, meson, ninja, wget, Python 3.
  </li>
  <li>
    <strong>Build libfuse 3.16.2</strong> — downloaded from the upstream release, configured with <code>disable-mtab</code>, built with meson/ninja, installed to <code>/usr/local</code>.
    <code>user_allow_other</code> is enabled in <code>fuse.conf</code>.
  </li>
  <li>
    <strong>Install Python crypt4gh</strong> — the reference implementation (<code>pip install crypt4gh</code>) is used to generate test keys and verify decryption round-trips.
  </li>
  <li>
    <strong>Compile crypt4gh-sqlite</strong> — <code>autoreconf -i</code>, <code>./configure</code>, <code>make</code>, <code>sudo make install</code>.
  </li>
  <li>
    <strong>Print version</strong> — <code>crypt4gh-sqlite.fs -V</code> (smoke-tests the binary).
  </li>
  <li>
    <strong>Set up &amp; mount the example</strong> — <code>make -C example update up</code> populates the test SQLite database and mounts the file system.
  </li>
  <li>
    <strong>Run 6 integration tests</strong> — each test is a <code>diff</code> between a file read through the mount point and its expected content.
  </li>
  <li>
    <strong>Tear down</strong> — <code>make -C example down</code> unmounts cleanly.
  </li>
</ol>

---

## Integration tests at a glance

| Test | File system path | What is verified |
|---|---|---|
| 1 | `mnt/crypt4gh/cleartext` | Driver decrypts a Crypt4GH file; matches `crypt4gh decrypt` |
| 2 | `mnt/subdir/file1.txt` | Prepend bytes + payload = expected concatenation |
| 3 | `mnt/subdir/file2.txt` | Payload + append bytes = expected concatenation |
| 4 | `mnt/extra/footer.txt` | Append-only virtual file equals the raw append data |
| 5 | `mnt/extra/header.txt` | Prepend-only virtual file equals the raw prepend data |
| 6 | `mnt/slim.txt` | Passthrough file equals the original plaintext |

---

## Full workflow YAML

```yaml
name: Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Install dependencies
        run: |
          sudo apt-get install -y \
            libsodium-dev libssl-dev pkg-config \
            python3 python3-pip autoconf automake make gcc \
            meson ninja-build wget

      - name: Install libfuse v3.16.2
        run: |
          wget https://github.com/libfuse/libfuse/releases/download/fuse-3.16.2/fuse-3.16.2.tar.gz
          tar xzf fuse-3.16.2.tar.gz; cd fuse-3.16.2
          mkdir build; cd build
          meson setup ..
          meson configure -D disable-mtab=true
          meson configure -D prefix=/usr/local
          meson configure -D tests=false
          meson configure -D examples=false
          ninja
          sudo ninja install
          sudo ldconfig -v
          sudo sed -i '/user_allow_other/s/^#.*user_allow_other$/user_allow_other/' \
            /usr/local/etc/fuse.conf

      - name: Install Crypt4GH
        run: sudo python3 -m pip install crypt4gh

      - name: Compile
        run: |
          autoreconf -i
          ./configure
          make
          sudo make install

      - name: Print version
        run: crypt4gh-sqlite.fs -V

      - name: Update the test and start the file system
        run: make -C example update up

      - name: Test 1
        run: |
          diff example/mnt/crypt4gh/cleartext \
            <(C4GH_PASSPHRASE=hello crypt4gh decrypt \
                --sk example/example.seckey \
                < example/mnt/crypt4gh/encrypted 2>/dev/null)

      - name: Test 2
        run: diff example/mnt/subdir/file1.txt <(cat example/prepend.txt example/example.txt)

      - name: Test 3
        run: diff example/mnt/subdir/file2.txt <(cat example/example.txt example/append.txt)

      - name: Test 4
        run: diff example/mnt/extra/footer.txt example/append.txt

      - name: Test 5
        run: diff example/mnt/extra/header.txt example/prepend.txt

      - name: Test 6
        run: diff example/mnt/slim.txt example/example.txt

      - name: Tear down
        run: make -C example down
```
