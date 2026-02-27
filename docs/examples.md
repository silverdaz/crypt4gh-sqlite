---
layout: default
title: Examples
description: Worked examples for crypt4gh-sqlite.
permalink: /examples/
---

# Examples

The repository ships a self-contained example under `example/`.
It demonstrates all major features: Crypt4GH decryption, passthrough, prepend, and append.

## Running the example

```bash
# From the repo root — update the DB with the current path, then mount
make -C example update up

# Tear down when done
make -C example down
```

The `update` step rewrites the `mountpoint` column in the database to the current
absolute path of the `example/` directory — necessary because payload paths are
stored as `mountpoint + rel_path`.

---

## How the example mounts

The example `Makefile` invokes the file system as:

```bash
crypt4gh-sqlite.fs \
  -o ro \
  -o seckey=/path/to/example/example.seckey \
  -o passphrase_from_env=C4GH_PASSPHRASE \
  -o allow_other,default_permissions \
  -o file_cache,dir_cache \
  example/example.sqlite \
  example/mnt
```

The passphrase for the example secret key is `hello`, exported as:

```bash
export C4GH_PASSPHRASE=hello
```

Debug levels 1–3 are also available:

```bash
make -C example debug    # debug level 2, foreground
make -C example debug1   # debug level 1
make -C example debug3   # debug level 3
```

Unmounting uses plain `umount` (since the example mounts with `allow_other`):

```bash
make -C example down
# equivalent to: umount example/mnt
```

---

## What the CI tests verify

The workflow runs six `diff`-based tests against the mounted file system.

### Test 1 — Crypt4GH decryption

```bash
diff example/mnt/crypt4gh/cleartext \
  <(C4GH_PASSPHRASE=hello crypt4gh decrypt \
      --sk example/example.seckey \
      < example/mnt/crypt4gh/encrypted 2>/dev/null)
```

`mnt/crypt4gh/cleartext` is served already-decrypted by the FUSE driver.
`mnt/crypt4gh/encrypted` is the raw ciphertext passthrough. Both must yield the same plaintext.

---

### Test 2 — Prepend

```bash
diff example/mnt/subdir/file1.txt \
  <(cat example/prepend.txt example/example.txt)
```

`file1.txt` has `prepend.txt` injected before the payload at read time.

---

### Test 3 — Append

```bash
diff example/mnt/subdir/file2.txt \
  <(cat example/example.txt example/append.txt)
```

`file2.txt` has `append.txt` appended after the payload at read time.

---

### Test 4 — Append-only virtual file

```bash
diff example/mnt/extra/footer.txt example/append.txt
```

A virtual file whose content comes entirely from the `append` column in the database — no payload.

---

### Test 5 — Prepend-only virtual file

```bash
diff example/mnt/extra/header.txt example/prepend.txt
```

A virtual file whose content comes entirely from the `prepend` column — no payload.

---

### Test 6 — Passthrough

```bash
diff example/mnt/slim.txt example/example.txt
```

A plain passthrough file: no `header`, no `prepend`, no `append` — the payload is served as-is.

---

## Re-using the pattern in your own setup

A minimal population of the database for a new file looks like:

```bash
# 1. Insert a directory entry
sqlite3 mydb.sqlite "
  INSERT INTO entries(inode, name, parent_inode, is_dir)
  VALUES (2, 'data', 1, 1);
"

# 2. Insert a file entry
sqlite3 mydb.sqlite "
  INSERT INTO entries(inode, name, parent_inode, size, is_dir)
  VALUES (3, 'sample.txt', 2, 1048576, 0);
"

# 3. Link it to a payload
sqlite3 mydb.sqlite "
  INSERT INTO files(inode, mountpoint, rel_path, header, payload_size)
  VALUES (3, '/data/payloads', 'sample.c4gh', readfile('sample.header'), 1048576);
"
```

Then mount with your secret key:

```bash
crypt4gh-sqlite.fs \
  -o seckey=/home/alice/.c4gh/key.sec \
  -o passphrase_from_env=MY_PASSPHRASE \
  mydb.sqlite /mnt/data
```
