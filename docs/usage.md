---
layout: default
title: Usage
description: How to mount and use crypt4gh-sqlite.
permalink: /usage/
---

# Usage

## Synopsis

```
crypt4gh-sqlite.fs <sqlite_filepath> <mountpoint> [options]
```

The two positional arguments — the SQLite database path and the mount point — are required and must come first.

---

## Options

### General

| Option | Description |
|---|---|
| `-h`, `--help` | Print help and exit |
| `-V`, `--version` | Print version and exit |
| `-f` | Run in foreground (do not daemonise) |
| `-s` | Disable multi-threaded operation (single-threaded mode) |
| `-g`, `-o local_debug[=N]` | Print debugging information; implies `-f` |
| `-o opt,[opt...]` | Pass FUSE mount options |

### Caching & I/O

| Option | Description |
|---|---|
| `-o direct_io` | Enable direct I/O (bypass kernel page cache) |
| `-o file_cache` | Instruct the kernel to cache file output data |
| `-o dir_cache` | Instruct the kernel to cache directory listings |
| `-o entry_timeout=S` | Seconds to cache lookup names (default: 86400 — one day) |
| `-o attr_timeout=S` | Seconds to cache file/dir attributes (default: 86400 — one day) |

### Directory listing

| Option | Description |
|---|---|
| `-o dotdot` | Show `.` and `..` entries in directory listings (hidden by default) |

### Ownership

| Option | Description |
|---|---|
| `-o user_id=N` | UID reported for all mount point entries (default: caller's UID) |
| `-o group_id=N` | GID reported for all mount point entries (default: caller's GID) |
| `-o group_name=S` | Group name for the mount point (overrides `group_id`) |

### Crypt4GH decryption

These options are only relevant when the build was compiled with Crypt4GH support.
Omitting `seckey` disables decryption entirely (passthrough mode).

| Option | Description |
|---|---|
| `-o seckey=<path>` | **Absolute path** to the Crypt4GH secret key file |
| `-o passphrase_from_env=<ENVVAR>` | Read the key passphrase from the named environment variable instead of prompting on the TTY |

### Multi-threading

| Option | Description |
|---|---|
| `-o clone_fd` | Use separate `/dev/fuse` file descriptors per thread |
| `-o max_threads=N` | Maximum number of worker threads (default: 10) |

---

## Examples

### Basic mount (passthrough, no decryption)

```bash
crypt4gh-sqlite.fs /data/genomics.db /mnt/data
```

### Mount with Crypt4GH decryption, passphrase prompted on TTY

```bash
crypt4gh-sqlite.fs /data/genomics.db /mnt/data \
  -o seckey=/home/alice/.c4gh/key.sec
```

### Mount with passphrase from an environment variable

```bash
export MY_PASSPHRASE="hunter2"
crypt4gh-sqlite.fs /data/genomics.db /mnt/data \
  -o seckey=/home/alice/.c4gh/key.sec \
  -o passphrase_from_env=MY_PASSPHRASE
```

### Foreground / debug mode

```bash
crypt4gh-sqlite.fs /data/genomics.db /mnt/data -f -g \
  -o seckey=/home/alice/.c4gh/key.sec
```

### Single-threaded, custom group

```bash
crypt4gh-sqlite.fs /data/genomics.db /mnt/data -s \
  -o seckey=/home/alice/.c4gh/key.sec \
  -o group_name=biodata
```

---

## Unmounting

```bash
fusermount3 -u /mnt/data
```

---

## Notes

- The SQLite database is opened **read-write** if the process has write permission on the file (needed for `setxattr` / `removexattr`), and **read-only** otherwise. The virtual file system itself is always read-only from the user's perspective.
- The `seckey` path **must be absolute** (starting with `/`).
- File and directory permissions at the mount point are derived from the caller's `umask` at mount time (`0666 & ~umask` for files, `0777 & ~umask` for directories).
- Requires FUSE ≥ 3.12.

<div class="tip">
<strong>Tip:</strong> Use <code>-o passphrase_from_env</code> in automated / CI contexts to avoid interactive TTY prompts.
</div>
