---
layout: default
title: Database Schema
description: SQLite database schema used by crypt4gh-sqlite.
permalink: /schema/
---

# Database Schema

The entire virtual file system is driven by a single SQLite database.
Below is the exact schema as defined in the source.

---

## Table: `entries`

Represents every node in the file system tree — both directories and files.
The root directory is pre-inserted with inode `1`, self-referencing as its own parent.

```sql
CREATE TABLE IF NOT EXISTS entries (
    inode             INT64 NOT NULL PRIMARY KEY,
    name              text NOT NULL,
    parent_inode      INT64 NOT NULL REFERENCES entries(inode) ON DELETE CASCADE
                                     NOT DEFERRABLE INITIALLY IMMEDIATE,
    ctime             INT64 NOT NULL DEFAULT (unixepoch('now')),
    mtime             INT64 NOT NULL DEFAULT (unixepoch('now')),
    nlink             INT NOT NULL DEFAULT 2,
    size              INT64 NOT NULL DEFAULT 0,
    is_dir            INT NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS names ON entries(parent_inode, name);

-- Root directory (bootstrapped once)
INSERT INTO entries(inode, name, parent_inode)
VALUES (1, '/', 1)
ON CONFLICT DO NOTHING;
```

| Column | Type | Description |
|---|---|---|
| `inode` | INT64 PK | Unique inode number |
| `name` | text | Entry name (single path component) |
| `parent_inode` | INT64 FK | Parent entry; root points to itself |
| `ctime` | INT64 | Last status-change time (Unix epoch) |
| `mtime` | INT64 | Last modification time (Unix epoch) |
| `nlink` | INT | Hard link count (default 2 for directories) |
| `size` | INT64 | Logical size in bytes |
| `is_dir` | INT | `1` = directory, `0` = file |

---

## Table: `files`

Holds the file-specific data for every entry where `is_dir = 0`.
Linked 1-to-1 with `entries` via `inode`.

```sql
CREATE TABLE IF NOT EXISTS files (
  inode         INT64 PRIMARY KEY REFERENCES entries(inode) ON DELETE CASCADE
                                  NOT DEFERRABLE INITIALLY IMMEDIATE,
  mountpoint    text,
  rel_path      text,
  header        BLOB,
  payload_size  INT64 NOT NULL DEFAULT 0,
  prepend       BLOB,
  append        BLOB
);
```

| Column | Type | Description |
|---|---|---|
| `inode` | INT64 PK FK | References `entries.inode` |
| `mountpoint` | text | Base directory where the payload file lives on disk |
| `rel_path` | text | Path to the payload file, relative to `mountpoint` |
| `header` | BLOB | Re-encrypted Crypt4GH header for this user; `NULL` for passthrough files |
| `payload_size` | INT64 | Size of the raw (encrypted) payload in bytes |
| `prepend` | BLOB | Bytes to prepend to the payload at read time; `NULL` if none |
| `append` | BLOB | Bytes to append to the payload at read time; `NULL` if none |

The full logical size seen by a reader is: `length(prepend) + payload_size + length(append)`.

---

## Table: `extended_attributes`

Stores arbitrary POSIX extended attributes (`xattr`) on any entry.
Writing xattrs is only available when the database file is writable by the mounting process.

```sql
CREATE TABLE IF NOT EXISTS extended_attributes (
    inode             INT64 REFERENCES entries(inode) ON DELETE CASCADE
                            NOT DEFERRABLE INITIALLY IMMEDIATE,
    name              text NOT NULL,
    value             text NOT NULL,
    PRIMARY KEY(inode, name)
);
```

| Column | Type | Description |
|---|---|---|
| `inode` | INT64 FK | References `entries.inode` |
| `name` | text | Attribute name (e.g. `user.checksum`) |
| `value` | text | Attribute value |

---

## Triggers

Any insert, update, or delete on `extended_attributes` automatically bumps the `mtime`
and `ctime` of the affected entry:

```sql
CREATE TRIGGER on_insert AFTER INSERT ON extended_attributes
BEGIN
  UPDATE entries SET mtime = unixepoch('now'), ctime = unixepoch('now')
  WHERE inode = NEW.inode;
END;

CREATE TRIGGER on_update AFTER UPDATE ON extended_attributes
BEGIN
  UPDATE entries SET mtime = unixepoch('now'), ctime = unixepoch('now')
  WHERE inode = NEW.inode;
END;

CREATE TRIGGER on_delete AFTER DELETE ON extended_attributes
BEGIN
  UPDATE entries SET mtime = unixepoch('now'), ctime = unixepoch('now')
  WHERE inode = NEW.inode;
END;
```

---

## Inspecting a live database

```bash
# Dump the schema
sqlite3 /data/genomics.db ".schema"

# List all entries
sqlite3 /data/genomics.db "SELECT inode, parent_inode, is_dir, name FROM entries;"

# List files with their payload paths
sqlite3 /data/genomics.db \
  "SELECT e.inode, e.name, f.mountpoint, f.rel_path, f.payload_size
   FROM entries e JOIN files f USING (inode);"

# Show extended attributes
sqlite3 /data/genomics.db "SELECT * FROM extended_attributes;"
```
