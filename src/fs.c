/*
  Read-only Crypt4GH file system, listing info from an SQLite "database".
  Copyright (C) 2021  Frédéric Haziza <frederic.haziza@crg.eu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "includes.h"

#define QUERY_C4GH(q) ((config.c4gh_decrypt)?q ## _no_ext : q)

// Lookup entry
static char *lookup_query = "SELECT inode, ctime, mtime, nlink, size, decrypted_size, is_dir "
                             "FROM entries e "
                             "WHERE parent_inode = ?1 and inode > 1 and name = ?2";
static char *lookup_query_no_ext = "SELECT inode, ctime, mtime, nlink, size, decrypted_size, is_dir "
                                 "FROM entries e "
                                 "WHERE parent_inode = ?1 AND inode > 1 AND "
                                 "       CASE WHEN is_dir "
                                 "       THEN name = ?2"
                                 "       ELSE SUBSTR(name, 1, LENGTH(name) - 5) = ?2"
                                 "       END";

// Get the attr $1: inode
static char *getattr_query = "SELECT ctime, mtime, nlink, size, decrypted_size, is_dir "
                             "FROM entries e "
                             "WHERE inode = ?1 and inode > 1";

// Read directory $1: parent inode, $2: offset (limit = 100)
static char *readdir_query = "SELECT inode, name, ctime, mtime, nlink, size, decrypted_size, is_dir "
                             "FROM entries "
                             "WHERE parent_inode = ?1 and inode > 1 "
                             "ORDER BY inode LIMIT ?3 OFFSET ?2";

static char *readdir_query_no_ext = "SELECT inode, "
                                    "       CASE WHEN is_dir "
                                    "       THEN name "
                                    "       ELSE SUBSTR(name, 1, LENGTH(name) - 5)"
                                    "       END, "
                                    "       ctime, mtime, nlink, size, decrypted_size, is_dir "
                                    "FROM entries "
                                    "WHERE parent_inode = ?1 and inode > 1 "
                                    "ORDER BY inode LIMIT ?3 OFFSET ?2";

// Get file information using file inode $1
static char *file_info_query = "SELECT path, header FROM files WHERE inode = ?1";

// Get content list | x'0a' = \n
static char *content_query = "WITH RECURSIVE cte AS ( "
                             "  SELECT e.inode, '/' || e.name as name, e.parent_inode, e.is_dir "
                             "  FROM entries e "
                             "  WHERE parent_inode = 1 AND inode > 1"
                             "  UNION ALL"
                             "  SELECT e.inode, cte.name || '/' || e.name, e.parent_inode, e.is_dir "
                             "  FROM entries e "
                             "  INNER JOIN cte ON cte.inode=e.parent_inode AND cte.is_dir "
                             ")"
                             "SELECT cte.name FROM cte WHERE cte.is_dir IS FALSE ";
                             //"ORDER BY parent_inode, inode DESC;";

static char *content_query_no_ext = "WITH RECURSIVE cte AS ( "
                             "  SELECT e.inode, '/' || e.name as name, e.parent_inode, e.is_dir "
                             "  FROM entries e "
                             "  WHERE parent_inode = 1 AND inode > 1"
                             "  UNION ALL"
                             "  SELECT e.inode, cte.name || '/' || e.name, e.parent_inode, e.is_dir "
                             "  FROM entries e "
                             "  INNER JOIN cte ON cte.inode=e.parent_inode AND cte.is_dir "
                             ")"
                             "SELECT SUBSTR(cte.name, 1, LENGTH(cte.name) - 5) FROM cte WHERE cte.is_dir IS FALSE ";
                             //"ORDER BY parent_inode, inode DESC;";
                             // because only files

// works for both with or without .c4gh extension
static char *content_len_query = "WITH RECURSIVE cte AS ( "
                                 "  SELECT e.inode, '/' || e.name as name, e.parent_inode, e.is_dir "
                                 "  FROM entries e "
                                 "  WHERE parent_inode=1 AND inode>1"
                                 "  UNION ALL"
                                 "  SELECT e.inode, cte.name || '/' || e.name, e.parent_inode, e.is_dir "
                                 "  FROM entries e "
                                 "  INNER JOIN cte ON cte.inode=e.parent_inode AND cte.is_dir "
                                 ")"
                                 "SELECT sum(length(name)+1) FROM cte WHERE cte.is_dir IS FALSE;";

#define DEFAULT_READDIR_LIMIT 100

#define FUSE_CONTENT_ID 2

static size_t content_len = 0;

struct buffer {
  size_t len;
  char *data;
};

static inline size_t
get_content_len(void){

  if(content_len > 0)
    return content_len;

  D1("GET content len");

  int rc = 0;
  sqlite3_stmt *stmt = NULL;
  if(sqlite3_prepare_v2(config.db, content_len_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
     !stmt){
    E("Preparing content len statement: %s | %s", content_len_query, sqlite3_errmsg(config.db));
    return 0;
  }

  while(1){
    rc = sqlite3_step(stmt);
    if( rc == SQLITE_DONE)
      break;

    if( rc == SQLITE_ROW){
      content_len = sqlite3_column_int(stmt, 0);
      break; // only one
    }
    D3("Error content len: %d", rc);
  }

  sqlite3_finalize(stmt);
  return content_len;
}

static inline void
sqlitefs_read_content(fuse_req_t req, struct buffer *b, size_t size, off_t offset)
{
  D1("READ content | offset: %zu | size: %zu | content len: %zu", offset, size, content_len);

  if(offset > b->len){
    offset = 0;
    size = 0;
  }
  if( (offset + size) > b->len ){
    size = b->len - offset;
  }

  D2("=> offset: %zu | size: %zu", offset, size);

  struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
  buf.buf[0].mem = b->data + offset; /* reusing the memory, no need to alloc+copy to a separate buffer */
  buf.buf[0].pos = 0;
  fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static inline void
sqlitefs_open_content(fuse_req_t req, struct fuse_file_info *fi)
{
    sqlite3_stmt *stmt = NULL;
    D1("content statement: %s", QUERY_C4GH(content_query));
    if( sqlite3_prepare_v2(config.db, QUERY_C4GH(content_query), -1, &stmt, NULL) /* != SQLITE_OK */ ||
	!stmt){
      E("Preparing content statement: %s | %s", QUERY_C4GH(content_query), sqlite3_errmsg(config.db));
      return (void) fuse_reply_err(req, EIO);
    }

    struct buffer *buffer = malloc(sizeof(struct buffer));
    size_t size = get_content_len();
    char *p = malloc(size /* * sizeof(char) */);

    if(!buffer || !p){
      sqlite3_finalize(stmt);
      if(buffer) free(buffer);
      if(p) free(p);
      return (void) fuse_reply_err(req, ENOMEM);
    }

    buffer->data = p;
    buffer->len = size;

    char* row = NULL;
    size_t row_len = 0;
    while(sqlite3_step(stmt) == SQLITE_ROW){
      row = (char*)sqlite3_column_text(stmt, 0);
      row_len = (size_t)sqlite3_column_bytes(stmt, 0);
      if(row && row_len > 0){
	memcpy(p, row, row_len);
	p += row_len;
	*p = '\n';
	p++;
      }
    }

    sqlite3_finalize(stmt);
    
    fi->fh = (uint64_t)buffer;
    if (config.file_cache)
      fi->keep_cache = 1;
    fi->direct_io = 0; // disable
    fi->noflush = 1;
    return (void) fuse_reply_open(req, fi);
}


struct fs_file {

  int fd;

  /* header */
  uint8_t *header;
  unsigned int header_size;

  /* parsed header */
  uint8_t *session_keys;
  unsigned int nkeys;
  uint64_t *edit_list;
  unsigned int edit_list_len;

  /* decryption cache and pre-allocation.
   * We pull one segment at a time, even if the requested buffer size 
   * is more. We'll loop until we pulled all the necessary segments.
   *
   * TODO? add an option `readahead` that pull n segments at a time.
   * For the moment, n = 1;
   */
  uint8_t segment[CRYPT4GH_SEGMENT_SIZE];
  size_t  segment_len;

  size_t last_segment;
  int has_data;
  
  uint8_t ciphersegment[CRYPT4GH_CIPHERSEGMENT_SIZE];
  size_t  ciphersegment_len;

  pthread_mutex_t lock;
};

static inline void
fs_file_free(struct fs_file *f)
{
  if(!f) return;
  if(f->header) free(f->header);
  if(f->session_keys) free(f->session_keys);
  if(f->edit_list) free(f->edit_list);
  free(f);
}


static void
sqlitefs_getattr(fuse_req_t req, fuse_ino_t ino,
		 struct fuse_file_info *fi)
{
  D1("GETATTR %lu", ino);

  struct stat s;
  memset(&s, 0, sizeof(struct stat));

  s.st_uid = config.uid;
  s.st_gid = config.gid;
  //s.st_blksize = 512;     /* Block size for filesystem I/O */
  //s.st_blocks = 1;        /* Number of 512B blocks allocated */

  if( ino == FUSE_ROOT_ID ){ /* It's the root directory itself */
    s.st_ino = ino;
    s.st_mode = S_IFDIR | 0500;
    s.st_nlink = 1;
    s.st_size = 0;
    time_t now = time(NULL);
    struct timespec mt = { .tv_sec = config.mounted_at, .tv_nsec = 0L },
                    at = { .tv_sec = now              , .tv_nsec = 0L },
	            ct = { .tv_sec = config.mounted_at, .tv_nsec = 0L };
    s.st_mtim = mt;
    s.st_atim = at;
    s.st_ctim = ct;
    D2("=> root dir");
    return (void) fuse_reply_attr(req, &s, config.attr_timeout);
  }

  if( ino == FUSE_CONTENT_ID ){ /* It's the content file */
    s.st_ino = ino;
    s.st_mode = S_IFREG | 0400;
    s.st_nlink = 1;
    s.st_size = get_content_len();
    time_t now = time(NULL); // TODO: get the sqlite timespec
    struct timespec mt = { .tv_sec = config.mounted_at, .tv_nsec = 0L },
                    at = { .tv_sec = now              , .tv_nsec = 0L },
	            ct = { .tv_sec = config.mounted_at, .tv_nsec = 0L };
    s.st_mtim = mt;
    s.st_atim = at;
    s.st_ctim = ct;
    D2("=> content file");
    return (void) fuse_reply_attr(req, &s, config.attr_timeout);
  }

  sqlite3_stmt *stmt = NULL;
  if(sqlite3_prepare_v2(config.db, getattr_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
     !stmt){
    E("Preparing statement: %s | %s", getattr_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, ino);

  int rc = 0;
  char* expanded_sql = sqlite3_expanded_sql(stmt);
  D3("expanded statement: %s", expanded_sql);
  sqlite3_free(expanded_sql);

  while(1){ /* Execute the query. */

    s.st_ino = 0;
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){

      // ctime: 0, mtime: 1, num_files : 2 , size: 3, decrypted_size:4, is_dir: 5
      time_t ctime = (time_t)sqlite3_column_int(stmt, 0);
      time_t mtime = (time_t)sqlite3_column_int(stmt, 1);
      s.st_nlink = (nlink_t)(uint32_t)sqlite3_column_int(stmt, 2);

      s.st_size = (uint64_t)sqlite3_column_int(stmt, (config.c4gh_decrypt)?4:3);
      
      if(sqlite3_column_int(stmt, 5)) // is_dir
	s.st_mode = S_IFDIR | 0500;
      else 
	s.st_mode = S_IFREG | 0400;
      
      time_t now = time(NULL);
      struct timespec mt = { .tv_sec = mtime, .tv_nsec = 0L },
                      at = { .tv_sec = now  , .tv_nsec = 0L },
                      ct = { .tv_sec = ctime, .tv_nsec = 0L };
      s.st_mtim = mt;
      s.st_atim = at;
      s.st_ctim = ct;
      // success
      s.st_ino = ino;
      break;
    }
  }

  sqlite3_finalize(stmt);

  if(s.st_ino)
    fuse_reply_attr(req, &s, config.attr_timeout);
  else
    fuse_reply_err(req, ENOENT);
}


static void
sqlitefs_lookup(fuse_req_t req, fuse_ino_t inode_p, const char *name)
__attribute__((nonnull(3)))
{
  D1("LOOKUP [%lu]/%s", inode_p, name);

  struct fuse_entry_param e;
  memset(&e, 0, sizeof(e));
  e.attr_timeout = config.attr_timeout;
  e.entry_timeout = config.entry_timeout;

  e.attr.st_uid = config.uid;
  e.attr.st_gid = config.gid;
  //e.attr.st_blksize = 512;     /* Block size for filesystem I/O */
  //e.attr.st_blocks = 1;        /* Number of 512B blocks allocated */

  if( inode_p == FUSE_ROOT_ID && strncmp(name, config.content_filename, config.content_filename_len) == 0){ /* It's the content file */
    e.ino = FUSE_CONTENT_ID;
    e.attr.st_ino = FUSE_CONTENT_ID;
    e.attr.st_mode = S_IFREG | 0400;
    e.attr.st_nlink = 1;
    e.attr.st_size = get_content_len();
    time_t now = time(NULL); // TODO: get the sqlite timespec
    struct timespec mt = { .tv_sec = config.mounted_at, .tv_nsec = 0L },
                    at = { .tv_sec = now              , .tv_nsec = 0L },
	            ct = { .tv_sec = config.mounted_at, .tv_nsec = 0L };
    e.attr.st_mtim = mt;
    e.attr.st_atim = at;
    e.attr.st_ctim = ct;
    return (void) fuse_reply_entry(req, &e);
  }


  sqlite3_stmt *stmt = NULL;
  if( sqlite3_prepare_v2(config.db, QUERY_C4GH(lookup_query), -1, &stmt, NULL) /* != SQLITE_OK */ ||
      !stmt){
    E("Preparing statement: %s | %s", QUERY_C4GH(lookup_query), sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, inode_p);
  sqlite3_bind_text(stmt, 2, name, strlen(name), SQLITE_STATIC); /* fuse handles its lifetime */

  char* expanded_sql = sqlite3_expanded_sql(stmt);
  D3("expanded statement: %s", expanded_sql);

  int rc = 0;
  time_t now = time(NULL);
  struct timespec mt = { .tv_sec = 0   , .tv_nsec = 0L },
                  at = { .tv_sec = now , .tv_nsec = 0L },
                  ct = { .tv_sec = 0   , .tv_nsec = 0L };
  e.attr.st_atim = at;
  
  while(1){ /* Execute the query. */

    e.ino = 0;
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){
      // inode: 0, ctime: 1, mtime: 2, num_files : 3 , size: 4, decrypted_size:5, is_dir: 6
      e.ino = (fuse_ino_t)sqlite3_column_int64(stmt, 0); // success
      e.attr.st_ino = e.ino;
      ct.tv_sec = (time_t)sqlite3_column_int64(stmt, 1);
      mt.tv_sec = (time_t)sqlite3_column_int64(stmt, 2);
      e.attr.st_mtim = mt;
      e.attr.st_ctim = ct;
      e.attr.st_nlink = (nlink_t)(uint32_t)sqlite3_column_int(stmt, 3);

      e.attr.st_size = (uint64_t)sqlite3_column_int64(stmt, (config.c4gh_decrypt)?5:4);

      if(sqlite3_column_int(stmt, 6)) // is_dir
	e.attr.st_mode = S_IFDIR | 0500;
      else 
	e.attr.st_mode = S_IFREG | 0400;
      break;
    }

    D1("looping the lookup: [%d] %s", rc, sqlite3_errmsg(config.db));
  }

  sqlite3_finalize(stmt);
  sqlite3_free(expanded_sql);

  if(e.ino){
    fuse_reply_entry(req, &e);
  } else
    fuse_reply_err(req, ENOENT);
}

/* ============ 

   Directories

   When opening the dir, we make _one_ call to the database,
   getting all the listing (passing limit NULL),
   and we save the PG results struct.
   When doing a readdir, we fill up the given buffer with rows for the PG result and shift the offset.
   Finally, on release, we clean the PG result struct.

   We use readdir_plus, because we can then pass the entire struct stat instead of just { .ino, .st_mode}
   (only using the bits 12-15, ie reg file or directory). That latter would cause a getattr for each entry.

   ============ */

static void
sqlitefs_opendir(fuse_req_t req, fuse_ino_t ino,
		 struct fuse_file_info *fi)
{
  D1("OPENDIR %lu", ino);

  sqlite3_stmt *stmt = NULL; 
  if( sqlite3_prepare_v3(config.db, QUERY_C4GH(readdir_query), -1, SQLITE_PREPARE_PERSISTENT, /* will be reused by readdir_plus */
			 &stmt, NULL) /* != SQLITE_OK */ ||
      !stmt){
    E("Preparing statement: %s | %s", QUERY_C4GH(readdir_query), sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }

  fi->fh = (uint64_t)stmt;
  fi->cache_readdir = 1;
  D3("stmt: %s", sqlite3_sql(stmt)); /* sqlite3_finalize will free it */
  fuse_reply_open(req, fi);
}

static void
sqlitefs_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  D1("RELEASEDIR %lu", ino);

  sqlite3_stmt *stmt = (sqlite3_stmt *)fi->fh;
  if(stmt) sqlite3_finalize(stmt);
  
  fuse_reply_err(req, errno);
}


static void
sqlitefs_readdir_plus(fuse_req_t req, fuse_ino_t ino, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
  D1("READDIR+ %lu | offset: %lu | size: %zu", ino, offset, size);
  int err = 1;

  sqlite3_stmt *stmt = (sqlite3_stmt *)fi->fh;
  if (!stmt)
    return (void) fuse_reply_err(req, EIO);

  D3("Allocating buffer of size: %zu", size);
  char *buf = calloc(1, size);
  if (!buf)
    return (void) fuse_reply_err(req, ENOMEM);

  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, ino);
  sqlite3_bind_int64(stmt, 2, offset);
  sqlite3_bind_int(stmt, 3, DEFAULT_READDIR_LIMIT);

  char* expanded_sql = sqlite3_expanded_sql(stmt);
  D3("expanded statement: %s", expanded_sql);

  char *p;
  size_t remainder = size;
  size_t entsize = 0;
  unsigned int count = 0;

  p = buf;

  struct fuse_entry_param e;
  memset(&e, 0, sizeof(e));
  e.attr_timeout = config.attr_timeout;
  e.entry_timeout = config.entry_timeout;

  time_t ctime, mtime; /* 8 bytes */
  time_t now = time(NULL);
  struct timespec mt = { .tv_sec = 0, .tv_nsec = 0L },
                  at = { .tv_sec = now, .tv_nsec = 0L },
                  ct = { .tv_sec = 0, .tv_nsec = 0L };

  e.attr.st_uid = config.uid;
  e.attr.st_gid = config.gid;
  e.attr.st_atim = at;

  if(ino == FUSE_ROOT_ID && offset == 0){ /* We add the content file */

    D3(" - [%lu]/%s", ino, config.content_filename);

    e.ino = (fuse_ino_t)FUSE_CONTENT_ID;
    e.attr.st_ino = e.ino;
    ct.tv_sec = now;
    mt.tv_sec = now;
    e.attr.st_mtim = mt;
    e.attr.st_ctim = ct;
    e.attr.st_nlink = 1;
    e.attr.st_size = get_content_len();
    e.attr.st_mode = S_IFREG | 0400;

    /* add the entry to the buffer and check size */
    entsize = fuse_add_direntry_plus(req, p, remainder, config.content_filename, &e, FUSE_CONTENT_ID); /* next offset */
    if (entsize > remainder) { /* Not added to the buffer, no space */
      goto skip; /* buffer full, not an error */
    }
    p += entsize;
    remainder -= entsize;
    //offset++;
  }


  while( 1 ){

    err = sqlite3_step(stmt);
    if(err == SQLITE_DONE)
      break;

    if(err == SQLITE_ROW){
      // ino int8, display_name text, ctime int, mtime int, nlink int, size int64, decrypted_size int64, is_dir int
      e.ino = (fuse_ino_t)sqlite3_column_int64(stmt, 0);
      e.attr.st_ino = e.ino;

      ct.tv_sec = (time_t)sqlite3_column_int(stmt, 2);
      mt.tv_sec = (time_t)sqlite3_column_int(stmt, 3);
      e.attr.st_mtim = mt;
      e.attr.st_ctim = ct;
      e.attr.st_nlink = (nlink_t)(uint32_t)sqlite3_column_int(stmt, 4);

      e.attr.st_size = (uint64_t)sqlite3_column_int64(stmt, (config.c4gh_decrypt)?6:5);
      D3("got size: %zu", e.attr.st_size);
    
      if(sqlite3_column_int(stmt, 7)) // is_dir
	e.attr.st_mode = S_IFDIR | 0500;
      else 
	e.attr.st_mode = S_IFREG | 0400;
      
      /* add the entry to the buffer and check size */
      char* pe = (char*)sqlite3_column_text(stmt, 1);
      D3(" - [%lu]/%s", ino, pe);
      entsize = fuse_add_direntry_plus(req, p, remainder, pe, &e, ++offset); /* next offset */

      D3("entsize: %zu | remainder: %zu | size: %zu", entsize, remainder, size);
      if (entsize > remainder) { /* Not added to the buffer, no space */
	break; /* buffer full, not an error */
      }
      p += entsize;
      remainder -= entsize;
      count++;
      continue; /* next row */
    }

    D1("looping the readdir: [%d] %s", err, sqlite3_errmsg(config.db));
  }
  err = 0;
  D3("Processed %u entries", count);

skip:

  sqlite3_reset(stmt);

  if (err && remainder == size){
    E("----------------------- There is an error: %d | remainder: %zu | errno: %d", err, remainder, errno);
    fuse_reply_err(req, (errno)?errno:ENOENT);
  } else {
    fuse_reply_buf(req, buf, size - remainder);
  }
  free(buf);
  sqlite3_free(expanded_sql);
}

/* ============ 

   Opening a Crypt4GH file

   We get the header from the database while opening the file.
   We prepend the header in its own buffer, if the offset is 0.
   Else we send the payload (no need to shift, expect in the first call).

   If decryption is enabled, we decrypt the header on the first read.
   We copy the ciphersegment into a buf and decrypt it.

   ============ */

static void
sqlitefs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{

  D1("OPEN %lu | flags=%d", ino, fi->flags);
  /* No write */
  if( fi->flags & O_RDWR || fi->flags & O_WRONLY)
    return (void)fuse_reply_err(req, EPERM);

  if(ino == FUSE_CONTENT_ID)
    return (void)sqlitefs_open_content(req, fi);

  /* otherwise */

  struct fs_file *fh = calloc(1, sizeof(struct fs_file));
  if (fh == NULL)
    return (void) fuse_reply_err(req, ENOMEM);

  int err = 1;
  sqlite3_stmt *stmt = NULL;
  if( sqlite3_prepare_v2(config.db, file_info_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
      !stmt){
    E("Preparing statement: %s | %s", file_info_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }

  /* Execute the query. */
  sqlite3_bind_int64(stmt, 1, ino);

  while(1){

    err = sqlite3_step(stmt);
    if(err == SQLITE_DONE )
      break;

    if(err == SQLITE_ROW ){
      
      const char* filepath = sqlite3_column_text(stmt, 0);
      const uint8_t *header = sqlite3_column_blob(stmt, 1);
      unsigned int header_size = sqlite3_column_bytes(stmt, 1);
    
      D2("filepath     : %s", filepath);
      D2("header_size  : %u", header_size);

      if (!filepath || !header || header_size == 0){
	errno = EPERM;
	err = 1;
	break;
      }

      int fd = open(filepath, fi->flags & ~O_NOFOLLOW);
      if (fd == -1){
	errno = ENOENT;
	err = 2;
	break;
      }
      
      fh->fd = fd;
      fh->header_size = header_size;
      fh->header = calloc(header_size, sizeof(uint8_t));
      if (fh->header == NULL){
	errno = ENOMEM;
	err = 3;
	break;
      }
      memcpy(fh->header, header, header_size);

      // success
      err = 0;
      break;
    }

    D1("looping the open: [%d] %s", err, sqlite3_errmsg(config.db));
  }

  sqlite3_finalize(stmt);
  
  if(err){
    free(fh);
    int e = (errno)?errno:EPERM;
    E("Error opening the file %lu: [%d] %s", ino, err, strerror(e));
    return (void) fuse_reply_err(req, e);
  }

  fi->fh = (uint64_t)fh;

  fi->noflush = 1;

  if (config.file_cache)
    fi->keep_cache = 1; /* don't flush the kernel cache */

  if (config.direct_io)
    fi->direct_io = 1;

  if(config.c4gh_decrypt){
    if(!config.singlethread)
      pthread_mutex_init(&fh->lock, NULL);
    fh->segment_len = -1;
  }

  fuse_reply_open(req, fi);
}


static void
sqlitefs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  if(ino == FUSE_CONTENT_ID){
    struct buffer *b = (struct buffer *)fi->fh;
    if(b){
      if(b->data) free(b->data);
      free(b);
    }
    return (void) fuse_reply_err(req, 0);
  }
  
  D1("release inode %lu", ino);
  struct fs_file *fh = (struct fs_file *)fi->fh;
  if(fh){
    if(fh->fd > 0) close(fh->fd);
    if(fh->header) free(fh->header);
    free(fh);
  }
  fuse_reply_err(req, 0);
}


/* static allocation instead of one extra dynamic fuse_buf with malloc(sizeof(struct fuse_bufvec) + sizeof(struct fuse_buf)) */
struct fuse_bufvec2 {
  size_t count;
  size_t idx;
  size_t off;
  struct fuse_buf buf[2];
};

static void
sqlitefs_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	      off_t offset, struct fuse_file_info *fi)
{
  
  if(ino == FUSE_CONTENT_ID)
    return (void) sqlitefs_read_content(req, (struct buffer *)fi->fh, size, offset);

  D1("READ %lu | offset: %zu | size: %zu", ino, offset, size);
  struct fs_file *fh = (struct fs_file *)fi->fh;
  if (offset < fh->header_size){

    if ( offset + size < fh->header_size ){
      /* Not asking for much data */
      struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
      buf.buf[0].mem = fh->header + offset;
      buf.buf[0].pos = 0;
      fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);

    } else {
      /* Asking for the header _and_ some more data */
      struct fuse_bufvec2 buf = {
	.count = 2,
	.idx = 0,
	.off = 0,
	.buf = {
	  { .size = fh->header_size - offset,
	    .flags = 0,
	    .mem = fh->header + offset,
	    .fd = -1,
	    .pos = 0,
	  },
	  { .size = size - (fh->header_size - offset),
	    .flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK, /* we don't use FUSE_BUF_FD_RETRY */
	    .fd = fh->fd,
	    .pos = 0,
	  }
	}
      };

      fuse_reply_data(req, (struct fuse_bufvec*)&buf, FUSE_BUF_SPLICE_MOVE);
    }

  } else {
    /* header already sent, sending now the payload, until EOF */
    struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size); /* might be more than what's left in the FD */
    buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK; /* we don't use FUSE_BUF_FD_RETRY */
    buf.buf[0].fd = fh->fd;
    buf.buf[0].pos = offset - fh->header_size;
    fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
  }
}



/*
 * get the cipher segment from the underlying file system
 *
 * TODO: add a variable readahead=<n> and pre-allocate n cipher buffers
 * We then don't pull one segments, but n, if possible.
 * Alternatively, we use the size passed to crypt4gh_read() and allocate that amount (in cipher segments)
 * If size gets bigger, we reallocate. We then don't need the readahead variable, cuz the call will adapt
 * to the largest requested buffer.
 */
static int
c4gh_pull_segment(off_t idx, struct fs_file* fh)
__attribute__((nonnull))
{

  /* reverting the file handle */
  unsigned int requested = CRYPT4GH_CIPHERSEGMENT_SIZE;
  unsigned int received = 0;
  int len;

  off_t offset = idx * CRYPT4GH_CIPHERSEGMENT_SIZE;

  D2("Pulling segment " OFF_FMT " at position: " OFF_FMT, idx, offset);

  /* We loop until we pulled a full segment.
   * In case we pull less, we pull again and stop if we receive a zero-byte response.
   */
  while(requested > 0){
    len = pread(fh->fd,
		(char*)(fh->ciphersegment + received),  /* where to put the data */
		requested,                              /* requested amount      */
		offset + received);                     /* shift                 */
    if(len < 0) /* error */
      return len;
    
    D3("received %d bytes | left: %u", len, requested);
    if(len == 0) /* done */
      break;
    received += len;
    requested -= len;
  }

  if(received < CIPHER_DIFF)
    return -EIO;

  fh->ciphersegment_len = received;

  D3("Pulling segment " OFF_FMT " received %u bytes", idx, received);
  return received;
}


/* get the cipher segment from sqlitefh and decrypt */
static int
c4gh_decrypt_segment(struct fs_file* fh)
__attribute__((nonnull))
{

  unsigned int key_idx = 0;
  uint8_t* session_key = NULL;
  unsigned long long segment_len = 0;

  D3("Decrypting latest segment | nkeys: %d", fh->nkeys);

  /* Loop through all the session keys */
  session_key = fh->session_keys;
  for(key_idx = 0; key_idx < fh->nkeys; key_idx++)
    {
      if(crypto_aead_chacha20poly1305_ietf_decrypt(fh->segment, &segment_len,
						   NULL,
						   fh->ciphersegment + CRYPT4GH_NONCE_SIZE,
						   fh->ciphersegment_len - CRYPT4GH_NONCE_SIZE,
						   NULL, 0, /* no authenticated data */
						   fh->ciphersegment, session_key)
	 ){
	D3("Session key %d failed", key_idx + 1);
	/* try next session key */
	session_key += CRYPT4GH_SESSION_KEY_SIZE;
	continue;
      }
      D3("Session key %d worked | segment length: %llu", key_idx+1, segment_len);
      fh->segment_len = segment_len;
      fh->has_data = 1;
      return 0; /* success */
    }
  /* we tried all the keys, none worked */
  return -EPERM;
}

void
c4gh_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	  off_t offset, struct fuse_file_info *fi)
{

  if(ino == FUSE_CONTENT_ID)
    return (void) sqlitefs_read_content(req, (struct buffer *)fi->fh, size, offset);

  D1("READ (c4gh) %lu | offset: " OFF_FMT " | size: %zu", ino, offset, size);

  int err = -EIO;
  struct fs_file *fh = (struct fs_file*) fi->fh;

  /* Check if we already have the header */
  if(fh->nkeys == 0
     && c4gh_header_parse(fh->header, fh->header_size,
		       config.seckey, config.pubkey,
		       &fh->session_keys, &fh->nkeys,
		       &fh->edit_list, &fh->edit_list_len)
     && fh->nkeys == 0
     ){
    E("Opening header failed");
    return (void) fuse_reply_err(req, EPERM);
  }

  D2("%d session keys", fh->nkeys);

  /* Determine the number of segments spanning the request */
  size_t start_segment = offset / CRYPT4GH_SEGMENT_SIZE;
  unsigned int off = offset % CRYPT4GH_SEGMENT_SIZE;
  size_t _size = off + size;
  size_t nsegments = _size / CRYPT4GH_SEGMENT_SIZE + (_size % CRYPT4GH_SEGMENT_SIZE != 0);

  D2("READ | spanning %lu segment%c | offset within first ciphersegment: %u",
     nsegments, (nsegments>1)?'s':' ', off);

  /* get and decrypt all the relevant segments */
  unsigned int segment_idx = start_segment;
  size_t len;
  unsigned int segment_offset = off; /* for the first one and then reset */
  size_t leftover = size;
  size_t received = 0;

  char* buf = calloc(size, sizeof(char));
  if(buf == NULL)
    return (void) fuse_reply_err(req, ENOMEM);
    
  char *b = buf;
  if(!config.singlethread)
    pthread_mutex_lock(&fh->lock);

  while(leftover > 0){

    /* pull segment */
    if( fh->has_data == 1 && fh->last_segment == segment_idx ){
      D3("Skipping pulling segment %u", segment_idx);
    } else {
      len = c4gh_pull_segment(segment_idx, fh);
      D2("pulling segment got %zu", len);
      
      if(len < 0){ err = len; goto done; }
      if(len == 0) goto done;
      /* decrypt segment */
      D2("Decrypting");
      err = c4gh_decrypt_segment(fh);
      if(err){
	D2("Decrypting error: %d", err);
	goto done;
      }
      fh->last_segment = segment_idx;
    }

    len = fh->segment_len - segment_offset;
    if(len < 0){ err = -EIO; goto done; }

    if(leftover < len) /* minimum */
      len = leftover;

    D3("Copying %zu bytes | segment %u | offset: %u | size: %zu", len, segment_idx, segment_offset, size);
    memcpy(b, fh->segment + segment_offset, len);
    leftover -= len;
    b += len;
    segment_idx++;
    segment_offset = 0; /* reset */
  }
  err = 0;

done:

  if(!config.singlethread)
    pthread_mutex_unlock(&fh->lock);

  if(err < 0){
    if(buf) free(buf);
    return (void) fuse_reply_err(req, -err);
  }

  D3("Answering %zu bytes", size - leftover);

  struct fuse_bufvec bufv = FUSE_BUFVEC_INIT(size);
  bufv.buf[0].mem = buf;
  bufv.buf[0].pos = 0;
  fuse_reply_data(req, &bufv, FUSE_BUF_SPLICE_MOVE);
  free(buf);
}


struct fuse_lowlevel_ops*
fs_operations(void)
{

  static struct fuse_lowlevel_ops fs_oper;

  fs_oper.lookup       = sqlitefs_lookup;
  fs_oper.getattr      = sqlitefs_getattr;
  fs_oper.opendir      = sqlitefs_opendir;
  fs_oper.readdirplus  = sqlitefs_readdir_plus;
  fs_oper.releasedir   = sqlitefs_releasedir;
  fs_oper.open         = sqlitefs_open;
  fs_oper.release      = sqlitefs_release;

  if(config.c4gh_decrypt)
    fs_oper.read         = c4gh_read;
  else
    fs_oper.read         = sqlitefs_read;

  //fs_oper.statfs       = sqlitefs_statfs;
  return &fs_oper;
}


//WITH RECURSIVE cte AS (                                     SELECT e.inode, '/' || e.name as name, e.parent_inode, e.is_dir                                     FROM entries e                                     WHERE parent_inode=1 AND inode>1                                    UNION ALL                                    SELECT e.inode, cte.name || '/' || e.name, e.parent_inode, e.is_dir                                     FROM entries e                                     INNER JOIN cte ON cte.inode=e.parent_inode AND cte.is_dir                                   )                                  SELECT sum(length(name)+1) FROM cte WHERE cte.is_dir IS FALSE;
