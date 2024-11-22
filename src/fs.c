/**********************************************************************************
 * Read-only Crypt4GH file system, listing information from an SQLite "database".
 *
 *  Author:  Frédéric Haziza <silverdaz@gmail.com>
 *    Date:  November 2024
 *
 *  This program can be distributed under the terms of the GNU Affero GPL.
 *  See the file COPYING.
 **********************************************************************************/

#include "includes.h"

// Lookup entry
static char *lookup_query = "SELECT inode, ctime, mtime, nlink, size, is_dir "
                             "FROM entries e "
                             "WHERE parent_inode = ?1 and inode > 1 and name = ?2";

// Get the attr $1: inode
static char *getattr_query = "SELECT ctime, mtime, nlink, size, is_dir "
                             "FROM entries e "
                             "WHERE inode = ?1 and inode > 1";

// Read directory $1: parent inode, $2: offset (limit = 100)
static char *readdir_query = "SELECT inode, name, ctime, mtime, nlink, size, is_dir "
                             "FROM entries "
                             "WHERE parent_inode = ?1 and inode > 1 "
                             "ORDER BY inode LIMIT ?3 OFFSET ?2"
                             ";";

// Get file information using file inode $1
static char *file_info_query = "SELECT case when rel_path is null then null else concat(rtrim(mountpoint,'/'), '/', ltrim(rel_path,'/')) end AS path,"
                               "       header, payload_size, prepend, append FROM files WHERE inode = ?1";

// Get the extended attr $1: inode
static char *getxattr_size_query = "SELECT LENGTH(value) FROM extended_attributes WHERE inode = ?1 AND name = ?2";
// value won't (or shouldn't) contain NUL-characters
static char *getxattr_query = "SELECT value FROM extended_attributes WHERE inode = ?1 AND name = ?2";

static char *listxattr_size_query = "SELECT SUM(LENGTH(name)+1) AS value FROM extended_attributes WHERE inode = ?1";
// value won't contain NUL-characters
static char *listxattr_query = "SELECT GROUP_CONCAT(name, char(0)) || char(0) AS value FROM extended_attributes WHERE inode = ?1";

#define DEFAULT_READDIR_LIMIT 100

static void
crypt4gh_sqlite_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
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

  sqlite3_stmt *stmt = NULL;
  if(sqlite3_prepare_v2(config.db, getattr_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
     !stmt){
    E("Preparing statement: %s | %s", getattr_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, ino);

  if(config.debug > 2){ // DEBUG 3
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D3("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  int rc = 0;

  while(1){ /* Execute the query. */

    s.st_ino = 0;
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){

      // ctime: 0, mtime: 1, num_files : 2 , size: 3, is_dir: 4
      time_t ctime = (time_t)sqlite3_column_int(stmt, 0);
      time_t mtime = (time_t)sqlite3_column_int(stmt, 1);
      s.st_nlink = (nlink_t)(uint32_t)sqlite3_column_int(stmt, 2);
      s.st_size = (uint64_t)sqlite3_column_int(stmt, 3);
      
      if(sqlite3_column_int(stmt, 4)) // is_dir
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
crypt4gh_sqlite_lookup(fuse_req_t req, fuse_ino_t inode_p, const char *name)
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

  sqlite3_stmt *stmt = NULL;
  if( sqlite3_prepare_v2(config.db, lookup_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
      !stmt){
    E("Preparing statement: %s | %s", lookup_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, inode_p);
  sqlite3_bind_text(stmt, 2, name, strlen(name), SQLITE_STATIC); /* fuse handles its lifetime */

  if(config.debug > 2){ // DEBUG 3
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D3("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  int rc, loop_count = 10;
  time_t now = time(NULL);
  struct timespec mt = { .tv_sec = 0   , .tv_nsec = 0L },
                  at = { .tv_sec = now , .tv_nsec = 0L },
                  ct = { .tv_sec = 0   , .tv_nsec = 0L };
  e.attr.st_atim = at;
  
  while(loop_count--){ /* Execute the query. */

    e.ino = 0;
    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){
      // inode: 0, ctime: 1, mtime: 2, num_files : 3 , size: 4, is_dir: 5
      e.ino = (fuse_ino_t)sqlite3_column_int64(stmt, 0); // success
      e.attr.st_ino = e.ino;
      ct.tv_sec = (time_t)sqlite3_column_int64(stmt, 1);
      mt.tv_sec = (time_t)sqlite3_column_int64(stmt, 2);
      e.attr.st_mtim = mt;
      e.attr.st_ctim = ct;
      e.attr.st_nlink = (nlink_t)(uint32_t)sqlite3_column_int(stmt, 3);

      e.attr.st_size = (uint64_t)sqlite3_column_int64(stmt, 4);

      if(sqlite3_column_int(stmt, 5)) // is_dir
	e.attr.st_mode = S_IFDIR | 0500;
      else 
	e.attr.st_mode = S_IFREG | 0400;
      break;
    }

    D1("(%d) lookup: [%d] %s", loop_count, rc, sqlite3_errmsg(config.db));
  }

  sqlite3_finalize(stmt);

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
crypt4gh_sqlite_opendir(fuse_req_t req, fuse_ino_t ino,
		 struct fuse_file_info *fi)
{
  D1("OPENDIR %lu", ino);

  sqlite3_stmt *stmt = NULL; 
  if( sqlite3_prepare_v3(config.db, readdir_query, -1, SQLITE_PREPARE_PERSISTENT, /* will be reused by readdir_plus */
			 &stmt, NULL) /* != SQLITE_OK */ ||
      !stmt){
    E("Preparing statement: %s | %s", readdir_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }

  fi->fh = (uint64_t)stmt;
  fi->cache_readdir = 1;
  D3("stmt: %s", sqlite3_sql(stmt)); /* sqlite3_finalize will free it */
  fuse_reply_open(req, fi);
}

static void
crypt4gh_sqlite_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  D1("RELEASEDIR %lu", ino);

  sqlite3_stmt *stmt = (sqlite3_stmt *)fi->fh;
  if(stmt) sqlite3_finalize(stmt);
  
  fuse_reply_err(req, errno);
}


static void
crypt4gh_sqlite_readdir_plus(fuse_req_t req, fuse_ino_t ino, size_t size,
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

  if(config.debug > 2){ // DEBUG 3
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D3("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  char *p;
  size_t remainder = size;
  size_t entsize = 0;
  unsigned int count = 0, loop_max_errors = 100;

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

  /* Handle the '.' and '..' di*/
  if(!config.show_dotdot || offset >= 2)
    goto content;

  e.attr.st_mtim = mt;
  e.attr.st_ctim = ct;
  e.attr.st_atim = at;
  e.attr.st_nlink = 1;
  e.attr.st_size = 0;
  e.attr.st_mode = S_IFDIR | 0500;

  if(offset < 1){
    e.ino = 2;
    e.attr.st_ino = e.ino;
    e.attr.st_uid = 0;
    e.attr.st_gid = 0;
    D3(" - [%lu]/..", ino);
    entsize = fuse_add_direntry_plus(req, p, remainder, "..", &e, ++offset);
    if (entsize > remainder) { /* Not added to the buffer, no space */
      goto skip; /* buffer full, not an error */
    }
    p += entsize;
    remainder -= entsize;
    /* reset */
    e.attr.st_uid = config.uid;
    e.attr.st_gid = config.gid;
  }
    
  if(offset < 2){
    e.ino = ino;
    e.attr.st_ino = e.ino;
    D3(" - [%lu]/.", ino);
    entsize = fuse_add_direntry_plus(req, p, remainder, ".", &e, ++offset);
    if (entsize > remainder) { /* Not added to the buffer, no space */
      goto skip; /* buffer full, not an error */
    }
    p += entsize;
    remainder -= entsize;
  }

content:

  while( 1 ){

    err = sqlite3_step(stmt);
    if(err == SQLITE_DONE)
      break;

    if(err == SQLITE_ROW){
      // ino int8, display_name text, ctime int, mtime int, nlink int, decrypted_size int64, is_dir int
      e.ino = (fuse_ino_t)sqlite3_column_int64(stmt, 0);
      e.attr.st_ino = e.ino;

      ct.tv_sec = (time_t)sqlite3_column_int(stmt, 2);
      mt.tv_sec = (time_t)sqlite3_column_int(stmt, 3);
      e.attr.st_mtim = mt;
      e.attr.st_ctim = ct;
      e.attr.st_nlink = (nlink_t)(uint32_t)sqlite3_column_int(stmt, 4);
      e.attr.st_size = (uint64_t)sqlite3_column_int64(stmt, 5);
    
      if(sqlite3_column_int(stmt, 6)) // is_dir
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
    
    if(loop_max_errors-- == 0) break;
    D1("(%u) readdir: [%d] %s", loop_max_errors, err, sqlite3_errmsg(config.db));
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
}

/* ============ 

   Opening a Crypt4GH file

   We get the header from the database while opening the file.
   We prepend the header in its own buffer, if the offset is 0.
   Else we send the payload (no need to shift, expect in the first call).

   If decryption is enabled, we decrypt the header on the first read.
   We copy the ciphersegment into a buf and decrypt it.

   ============ */

struct fs_file {

  int fd;
  fuse_ino_t ino;

  uint64_t payload_size; /* decrypted size */

  /* prepend data */
  uint8_t *prepend;
  uint64_t prepend_size;

  /* append data */
  uint8_t *append;
  uint64_t append_size;

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
  sqlite3_stmt *stmt;
};

static inline void
fs_file_free(struct fs_file *f)
{
  D3("Cleaning file %lu", f->ino);
  if(!f) return;
  if(f->fd > 0) close(f->fd);

  if(f->stmt) sqlite3_finalize(f->stmt);
  // f->stmt = NULL;

  if(f->session_keys) free(f->session_keys);
  if(f->edit_list) free(f->edit_list);
  free(f);
}

static void
crypt4gh_sqlite_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{

  D1("OPEN %lu | flags=%d", ino, fi->flags);
  /* No write */
  if( fi->flags & O_RDWR || fi->flags & O_WRONLY)
    return (void)fuse_reply_err(req, EPERM);

  struct fs_file *fh = calloc(1, sizeof(struct fs_file));
  if (fh == NULL)
    return (void) fuse_reply_err(req, ENOMEM);

  int err = 1;
  fh->ino = ino;

  if( sqlite3_prepare_v2(config.db, file_info_query, -1, &fh->stmt, NULL) /* != SQLITE_OK */ ||
      !fh->stmt){
    E("Preparing statement: %s | %s", file_info_query, sqlite3_errmsg(config.db));
    fs_file_free(fh);
    return (void) fuse_reply_err(req, EIO);
  }

  /* Execute the query. */
  sqlite3_bind_int64(fh->stmt, 1, ino);

  while(1){

    err = sqlite3_step(fh->stmt);
    if(err == SQLITE_DONE )
      break;

    if(err == SQLITE_ROW ){
      
      const char* filepath = sqlite3_column_text(fh->stmt, 0);

      fh->header = (uint8_t *)sqlite3_column_blob(fh->stmt, 1);
      fh->header_size = (unsigned int)sqlite3_column_bytes(fh->stmt, 1);

      fh->payload_size = sqlite3_column_int64(fh->stmt, 2);

      fh->prepend = (uint8_t *)sqlite3_column_blob(fh->stmt, 3);
      fh->prepend_size = (uint64_t)sqlite3_column_bytes(fh->stmt, 3);

      fh->append = (uint8_t *)sqlite3_column_blob(fh->stmt, 4);
      fh->append_size = (uint64_t)sqlite3_column_bytes(fh->stmt, 4);
    
      D2("filepath    : %s", filepath);
      D2("header_size : %u", fh->header_size);
      D2("payload_size: %lu", fh->payload_size);
      D2("prepend_size: %lu", fh->prepend_size);
      D2("append_size : %lu", fh->append_size);

      /* File settings */
      if(filepath != NULL && fh->payload_size > 0){
	fh->fd = open(filepath, fi->flags);
	if (fh->fd == -1){
	  D2("failed to open %s: %d | %s", filepath, errno, strerror(errno));
	  err = 1;
	  break;
	}
      }

#if 0
      if(fh->header_size > 4)
	D2("header: %02x%02x%02x%02x", fh->header[0], fh->header[1], fh->header[2], fh->header[3]);

      if(fh->prepend_size > 4)
	D2("prepend: %02x%02x%02x%02x", fh->prepend[0], fh->prepend[1], fh->prepend[2], fh->prepend[3]);

      if(fh->append_size > 4)
	D2("append: %02x%02x%02x%02x", fh->append[0], fh->append[1], fh->append[2], fh->append[3]);
#endif

      err = 0;
      break;
    }

    D1("looping the open: [%d] %s", err, sqlite3_errmsg(config.db));
  }

  if(err){
    int e = (errno)?errno:EPERM;
    E("Error opening the file %lu: [%d] %s", ino, err, strerror(e));
    fs_file_free(fh); // done by release ?
    return (void) fuse_reply_err(req, e);
  }

  fi->fh = (uint64_t)fh;

#if FUSE_VERSION >= 311 
  fi->noflush = 1; /* from 3.11 */
#endif

  if (config.file_cache)
    fi->keep_cache = 1; /* don't flush the kernel cache */

  if (config.direct_io)
    fi->direct_io = 1;

  if(!config.singlethread)
    pthread_mutex_init(&fh->lock, NULL);

  fuse_reply_open(req, fi);
}


static void
crypt4gh_sqlite_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  D1("RELEASE inode %lu", ino);
  fs_file_free((struct fs_file *)fi->fh);
  fuse_reply_err(req, 0);
}


/* static allocation instead of one extra dynamic fuse_buf with malloc(sizeof(struct fuse_bufvec) + 2 * sizeof(struct fuse_buf)) */
struct fuse_bufvec3 {
  size_t count;
  size_t idx;
  size_t off;
  struct fuse_buf buf[3];
};

static int c4gh_read(off_t offset, size_t size, struct fs_file *fh, char* b);

static void
crypt4gh_sqlite_read(fuse_req_t req, fuse_ino_t ino, size_t size,
	 off_t offset, struct fuse_file_info *fi)
{
  D1("READ ino:%lu | offset: %zu | size: %zu", ino, offset, size);
  struct fs_file *fh = (struct fs_file *)fi->fh;

  /*     0  prepend           payload           append    
   *     |===========|=======================|==========|
   *              |---------------|
   *             offset         offset+size
   *  Cases:
   *      A)  |----|
   *      B)  |-----------|
   *      C)  |----------------------------------| (for small files)
   *      D)              |----------|
   *      E)                          |---------------|
   *      F)                                      |---|
   */

  size_t limit = offset + size;
  size_t append_offset = fh->prepend_size + fh->payload_size;

  struct fuse_buf *prepend_fbuf = NULL, *append_fbuf = NULL, *data_fbuf = NULL;
  char *buf=NULL;
  size_t prepend_len = 0;
  size_t append_len = 0;
  int err = 0;

  /* Prepare prepend data */
  if(fh->prepend != NULL && offset < fh->prepend_size) {

    if(limit > fh->prepend_size)
      prepend_len = (fh->prepend_size - offset);
    else
      prepend_len = size;

    prepend_fbuf = (struct fuse_buf *)calloc(1, sizeof(struct fuse_buf));
    if(!prepend_fbuf){ err = -ENOMEM; goto error; }
    /* memset(prepend_fbuf, '\0', sizeof(struct fuse_buf)); */

    prepend_fbuf->size = prepend_len;
    //prepend_fbuf->flags = 0;
    prepend_fbuf->mem = fh->prepend + offset;
    //prepend_fbuf->pos = offset; // not used with .mem

  }

  /* Prepare append data */
  if(fh->append != NULL && limit > append_offset) {

    append_len = (limit - append_offset);
    if ( size < append_len )
      append_len = size;

    append_fbuf = (struct fuse_buf *)calloc(1, sizeof(struct fuse_buf));
    if(!append_fbuf){ err = -ENOMEM; goto error; }
    /* memset(append_fbuf, '\0', sizeof(struct fuse_buf)); */

    append_fbuf->size = append_len;
    //append_fbuf->flags = 0;
    append_fbuf->mem = fh->append + ((offset < append_offset) ? 0 : (offset - append_offset));
    //append_fbuf->pos = ((offset < append_offset) ? 0 : (offset - append_offset)); // not used with .mem

  }

  D3("prepend_len: %zu | prepend size: %zu", prepend_len, fh->prepend_size);
  D3("append_len: %zu | append size: %zu", append_len, fh->append_size);

  /* Now the data */
  if(limit > fh->prepend_size && offset < append_offset
     && fh->payload_size > 0){

    size_t data_offset = offset + prepend_len - fh->prepend_size;
    size_t data_size = size - prepend_len - append_len;
    if(data_size > fh->payload_size)
      data_size = fh->payload_size;

    D3("data offset: %zu", data_offset);
    D3("data size: %zu", data_size);

    data_fbuf = (struct fuse_buf *)calloc(1, sizeof(struct fuse_buf));
    if(!data_fbuf){ err = -ENOMEM; goto error; }

    if(fh->header){ // Try Crypt4GH data

      buf = calloc(data_size, sizeof(char));
      if(!buf){ err = -ENOMEM; goto error; }
      
      D3("encrypted data: offset %zu, size: %zu", data_offset, data_size);
      err = c4gh_read(data_offset, data_size, fh, buf);
      if(err < 0){ D1("c4gh_read error: %s", strerror(-err)); goto error; }
      
      data_fbuf->size = data_size;
      //data_fbuf->flags = 0;
      data_fbuf->mem = buf;
      //append_fbuf->pos = ((offset < append_offset) ? 0 : (offset - append_offset)); // not used with .mem

    } else { // not Crypt4GH

      data_fbuf->size = data_size;
      data_fbuf->flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
      data_fbuf->fd = fh->fd;
      data_fbuf->pos = data_offset;
    }

  }

  /* Finally: Outputting the buffers */
  struct fuse_bufvec3 bufv;
  bufv.count = 0;
  bufv.idx = 0;
  bufv.off = 0;
  if(prepend_fbuf){ 
    struct fuse_buf *b = &bufv.buf[bufv.count++];
    b->size = prepend_fbuf->size;
    b->flags = prepend_fbuf->flags;
    b->mem = prepend_fbuf->mem;
    b->pos = prepend_fbuf->pos;
    b->fd = prepend_fbuf->fd;
    D3("we have a prepend buf");
  }
  if(data_fbuf){
    struct fuse_buf *b = &bufv.buf[bufv.count++];
    b->size = data_fbuf->size;
    b->flags = data_fbuf->flags;
    b->mem = data_fbuf->mem;
    b->pos = data_fbuf->pos;
    b->fd = data_fbuf->fd;
    D3("we have a data buf");
  }
  if(append_fbuf){
    struct fuse_buf *b = &bufv.buf[bufv.count++]; 
    b->size = append_fbuf->size;
    b->flags = append_fbuf->flags;
    b->mem = append_fbuf->mem;
    b->pos = append_fbuf->pos;
    b->fd = append_fbuf->fd;
    D3("we have an append buf");
  }

  D3("buf count: %d", bufv.count);

  /* optimization if count == 1 && not fd */
  if(bufv.count == 1 && !(bufv.buf[0].flags & FUSE_BUF_IS_FD)){
    fuse_reply_buf(req, bufv.buf[0].mem, bufv.buf[0].size);
  } else {
    fuse_reply_data(req, (struct fuse_bufvec*)&bufv, FUSE_BUF_SPLICE_MOVE);
  }
  /* fallthrough for cleanup */

error:

  if(prepend_fbuf) free(prepend_fbuf);
  if(append_fbuf) free(append_fbuf);
  if(data_fbuf) free(data_fbuf);
  if(buf) free(buf);

  if(err) fuse_reply_err(req, -err);
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

static int
c4gh_read(off_t offset, size_t size, struct fs_file *fh, char* b)
{
  D1("READ (c4gh) offset: " OFF_FMT " | size: %zu", offset, size);

  int err = -EIO;

  if(!config.singlethread)
    pthread_mutex_lock(&fh->lock);

  /* Check if we already have the header */
  if(fh->nkeys == 0
     && c4gh_header_parse(fh->header, fh->header_size,
		       config.seckey, config.pubkey,
		       &fh->session_keys, &fh->nkeys,
		       &fh->edit_list, &fh->edit_list_len)
     && fh->nkeys == 0
     ){
    E("Opening header failed");
    if(!config.singlethread)
      pthread_mutex_unlock(&fh->lock);
    return -EPERM;
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

  while(leftover > 0){

    /* pull segment */
    if( fh->has_data == 1 && fh->last_segment == segment_idx ){
      D3("Skipping pulling segment %u", segment_idx);
    } else {
      len = c4gh_pull_segment(segment_idx, fh);
      D3("pulling segment got %zu", len);
      
      if(len < 0){ err = len; goto done; }
      if(len == 0) goto done;
      /* decrypt segment */
      D2("Decrypting");
      err = c4gh_decrypt_segment(fh);
      D2("Decrypting error: %d", err);
      if(err)
	goto done;
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

  return err;
}


/* ============ 
   Extended attributes
   ============ */

static int
crypt4gh_sqlite_xattr_size(fuse_ino_t ino, const char* name, const char* sql)
{
  int value_len = 0;

  // get the list and its size
  sqlite3_stmt *stmt = NULL;
  if(sqlite3_prepare_v2(config.db, sql, -1, &stmt, NULL) /* != SQLITE_OK */ ||
     !stmt){
    E("Preparing statement: %s | %s", sql, sqlite3_errmsg(config.db));
    return -EIO;
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, ino);
  if(name)
    sqlite3_bind_text(stmt, 2, name, strlen(name), SQLITE_STATIC); /* fuse handles its lifetime */

  if(config.debug > 2){ // DEBUG 3
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D3("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  int rc = 0;
  while(1){ /* Execute the query. */

    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){
      value_len = sqlite3_column_int(stmt, 0);
      break;
    }
  }

  sqlite3_finalize(stmt);
  return value_len;
}


static void
crypt4gh_sqlite_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size)
{
  D1("LISTXATTR %lu | size:%zu", ino, (int)size);

  if(size == 0){ /* requesting the buffer size */
    int vlen = crypt4gh_sqlite_xattr_size(ino, NULL, listxattr_size_query);
    if(vlen < 0)
      return (void) fuse_reply_err(req, -vlen);
    D2("attributes: %d", vlen);
    return (void) fuse_reply_xattr(req, vlen);
  }

  char* value = NULL;
  unsigned int value_len = 0;

  // get the list and its size
  sqlite3_stmt *stmt = NULL;
  if(sqlite3_prepare_v2(config.db, listxattr_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
     !stmt){
    E("Preparing statement: %s | %s", listxattr_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, ino);

  if(config.debug > 2){ // DEBUG 3
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D3("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  int rc = 0;
  while(1){ /* Execute the query. */

    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){
      value_len = sqlite3_column_bytes(stmt, 0);
      value = (char*)sqlite3_column_blob(stmt, 0);
      break;
    }
  }

  if(value_len)
    D2("attributes: %u | %.*s", value_len, (int)value_len, value);

  if(size < value_len)
    fuse_reply_err(req, ERANGE);
  else
    fuse_reply_buf(req, value, value_len);

  sqlite3_finalize(stmt);
}


static void
crypt4gh_sqlite_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
  D1("GETXATTR %lu: %s | size:%zu", ino, name, size);

  if(size == 0){ /* requesting the buffer size */
    int vlen = crypt4gh_sqlite_xattr_size(ino, name, getxattr_size_query);
    if(vlen < 0)
      return (void) fuse_reply_err(req, -vlen);
    D2("attributes: %d", vlen);
    return (void) fuse_reply_xattr(req, vlen);
  }

  char* value = NULL;
  unsigned int value_len = 0;

  sqlite3_stmt *stmt = NULL;
  if(sqlite3_prepare_v2(config.db, getxattr_query, -1, &stmt, NULL) /* != SQLITE_OK */ ||
     !stmt){
    E("Preparing statement: %s | %s", getxattr_query, sqlite3_errmsg(config.db));
    return (void) fuse_reply_err(req, EIO);
  }
  
  /* Bind arguments */
  sqlite3_bind_int64(stmt, 1, ino);
  sqlite3_bind_text(stmt, 2, name, strlen(name), SQLITE_STATIC); /* fuse handles its lifetime */

  if(config.debug > 2){ // DEBUG 3
    char* expanded_sql = sqlite3_expanded_sql(stmt);
    D3("expanded statement: %s", expanded_sql);
    sqlite3_free(expanded_sql);
  }

  int rc = 0;

  while(1){ /* Execute the query. */

    rc = sqlite3_step(stmt);
    if(rc == SQLITE_DONE)
      break;

    if(rc == SQLITE_ROW){
      value_len = sqlite3_column_bytes(stmt, 0);
      value = (char*)sqlite3_column_blob(stmt, 0);
      break;
    }
  }

  D2("value: %u | %.*s", value_len, (int)value_len, value);

  if(size < value_len)
    fuse_reply_err(req, ERANGE);
  else
    fuse_reply_buf(req, value, value_len);

  sqlite3_finalize(stmt);
}


struct fuse_lowlevel_ops*
fs_operations(void)
{

  static struct fuse_lowlevel_ops fs_oper;

  memset(&fs_oper, 0, sizeof(struct fuse_lowlevel_ops));

  fs_oper.lookup       = crypt4gh_sqlite_lookup;
  fs_oper.getattr      = crypt4gh_sqlite_getattr;

  fs_oper.opendir      = crypt4gh_sqlite_opendir;
  fs_oper.readdirplus  = crypt4gh_sqlite_readdir_plus;
  fs_oper.releasedir   = crypt4gh_sqlite_releasedir;

  fs_oper.open         = crypt4gh_sqlite_open;
  fs_oper.release      = crypt4gh_sqlite_release;
  fs_oper.read         = crypt4gh_sqlite_read;

  fs_oper.listxattr    = crypt4gh_sqlite_listxattr;
  fs_oper.getxattr     = crypt4gh_sqlite_getxattr;

  //fs_oper.statfs       = crypt4gh_sqlite_statfs;
  return &fs_oper;
}
