/**********************************************************************************
 * Read-only Crypt4GH file system, listing information from an SQLite "database".
 *
 *  Author:  Frédéric Haziza <silverdaz@gmail.com>
 *    Date:  November 2024
 *
 *  This program can be distributed under the terms of the GNU Affero GPL.
 *  See the LICENSE file.
 **********************************************************************************/

#pragma once

#define _GNU_SOURCE /* avoid implicit declaration of *pt* functions */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "2.0"
#endif

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION FUSE_MAKE_VERSION(3, 14)
#endif

#include <fuse_lowlevel.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <limits.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <ctype.h>

#define OFF_FMT "%lu"
#define INO_FMT "%lu"

#ifndef _PATH_TTY
# define _PATH_TTY "/dev/tty"
#endif

/* #if !defined(__GNUC__) || (__GNUC__ < 2) */
/* # define __attribute__(x) */
/* #endif /\* !defined(__GNUC__) || (__GNUC__ < 2) *\/ */

/* #if !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__) */
/* # define __nonnull__(x) */
/* #endif */

#define __attribute__(x)
#define __nonnull__(x)

#ifndef MAP_LOCKED
#  define MAP_LOCKED 0
#endif

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#  define MAP_ANONYMOUS MAP_ANON
#endif

/* OpenBSD function replacements */
#include "keys/base64.h"
#include "keys/sha2.h"
#include "keys/blf.h"
#include "keys/readpassphrase.h"

#ifndef HAVE_BCRYPT_PBKDF
int	bcrypt_pbkdf(const char *, size_t, const u_int8_t *, size_t,
    u_int8_t *, size_t, unsigned int);
#endif

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void *p, size_t n);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_TIMINGSAFE_BCMP
int timingsafe_bcmp(const void *, const void *, size_t);
#endif


#include "sqlite-3.45.2/sqlite3.h"
#include "crypt4gh.h"
#include "keys/key.h"

struct fs_config {

  uid_t uid;
  gid_t gid;
  time_t mounted_at;
  int direct_io;

  int is_readwrite;
  unsigned int dperm;
  unsigned int fperm;

  int local_debug;
  int verbose;
  int foreground;
  char *progname;
  int show_version;
  int show_help;

  int show_dotdot;

  char *mountpoint;
  mode_t mnt_mode;
  double entry_timeout; /* in seconds, for which name lookups will be cached */
  double attr_timeout; /* in seconds for which file/directory attributes are cached */

  unsigned int dir_cache;
  unsigned int file_cache;

  /* if Crypt4GH is enabled */
  char* seckeypath;
  char* passphrase;
  char* passphrase_from_env;
  uint8_t seckey[crypto_kx_SECRETKEYBYTES]; /* unlocked secret key. TODO: better protect it */
  uint8_t pubkey[crypto_kx_PUBLICKEYBYTES];

  /* SQLite database */
  char* db_path;
  sqlite3* db;
  
  /* multithreaded */
  int singlethread;
  int clone_fd;
  int max_idle_threads;
  int max_threads;
};


extern struct fs_config config;
struct fuse_lowlevel_ops* fs_operations(void);

/* DEBUG output */
#ifdef NO_DEBUG
#define D1(fmt, ...)
#define D2(fmt, ...)
#define D3(fmt, ...)
#else
#define D1(fmt, ...) if(config.local_debug > 0) fprintf(stderr, "# " fmt "\n", ##__VA_ARGS__)
#define D2(fmt, ...) if(config.local_debug > 1) fprintf(stderr, "#      " fmt "\n", ##__VA_ARGS__)
#define D3(fmt, ...) if(config.local_debug > 2) fprintf(stderr, "#           " fmt "\n", ##__VA_ARGS__)
#endif

#define E(fmt, ...)  fprintf(stderr, "\x1b[31mError:\x1b[0m " fmt "\n", ##__VA_ARGS__)
#define W(fmt, ...)  fprintf(stderr, "Warning: " fmt "\n", ##__VA_ARGS__)
