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

#define DEFAULT_MAX_THREADS   10
#define DEFAULT_ENTRY_TIMEOUT 24 * 3600 /* one day */
#define DEFAULT_ATTR_TIMEOUT  24 * 3600 /* one day */
#define MAX_PASSPHRASE        1024
#define MIN(a,b) ((a) < (b))?(a):(b)

#define FS_NAME "crypt4gh-sqlite.fs"

/* global variable */
struct fs_config config;

static void usage(struct fuse_args *args)
{
	printf(
"usage: %s <sqlite_filepath> <mountpoint> [options]\n"
"\n"
"    -h   --help            print help\n"
"    -V   --version         print version\n"
"    -f                     foreground operation\n"
"    -s                     disable multi-threaded operation\n"
"    -o opt,[opt...]        mount options\n"
"    -d, --debug            print some debugging information (implies -f)\n"
"        --debug=N          debug level <N>\n"
"    -o direct_io           enable direct i/o\n"
"    -o file_cache          instructs the kernel to cache output data\n"
"    -o file_cache          instructs the kernel to cache output data\n"
"    -o entry_timeout=S     seconds for which lookup names are cached [default: one day]\n"
"    -o attr_timeout=S      seconds for which directories/files attributes are cached [default: one day]\n"
"    -o dotdot              Shows '.' and '..' directories [default: ignored]\n"
"\n"
"Crypt4GH Options (if enabled):\n"
"    -o seckey=<path>       Absolute path to the Crypt4GH secret key\n"
"    -o passphrase_from_env=<ENVVAR>\n"
"                           read passphrase from environment variable <ENVVAR>\n"
, args->argv[0]);
}


#define CRYPT4GH_SQLITE_OPT(t, p, v) { t, offsetof(struct fs_config, p), v }

static struct fuse_opt fs_opts[] = {

	CRYPT4GH_SQLITE_OPT("-h",		show_help, 1),
	CRYPT4GH_SQLITE_OPT("--help",	show_help, 1),
	CRYPT4GH_SQLITE_OPT("-V",		show_version, 1),
	CRYPT4GH_SQLITE_OPT("--version",	show_version, 1),
	CRYPT4GH_SQLITE_OPT("-v",		verbose, 1),
	CRYPT4GH_SQLITE_OPT("verbose",	verbose, 1),
	CRYPT4GH_SQLITE_OPT("-f",		foreground, 1),

	CRYPT4GH_SQLITE_OPT("-d",		debug, 1),
	CRYPT4GH_SQLITE_OPT("debug",	debug, 1),
	CRYPT4GH_SQLITE_OPT("debug=%u",     debug, 0),

	CRYPT4GH_SQLITE_OPT("direct_io",    direct_io, 1),
	CRYPT4GH_SQLITE_OPT("file_cache",   file_cache, 1),

	CRYPT4GH_SQLITE_OPT("dotdot",       show_dotdot, 1),

	/* in case Crypt4GH is enabled */
	CRYPT4GH_SQLITE_OPT("seckey=%s"             , seckeypath         , 0),
	CRYPT4GH_SQLITE_OPT("passphrase_from_env=%s", passphrase_from_env, 0),

	/* if multithreaded */
	CRYPT4GH_SQLITE_OPT("-s"              , singlethread    , 1),
	CRYPT4GH_SQLITE_OPT("clone_fd"        , clone_fd        , 1),
	CRYPT4GH_SQLITE_OPT("max_idle_threads=%u", max_idle_threads, 0),

	CRYPT4GH_SQLITE_OPT("entry_timeout=%lf",     entry_timeout, 0),
	CRYPT4GH_SQLITE_OPT("attr_timeout=%lf",      attr_timeout, 0),


	/* Ignore these options.
	 * These may come in from /etc/fstab
	 */
	FUSE_OPT_KEY("writeback_cache=no", FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("auto",               FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("noauto",             FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("user",               FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("nouser",             FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("users",              FUSE_OPT_KEY_DISCARD),
	FUSE_OPT_KEY("_netdev",            FUSE_OPT_KEY_DISCARD),

	FUSE_OPT_END
};

static int
fs_opt_proc(void *data, const char *arg, int key, struct fuse_args *outargs)
{
	(void) outargs; (void) data;
	char *tmp;

	switch (key) {
	case FUSE_OPT_KEY_OPT:
	  /* Pass through */
	  return 1;

	case FUSE_OPT_KEY_NONOPT:
	  /* first one: SQLite file
	   * second one: mountpoint
	   */
	  if (!config.db_path) {
	    config.db_path = strdup(arg);
	    return 0;
	  }
	  else if (!config.mountpoint) {
	    config.mountpoint = realpath(arg, NULL);
	    if (!config.mountpoint) {
	      fprintf(stderr, FS_NAME ": bad mount point `%s': %s\n", arg, strerror(errno));
	      return -1;
	    }
	    return 0;
	  }
	  
	  fprintf(stderr, FS_NAME ": invalid argument `%s'\n", arg);
	  return -2;
	default:
	  fprintf(stderr, FS_NAME "internal error\n");
	  abort();
	}
}


static int
read_passphrase(const char* prompt)
{
  D1("Reading passphrase from TTY");
  int err = 0;
  int size = getpagesize();
  int max_passphrase = MIN(MAX_PASSPHRASE, size - 1);
  int n, rppflags, ttyfd;

  config.passphrase = mmap(NULL, size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
			   -1, 0);
  if (config.passphrase == MAP_FAILED) {
    perror("Failed to allocate locked page for passphrase");
    return -1;
  }
  if (mlock(config.passphrase, size) == -1) {
    perror("Failed to lock the page for passphrase");
    err = 1;
    goto error;
  }

  /* require a TTY */
  rppflags = RPP_ECHO_OFF | RPP_REQUIRE_TTY;
  ttyfd = open(_PATH_TTY, O_RDWR);
  if (ttyfd < 0){
    perror("can't open " _PATH_TTY);
    err = 2;
    goto error;
  }
  /*
   * If we're on a tty, ensure that show the prompt at
   * the beginning of the line. This will hopefully
   * clobber any passphrase characters the user has
   * optimistically typed before echo is disabled.
   */
  const char cr = '\r';
  (void) write(ttyfd, &cr, 1);
  close(ttyfd);

  /* read the passphrase */
  if(readpassphrase(prompt, config.passphrase, max_passphrase, rppflags) == NULL) {
    perror("can't read the passphrase");
    err = 3;
    goto error;
  }

  config.passphrase[strcspn(config.passphrase, "\r\n")] = '\0'; /* replace the CRLF */
  
  return 0;

error:
  memset(config.passphrase, 0, size);
  munmap(config.passphrase, size);
  config.passphrase = NULL;
  return err;
}

static int
c4gh_init(void)
{
  int res = 0;

  if(!config.seckeypath || *config.seckeypath != '/'){
    E("Missing secret key path, or non-absolute path");
    res ++;
    goto bailout;
  }

  /* Get the passphrase to unlock the Crypt4GH secret key */
  if (config.passphrase_from_env) {
    D1("Getting the passphrase from envvar %s", config.passphrase_from_env);
    config.passphrase = getenv(config.passphrase_from_env);
  } else {
    char prompt[PATH_MAX + sizeof("Enter the passphrase for the Crypt4GH key '': ")];
    sprintf(prompt, "Enter the passphrase for the Crypt4GH key '%s': ", config.seckeypath);
    if (read_passphrase(prompt) != 0){
      res ++;
      goto bailout;
    }
  }

  if(!config.passphrase){
    E("Missing passphrase");
    res ++;
    goto bailout;
  }

  /* Initialize libsodium */
  if (sodium_init() == -1) {
    E("Could not initialize libsodium: disabling Crypt4GH decryption");
    res ++;
    goto bailout;
  }

  /* Load the private key */
  D2("Loading secret key from %s", config.seckeypath);

  if( crypt4gh_sqlite_private_key_from_file(config.seckeypath, config.passphrase,
					    config.seckey, config.pubkey) ){
    E("Can't load the secret key from %s", config.seckeypath);
    res ++;
    goto bailout;
  }

  D3("Crypt4GH key loaded from '%s'", config.seckeypath);

bailout:
  return res;
}

static inline void
c4gh_destroy(void)
{
  sodium_memzero(config.seckey, crypto_kx_SECRETKEYBYTES);
  sodium_memzero(config.pubkey, crypto_kx_PUBLICKEYBYTES);
}


int main(int argc, char *argv[])
{

#if MUST_BE_ROOT
  /* if we're really root and aren't running setuid */
  const uid_t ruid = getuid();
  const uid_t euid = geteuid();
  if( (uid_t) 0 != ruid || ruid != euid ){
    fprintf(stderr, "%s can only be run as root\n", argv[0]);
    exit(1);
  }
#endif
  
  int res = 0;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct fuse *fuse;
  struct fuse_session *se;
  struct fuse_lowlevel_ops *operations;
 
  memset(&config, 0, sizeof(struct fs_config));

  config.progname = argv[0];
  config.show_help = 0;
  config.show_version = 0;
  config.singlethread = 0;
  config.foreground = 0;
  config.mounted_at = time(NULL);
  config.max_idle_threads = DEFAULT_MAX_THREADS;
  config.entry_timeout = DEFAULT_ENTRY_TIMEOUT;
  config.attr_timeout = DEFAULT_ATTR_TIMEOUT;

  config.uid = getuid();
  config.gid = getgid();

  /* General options */
  if (fuse_opt_parse(&args, &config, fs_opts, fs_opt_proc) == -1)
    exit(1);

  if (config.show_version) {
    printf("%s version %s\n", argv[0], PACKAGE_VERSION);
    printf("FUSE library version %s\n", fuse_pkgversion());
    fuse_lowlevel_version();
    exit(0);
  }
  if (config.show_help) {
    usage(&args);
    exit(0);
  }

  if (!config.db_path) {
    fprintf(stderr, "missing SQLite file\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  } 
  if (!config.mountpoint) {
    fprintf(stderr, "error: no mountpoint specified\n");
    fprintf(stderr, "see `%s -h' for usage\n", argv[0]);
    exit(1);
  }

  fuse_opt_insert_arg(&args, 1, "-ofsname=" FS_NAME);

  if(config.debug)
    config.foreground = 1;

  D1(FS_NAME " version %s", PACKAGE_VERSION);

  /* SQLite database */
  if(config.singlethread)
    sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
  else 
    sqlite3_config(SQLITE_CONFIG_MULTITHREAD);

  D1("Opening SQLite path: %s", config.db_path);
  sqlite3_open_v2(config.db_path, &config.db, SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX, NULL);
  if (config.db == NULL){
    E("Failed to allocate SQLite database handle"); 
    goto bailout;
  }
  if( sqlite3_errcode(config.db) != SQLITE_OK) {
    E("Failed to open DB: [%d] %s", sqlite3_extended_errcode(config.db), sqlite3_errmsg(config.db));
    goto bailout;
  }

  /* Crypt4GH options */
  if(c4gh_init()){
    E("Parsing Crypt4GH options");
    res = 1;
    goto bailout;
  }

  operations = fs_operations();

  /* FUSE loop */
  D1("Starting the FUSE session");
  se = fuse_session_new(&args, operations, sizeof(struct fuse_lowlevel_ops), NULL); //&config
  if (se == NULL){
    res = 3;
    goto bailout;
  }

  D2("Setting up signal handlers");
  if (fuse_set_signal_handlers(se) != 0) {
    res = 4;
    goto bailout_destroy;
  }


  D2("Mounting %s", config.mountpoint);
  if (fuse_session_mount(se, config.mountpoint) != 0) {
    res = 5;
    goto bailout_signal;
  }

  D2("Deamonize: %s", (config.foreground)?"no":"yes");
  if (fuse_daemonize(config.foreground) == -1) {
    res = 6;
    goto bailout_unmount;
  }

  D2("Mode: %s-threaded", (config.singlethread)?"single":"multi");
  D2("PID: %d", getpid());

  if (config.singlethread)
    res = fuse_session_loop(se);
  else {
    struct fuse_loop_config cf = {
      .clone_fd = config.clone_fd,
      .max_idle_threads = config.max_idle_threads,
    };
    D2("Max idle threads: %d", cf.max_idle_threads);
    res = fuse_session_loop_mt(se, &cf);
  }


 bailout_unmount:
  D2("Unmounting");
  fuse_session_unmount(se);

 bailout_signal:
  D2("Removing signal handlers");
  fuse_remove_signal_handlers(se);

 bailout_destroy:
  D1("Destroying");
  fuse_session_destroy(se);

 bailout:
  D1("Exiting with status %d", res);

  fuse_opt_free_args(&args);

  c4gh_destroy();
  if(config.db) sqlite3_close(config.db);
  if(config.db_path) free(config.db_path);
  if(config.mountpoint) free(config.mountpoint);

  return res;
}

