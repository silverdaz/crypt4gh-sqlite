
DAZ_FS=$(shell pwd)/../crypt4gh-sqlite.fs
DAZ_MNT=$(shell pwd)/mnt
DAZ_SQLITE=$(shell pwd)/example.sqlite
DAZ_SQLITE_BAK=$(DAZ_SQLITE).bak
DAZ_SECKEY=$(shell pwd)/example.seckey

export C4GH_PASSPHRASE=hello

DAZ_OPTS+=ro,seckey=$(DAZ_SECKEY),passphrase_from_env=C4GH_PASSPHRASE
DAZ_OPTS+=allow_other,default_permissions
DAZ_OPTS+=file_cache,dir_cache

all: up

debug: DAZ_FS+= -d

debug1 debug2 debug3: DAZ_FS+= -g
debug1: DAZ_OPTS+=local_debug=1
debug2: DAZ_OPTS+=local_debug=2
debug3: DAZ_OPTS+=local_debug=3

up debug debug1 debug2 debug3: $(DAZ_SQLITE) | mnt
	$(DAZ_FS) $(DAZ_OPTS:%=-o %) $< $(DAZ_MNT)

down:
	umount $(DAZ_MNT)

mnt:
	mkdir -p -m 700 $@

$(DAZ_SQLITE): $(DAZ_SQLITE_BAK)
	@cp $< $@
	@sqlite3 $@ "UPDATE files SET mountpoint = '$(shell pwd)';"
