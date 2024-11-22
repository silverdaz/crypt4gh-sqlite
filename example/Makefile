
DAZ_FS=$(shell pwd)/../crypt4gh-sqlite.fs
DAZ_MNT=$(shell pwd)/mnt
DAZ_SQLITE=$(shell pwd)/example.sqlite
DAZ_SECKEY=$(shell pwd)/example.seckey

export C4GH_PASSPHRASE=hello

DAZ_OPTS+=ro,seckey=$(DAZ_SECKEY),passphrase_from_env=C4GH_PASSPHRASE
DAZ_OPTS+=allow_other

all: up

debug: debug2

debug1 debug2 debug3: DAZ_FS+= -d
debug1: DAZ_OPTS+=debug=1
debug2: DAZ_OPTS+=debug=2
debug3: DAZ_OPTS+=debug=3
up debug1 debug2 debug3: | mnt
	$(DAZ_FS) $(DAZ_OPTS:%=-o %) $(DAZ_SQLITE) $(DAZ_MNT)

down:
	umount $(DAZ_MNT)

mnt:
	mkdir -p -m 700 $@

update:
	sqlite3 $(DAZ_SQLITE) "UPDATE files SET mountpoint = '$(shell pwd)';"
