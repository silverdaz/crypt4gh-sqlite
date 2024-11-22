# An example

The provided Makefile helps you with some presets.  

Run first the `make update` command to update the mountpoints of the embedded files, so that it reflects your directory structure.  
(ie, we'll load the current directory, so the local files refer to it).

You can then run `make up` to start the file system and `make down` to stop it.

If you want to see the debug output, and what the file system is doing, use `make debug`.  
You can adjust the verbosity with `make debug1`, `make debug2`, or `make debug3`.

You should see the file system in the current directory under `<here>/mnt/`.

	# tree mnt/
	mnt/
	├── extra
	│   ├── footer.txt
	│   └── header.txt
	├── full.txt
	├── slim.txt
	└── subdir
		├── file1.txt
		└── file2.txt

	3 directories, 6 files
