CC=gcc
CFLAGS=-Wall -Wextra -O0
.PHONY: clean

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
bin_dir := $(dir $(mkfile_path))bin
linkdir := /usr/local/bin

stack: stack.c
	[ -d $(bin_dir) ] || mkdir $(bin_dir)
	$(CC) -o $(bin_dir)/$@ $(CFLAGS) $<
	sudo ln -sf $(bin_dir)/$@ $(linkdir)/$@

clean:
	sudo rm $(linkdir)/stack
	rm -r $(bin_dir)
