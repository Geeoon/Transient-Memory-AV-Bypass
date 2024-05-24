WIN_SOURCEDIR=src/windows
LINUX_SOURCEDIR=src/linux

WIN_BUILDDIR=build/windows
LINUX_BUILDDIR=build/linux

CC=gcc
# CFLAGS=-s -O3 -static  # will cause valgrind memory errors
CFLAGS=-fno-stack-protector -z execstack

all:
	$(error Choose either `windows` or `linux` as the make target)
	
linux: $(LINUX_BUILDDIR)/main.o
	$(CC) $(CFLAGS) $^ -o $(LINUX_BUILDDIR)/tmavb

$(LINUX_BUILDDIR)/main.o: $(LINUX_SOURCEDIR)/main.c
	$(CC) $(CFLAGS) -c $^ -o $@
	
