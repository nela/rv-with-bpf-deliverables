# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Re-using the code from: https://github.com/ethercflow/libbpf-bootstrap
#

OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
DEFAULT_BPFTOOL ?= bpftool
KERNEL_REL := $(shell uname -r)

# Default Ubuntu libbpf if argument not provided
ifdef LIBBPF_SRC
	LIBBPF := $(patsubst %/src,%,$(LIBBPF_SRC))
	LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
else
	LIBBPF := $(shell pkg-config --variable=libdir libbpf)
	LIBBPF_OBJ := $(LIBBPF)/libbpf.a
endif

INCLUDES := -I$(OUTPUT) -I $(LIBBPF)/include
CFLAGS := -g -Wall -lpthread
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPFTOOL ?= $(DEFAULT_BPFTOOL)

# Try to detect best kernel BTF source
VMLINUX_BTF_PATHS := /sys/kernel/btf/vmlinux /boot/vmlinux-$(KERNEL_REL)
VMLINUX_BTF_PATH := $(or $(VMLINUX_BTF),$(firstword                           \
                                          $(wildcard $(VMLINUX_BTF_PATHS))))

APPS = distributed

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Use default libbpf of build libbpf
ifdef LIBBPF_SRC
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install
else
	@$(ifneq ($(MAKECMDGOALS),clean),$(warning \
		LIBBPF_SRC not specified. Attempting build with system libbpf ${LIBBPF_OBJ}).)
endif

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(OUTPUT)/vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/vmlinux.h: $(VMLINUX_BTF_PATH) | $(OUTPUT)
	$(Q)$(call msg,GEN,$@)
	$(Q)if [ ! -e "$(VMLINUX_BTF_PATH)" ] ; then \
		echo "Couldn't find kernel BTF; set VMLINUX_BTF to"	    \
			"specify its location." >&2;			    \
		exit 1;\
	fi
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF_PATH) format c > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lelf -lz -o $@

install:
	install -m 755 $(APPS) /usr/bin/

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
