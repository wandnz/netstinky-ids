# Location of cross-compilation gcc for Turris Omnia
CC = /home/build/openwrt/staging_dir/toolchain-arm_cortex-a9+vfpv3_gcc-4.8-linaro_musl-1.1.15_eabi/bin/arm-openwrt-linux-muslgnueabi-gcc

# The STAGING_DIR must be set for the cross-compilation gcc
STAGING_DIR = /home/build/openwrt/staging_dir/target-arm_cortex-a9+vfpv3_musl-1.1.15_eabi

# Location of *.h and library files
INCLUDE = -I $(STAGING_DIR)/usr/include
LIBDIR = -L $(STAGING_DIR)/usr/lib

#CC = gcc
CFLAGS += -Wall $(INCLUDE)
LDFLAGS = -lpcap

TARGET_CFLAGS += -ggdb3

SUBDIRS = data_structures/ebvbl data_structures/hat

DEPS = $(wildcard *.h) $(foreach dir,$(SUBDIRS),$(wildcard $(dir)/*.h))
SRC = $(wildcard *.c) $(foreach dir,$(SUBDIRS),$(wildcard $(dir)/*.c))
OBJ = $(patsubst %.c, %.o, $(SRC))

all: idsmain $(SUBDIRS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
idsmain: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
	
.PHONY: clean $(SUBDIRS)

clean:
	rm -f idsmain *.o