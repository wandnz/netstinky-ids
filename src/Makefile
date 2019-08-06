src = $(wildcard *.c) \
      $(wildcard error/*.c) \
      $(wildcard utils/*.c) \
      $(wildcard utils/ebvbl/*.c) \
      $(wildcard utils/hat/*.c) \
      $(wildcard blacklist/*.c) \
      $(wildcard test/*.c) \
      $(wildcard blacklist/updates/*.c)
obj = $(src:.c=.o)

CFLAGS:=-Wall -ggdb -std=c11 -DNO_MDNS -DNO_UPDATES
LDFLAGS:=-luv -lpcap -lssl -lcrypto -lcurl

CC?=gcc

# Add _GNU_SOURCE define on Linux
ifeq ($(shell uname -s), Linux)
	CFLAGS += -D_GNU_SOURCE
endif

nsids: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compiles using the AFL compiler and makes the compiler use the FUZZ_TEST code
fuzztest: CC=afl-gcc
fuzztest: CFLAGS+= -DFUZZ_TEST
fuzztest: clean nsids

clean:
	@rm -f nsids
	@rm -f *.o
	@rm -f utils/*.o
	@rm -f utils/hat/*.o
	@rm -f utils/ebvbl/*.o
	@rm -f mdns/*.o
	@rm -f blacklist/*.o

.PHONY: clean

