src = $(wildcard *.c) \
      $(wildcard utils/*.c) \
      $(wildcard utils/ebvbl/*.c) \
      $(wildcard utils/hat/*.c) \
      $(wildcard mdns/*.c) \
      $(wildcard blacklist/*.c) \
      $(wildcard test/*.c)
obj = $(src:.c=.o)

CFLAGS:=-Wall -ggdb -std=c11
LDFLAGS:=-luv -lpcap -lavahi-client -lavahi-common

CC:=gcc

# Add _GNU_SOURCE define on Linux
ifeq ($(shell uname -s), Linux)
	CFLAGS += -D_GNU_SOURCE
endif

nsids: $(obj)
	$(CC) -o $@ $^ $(LDFLAGS)

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

