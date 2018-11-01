CC = gcc
CFLAGS += -Wall
LDFLAGS = -lpcap

TARGET_CFLAGS += -ggdb

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