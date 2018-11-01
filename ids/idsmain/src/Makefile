CC = gcc
CFLAGS = -Wall
LDFLAGS = -lpcap

TARGET_CFLAGS += -ggdb

SUBDIRS = data_structures/ebvbl

DEPS = $(wildcard *.h) $(wildcard $(SUBDIRS)/*.h)
SRC = $(wildcard *.c) $(wildcard $(SUBDIRS)/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

all: idsmain $(SUBDIRS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
idsmain: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
	
.PHONY: clean $(SUBDIRS)

clean:
	rm -f idsmain *.o