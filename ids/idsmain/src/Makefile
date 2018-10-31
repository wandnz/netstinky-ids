all: idsmain

CC = gcc
CFLAGS = -Wall
LDFLAGS = -lpcap

TARGET_CFLAGS += -ggdb3

DEPS = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
idsmain: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
	
.PHONY: clean

clean:
	rm -f idsmain *.o