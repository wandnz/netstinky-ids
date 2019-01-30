CFLAGS += -Wall $(INCLUDE)
LDFLAGS += -lpcap

TARGET_CFLAGS += -ggdb3

SUBDIRS = data_structures/ebvbl data_structures/hat

DEPS = $(wildcard *.h) $(foreach dir,$(SUBDIRS),$(wildcard $(dir)/*.h))
SRC = $(wildcard *.c) $(foreach dir,$(SUBDIRS),$(wildcard $(dir)/*.c))
OBJ = $(patsubst %.c, %.o, $(SRC))

all: netstinky $(SUBDIRS)

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)
	
netstinky: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
	
.PHONY: clean $(SUBDIRS)

clean:
	rm -f netstinky
	find . -type f -name '*.o' -exec rm "{}" +
