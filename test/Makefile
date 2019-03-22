src = $(wildcard Test*.c)
obj = $(src:.c=.o)

CFLAGS:=-Wall -ggdb -std=c11 -Itestlib/ -I../src/
LDFLAGS:=-L../src/
SRCDIR:=../src

DEPS:=../src/utils/str.o ../src/linked_list.o ../ids_event_list.o

all: runner

lib/CuTest.o: testlib/CuTest.c testlib/CuTest.h
	$(CC) -c $< -o lib/CuTest.o

runner: AllTests.o testlib/CuTest.o $(obj) ../src/utils/str.o ../src/linked_list.o ../src/ids_event_list.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	@rm -f *.o
	@rm -f runner

.PHONY: clean

