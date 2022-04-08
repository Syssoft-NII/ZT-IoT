LIB=/usr/local/lib
all: audit-test regexptest plugin plugin-2

audit-test: sysname.h audit-test.c regexplib.o monlib.o
	$(CC) -o audit-test audit-test.c regexplib.o monlib.o -L$(LIB) -laudit
regexptest: regexptest.o regexplib.o
	$(CC) -o regexptest regexptest.o regexplib.o
plugin: plugin.c
	$(CC) -I/usr/local/include -o $@ $^ -L/usr/local/lib/ -lauparse -laudit
plugin-2: plugin-2.c sysname.h
	$(CC) -I/usr/local/include -o $@ $^ -L/usr/local/lib/ -lauparse -laudit
sysname.h: sysname.incl sysname_gen.c
	$(CC) -o sysname_gen sysname_gen.c
	./sysname_gen > sysname.h
sysname.incl:
	ausyscall --dump | sed -f script.sed | sed -e 's/Using.*//'> sysname.incl

clean:
	rm -f *.o audit-test regexptest sysname.incl
