LIB=/usr/local/lib
IMAGE=plugin-2
AUDISP=plugin-test
DST=./docker/audit/bin
all: audit-test regexptest plugin plugin-2

audit-test: sysname.h audit-test.c regexplib.o monlib.o
	$(CC) -g -o audit-test audit-test.c regexplib.o monlib.o -L$(LIB) -laudit
regexptest: regexptest.o regexplib.o
	$(CC) -g -o regexptest regexptest.o regexplib.o
plugin: plugin.c
	$(CC) -g -I/usr/local/include -o $@ $^ -L/usr/local/lib/ -lauparse -laudit
plugin-2: plugin-2.c sysname.h
	$(CC) -g -I/usr/local/include -o $@ $^ -L/usr/local/lib/ -lauparse -laudit
install:
	install $(IMAGE) $(DST)/$(AUDISP)
	tar --absolute-names -czf ./docker/audit.tar.gz /usr/local/lib/libaudit* /usr/local/lib/libauparse* /usr/local/sbin/au*
sysname.h: sysname.incl sysname_gen.c
	$(CC) -o sysname_gen sysname_gen.c
	./sysname_gen > sysname.h
sysname.incl:
	ausyscall --dump | sed -f script.sed | sed -e 's/Using.*//'> sysname.incl

clean:
	rm -f *.o audit-test regexptest sysname.incl
