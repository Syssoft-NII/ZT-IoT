LIB=/usr/local/lib
all: audit-test regexptest

audit-test: audit-test.c regexplib.o
	$(CC) -o audit-test audit-test.c regexplib.o -L$(LIB) -laudit
regexptest: regexptest.o regexplib.o
	$(CC) -o regexptest regexptest.o regexplib.o

clean:
	rm -f *.o audit-test regexptest
