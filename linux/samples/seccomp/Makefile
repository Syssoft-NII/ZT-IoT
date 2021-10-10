LIB = -lseccomp
OPT = -g -Wall
PROGS = test1 test2 test3 test4 test5 test-actlog
all: $(PROGS)
test1: test1.c
	$(CC) -o $@ $^ $(OPT) $(LIB)
test2: test2.c
	$(CC) -o $@ $^ $(OPT) $(LIB)
test3: test3.c
	$(CC) -o $@ $^ $(OPT) $(LIB)
test4: test4.c
	$(CC) -o $@ $^ $(OPT) $(LIB)
test5: test5.c
	$(CC) -o $@ $^ $(OPT) $(LIB) -lpthread
test-actlog: test-actlog.c
	$(CC) -o $@ $^ $(OPT) $(LIB)
clean:
	rm -f $(PROGS)
