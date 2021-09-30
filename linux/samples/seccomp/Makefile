LIB = -lseccomp
PROGS = test test2 test3 test4 test5 test6 test7
all: $(PROGS)
test: test.c
	$(CC) -o $@ $^ $(LIB)
test2: test2.c
	$(CC) -o $@ $^ $(LIB)
test3: test3.c
	$(CC) -o $@ $^ $(LIB)
test4: test4.c
	$(CC) -o $@ $^ $(LIB)
test5: test5.c
	$(CC) -o $@ $^ $(LIB)
test6: test6.c
	$(CC) -o $@ $^ $(LIB) -lpthread
test7: test7.c
	$(CC) -o $@ $^ $(LIB) -lpthread
clean:
	rm -f $(PROGS)
