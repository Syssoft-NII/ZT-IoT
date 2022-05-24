CC = cc
CFLAGS = -Wall -O2 -g -fPIC $(FJCFLAGS)
LDFLAGS= -shared
OBJ = hooklib.o

all: testlib.so hooklib.so mytest watch_mqtt.so connect
mytest: mytest.c
	$(CC) -o mytest mytest.c
run:
	export LD_LIBRARY_PATH=.:; export LD_PRELOAD=testlib.so; ./mytest
connect: connect.c
	$(CC) $(CFLAGS) -o $@ $^
watch_mqtt.so: watch_mqtt.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -ldl
watch_mqtt.o: watch_mqtt.c watch_mqtt.h
testlib.so: testlib.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -ldl
hooklib.so: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -lpthread -ldl
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJ)

