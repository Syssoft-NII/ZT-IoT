CC = cc
CFLAGS = -Wall

all: test_mqtt test connack connack2
test_mqtt: test_mqtt.o libmymqtt.o
	$(CC) -o $@ $^
libmymqtt.o: libmymqtt.c libmymqtt.h
.c.o:
	$(CC) -c $(CFLAGS) $<
test: test.c
	cc -o test test.c
connack: connack.c
	cc -o connack connack.c
connack2: connack2.c
	cc -o connack2 connack2.c
