#
#
#ARCH=x86_64
#ARCH=aarch64
#
ARCH ?= $(shell arch)
include mkdef.$(ARCH)
LIB=/usr/local/lib
IMAGE=plugin-3
AUDISP=plugin-test
DST=./docker/audit/bin

INCLUDES=-I../audit-userspace/ -I../audit-userspace/auparse/ -I../audit-userspace/lib/ -I../audit-userspace/src/

#all: audit-test audit-test2 regexptest cmdtest plugin plugin-2 plugin-3 selinux mqtt_sub mqtt_pub user-test
all: audit-test audit-test2 audit-test2per regexptest cmdtest \
	plugin-test \
	plugin plugin-2 plugin-3 mqtt_sub mqtt_pub user-test

audit-test: sysname.h audit-test.c regexplib.o monlib.o
	$(CC) -g -o audit-test audit-test.c regexplib.o monlib.o -L$(LIB) -laudit
audit-test2: sysname.h audit-test2.c regexplib.o monlib.o
	$(CC) -Wall -g -O2 -o audit-test2 audit-test2.c regexplib.o monlib.o -L$(LIB) -laudit -lpthread
audit-test2per: sysname.h audit-test2.c regexplib.o monlib.o
	$(CC) -Wall -g -O2 -DMEASURE_PERCALL -o audit-test2per audit-test2.c regexplib.o monlib.o -L$(LIB) -laudit -lpthread -lm
regexptest: regexptest.o regexplib.o
	$(CC) -g -o regexptest regexptest.o regexplib.o
cmdtest: cmdtest.o mylib.o
	$(CC) -g -o $@ $^
plugin: plugin.c
	$(CC) -g -I/usr/local/include -o $@ $< -L/usr/local/lib/ -lauparse -laudit
plugin-test: plugin-test.c autestlib.o
	$(CC) $(INCLUDES) -Wall -g -O2 -I/usr/local/include -o $@ $< autestlib.o \
	-L/usr/local/lib/ -lauparse -laudit -lm
autestlib.o: autestlib.c autestlib.h
plugin-2: plugin-2.c sysname.h
	$(CC) -g -I/usr/local/include -o $@ $< -L/usr/local/lib/ -lauparse -laudit
plugin-3: plugin-3.c sysname.h log-field.h mylib.o comlib.o
	$(CC) -g -I/usr/local/include -o $@ $< mylib.o comlib.o -L/usr/local/lib/ -lauparse -laudit -lmosquitto
comlib.o: comlib.c
	$(CC) -g -c -o $@ $^
mylib.o: mylib.c
	$(CC) -g -c -o $@ $^
selinux: selinux.c
	gcc -o $@ $< -lselinux
user-test: user-test.c
	gcc -o $@ $< -laudit
mqtt_sub: mqtt_sub.c
	gcc -o $@ $< -lmosquitto
mqtt_pub: mqtt_pub.c
	gcc -o $@ $< -lmosquitto
install:
	install $(IMAGE) $(DST)/$(AUDISP)
	install mqtt_sub mqtt_pub $(DST)/
	tar --absolute-names -czf ./docker/audit.tar.gz /usr/local/lib/libaudit* /usr/local/lib/libauparse* /usr/local/lib/libmosquitto* /usr/local/sbin/au* 
sysname.h: sysname.incl sysname_gen.c
	$(CC) -o sysname_gen sysname_gen.c
	./sysname_gen > sysname.h
sysname.incl:
	ausyscall --dump | sed -f script.sed | sed -e 's/Using.*//'> sysname.incl

clean:
	rm -f *.o audit-test audit-test2 regexptest cmdtest plugin plugin-2 plugin-3 selinux mqtt_sub mqtt_pub user-test sysname.incl

#
#
run-audit-test2:
	sh run_task.sh 5 ./audit-test2 -i 1000 -e 1 -n
run-audit-test2per:
	sh run_task.sh 5 ./audit-test2per -i 1000 -e 1 -n
	sh run_task.sh 5 ./audit-test2per -i 1000 -e 2 -n
	sh run_task.sh 5 ./audit-test2per -i 1000 -e 1
	sh run_task.sh 5 ./audit-test2per -i 1000 -e 2
run-plugin-test:
	taskset -c 4 auditd -f -n -s enable -c /usr/local/etc/audit >&/dev/null
