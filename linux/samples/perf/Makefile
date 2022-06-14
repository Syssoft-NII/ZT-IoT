#
#
PROG	= sample mj stat corebind

all: $(PROG)
sample: sample.c tsc.h
	cc -Wall -O0 -o sample sample.c
mj: mj.c tsc.h measurelib.h measurelib.o
	cc -Wall -O0 -o mj mj.c measurelib.o -lm
stat: stat.c
	cc -Wall -O2 -o stat stat.c
corebind: corebind.c
	cc -Wall -O2 -o corebind corebind.c
clean:
	rm -f $(PROG)

run_sample:
	sh run_task.sh 1 ./sample
run_mj:
	taskset -c 5 ./mj
	taskset -c 5 ./mj -n 10000
