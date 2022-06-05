#
#
PROG	= sample mj stat

all: $(PROG)
sample: sample.c tsc.h
	cc -Wall -O0 -o sample sample.c
mj: mj.c tsc.h
	cc -Wall -O0 -o mj mj.c -lm
stat: stat.c
	cc -Wall -O2 -o stat stat.c
clean:
	rm -f $(PROG)

run_sample:
	sh run_task.sh 1 ./sample
run_mj:
	./mj
	./mj -n 10000
