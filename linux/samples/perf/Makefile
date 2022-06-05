#
#
PROG	= sample mj

all: $(PROG)
sample: sample.c tsc.h
	cc -Wall -o sample sample.c
mj: mj.c tsc.h
	cc -Wall -g -o mj mj.c
clean:
	rm -f $(PROG)

run_sample:
	sh run_task.sh 1 ./sample
