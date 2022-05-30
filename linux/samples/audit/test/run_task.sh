#!/bin/bash
#
CPUS="0 1 2 3 4 5"

if test $# -lt 2 ; then
   echo "\trun_task.sh <#tials> <application>"
   exit 1
fi
ITER=$1
echo ITER= $ITER
shift 1
#
for i in $CPUS
do
    echo "######"
    echo taskset -c $i $@
    for j in `seq 1 $ITER`
    do
	taskset -c $i $@
    done
    echo
done
