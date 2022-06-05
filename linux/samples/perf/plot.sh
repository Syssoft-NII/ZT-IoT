#!/bin/bash

if test $# -lt 1 ; then
   echo "   plot.sh <file>"
   exit 1
fi

gnuplot <<EOF
set xlabel "trials"
set ylabel "msec"
unset key
set terminal jpeg
set output "$1.jpeg"
plot "$1.csv"
EOF
