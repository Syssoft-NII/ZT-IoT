#!/bin/bash

if test $# -lt 1 ; then
   echo "   plot.sh <file>"
   exit 1
fi

gnuplot <<EOF
set xlabel "msec"
set ylabel "counts"
unset key
set terminal jpeg
set output "$1-stat.jpeg"
plot "$1-stat.csv" with boxes
EOF
