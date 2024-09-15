#!/bin/bash
thisHome=$HOME/Projects/W1T3H4T/Find-PAN
thisTest=${thisHome}/test
declare -i count=0
declare -i max=100

function printCount() { 
    myCount=$1
    if [ $(( count % 5 )) -eq 0 ]; then
        echo -n " ${count},"
    fi
}
echo "Building $(( ${max} * 2 )) test PAN & Track data files"
while [[ $count -lt $max  ]]; do
    ./tools/create-pan-data.py   --count 50              > ${thisTest}/pan-log-file-${count}.log
    ./tools/create-pan-data.py   --count 50 --delimited >> ${thisTest}/pan-log-file-${count}.log
    ./tools/create-track-data.py --count 50              > ${thisTest}/track-log-file-${count}.log
    ./tools/create-track-data.py --count 50 --delimited >> ${thisTest}/track-log-file-${count}.log
    count=$(( count + 1 ))
    printCount $count
    #echo "${thisTest}/track-log-file-${count}.log: done"
    #echo "${thisTest}/pan-log-file-${count}.log: done"
done
echo
ls -l test/pan-log-file*
