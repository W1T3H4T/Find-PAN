#!/bin/bash
thisHome=$HOME/Projects/W1T3H4T/Find-PAN
thisTest=${thisHome}/test
declare -i count=0
declare -i max=100

function printCount() { 
    myCount=$1
    if [ $(( count % 10 )) -eq 0 ]; then
        echo -n " ${count},"
    fi
}
echo "Building test PAN data"
while [[ $count -lt $max  ]]; do
    ./tools/create-pan-data.py > ${thisTest}/pan-log-file-${count}.log
    ./tools/create-pan-data.py > --delimited > ${thisTest}/pan-log-file-${count}.log
    count=$(( count + 1 ))
    printCount $count
done
ls -l test/pan-log-file*
# create-track-data.py
