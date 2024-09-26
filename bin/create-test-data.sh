#!/bin/bash
thisHome=$(pwd)
thisTest=${thisHome}/test
declare -i count=0
declare -i max=50

function promptUser() {
    echo "NOTICE: Test data will be created in ${thisTest}"
    read -p "Continue (yes/NO)? " response
    response=${response:-no}
    response_lower=$(echo "$response" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$response_lower" == "y" || "$response_lower" == "yes" ]]; then
        return 1
    else
        echo "Exiting. No test data will be created."
        exit 1
    fi
    return 0
}

function printCount() { 
    myCount=$1
    if [ $(( count % 5 )) -eq 0 ]; then
        echo -n " ${count},"
    fi
}

#   Prompt the user to continue or not
promptUser
[[ $? -ne 1 ]] && exit 1

echo "Building $(( ${max} * 2 )) test PAN & Track data files"
while [[ $count -lt $max  ]]; do
    make-test-pan.py   --count 10              > ${thisTest}/pan-log-file-${count}.log
    make-test-pan.py   --count 10 --delimited >> ${thisTest}/pan-log-file-${count}.log
    make-test-track.py --count 10             > ${thisTest}/track-log-file-${count}.log
    make-test-track.py --count 10 --delimited >> ${thisTest}/track-log-file-${count}.log
    count=$(( count + 1 ))
    printCount $count
    #echo "${thisTest}/track-log-file-${count}.log: done"
    #echo "${thisTest}/pan-log-file-${count}.log: done"
done
echo
ls -l ${thisTest}/*.log
