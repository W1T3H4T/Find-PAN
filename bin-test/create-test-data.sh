#!/bin/bash
thisHome=$(pwd)
thisTest=${thisHome}/data

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

declare -i count=0
declare -i max=800
each=$(( $max / 4))
echo "Building test PAN & Track data files"
while [[ $count -lt $max  ]]; do
    ./bin-test/make-test-pan.py   --count ${each}              > ${thisTest}/test-pan-${count}.log
    ./bin-test/make-test-pan.py   --count ${each} --delimited >> ${thisTest}/test-pan-delimited-${count}.log
    ./bin-test/make-test-track.py --count ${each}              > ${thisTest}/test-track-${count}.log
    ./bin-test/make-test-track.py --count ${each} --delimited >> ${thisTest}/test-track-delimited-${count}.log
    count=$(( count + $each ))
    printCount $count
done
echo
ls -l ${thisTest}/*.log
