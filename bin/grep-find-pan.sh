#!/bin/bash
##  ==========================================================================
##  File    :   grep-find-pan.sh
##  What    :   Stupid-simple script for discovering the possiblity of
##          :   PAN data within files.
##  Who:    :   David Means <w1t3h4t@gmail.com>
##  Notes   :   Hits reported by this tool do not necessarily indicate the 
##          :   presence of actual PAN data used in a financial 
##          :   transaction.  Luhn checking is NOT performed, and test
##          :   PAN data is detected as valid findings.
##  ===========================================================================
##  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
##  ===========================================================================

##  ===========================================================================
##  Control our logging functions
##  ===========================================================================
_LOG_INFO=1
_LOG_DEBUG=0
_LOG_WARN=1
_LOG_ERROR=1
_LOG_TIMESTAMP=1
_LOG_INIT_MESSAGE=0
_LOG_FILE=$(pwd)/$(basename $0 .sh).log
rm -f ${_LOG_FILE}

##  ===========================================================================
##  Load our logging functions
##  ===========================================================================
loggersh=$(which logger.sh)
if [[ -f "${loggersh}" ]]; then
    source ${loggersh}
elif [[ -f $HOME/bin/logger.sh ]] ; then
    source $HOME/bin/logger.sh 
elif [[ -f /usr/local/bin/logger.sh ]]; then
    source /usr/loca/bin/logger.sh 
else 
    echo "Error: 'logger.sh' not found in"
    echo "-> \\$PATH"
    echo "-> $HOME/bin"
    echo "-> /usr/local/bin"
    exit 1 
fi

TMPFILE=/tmp/$(basename $0 .sh).tmp
directory=""

##  Require a prefix of one of the following before the 'PAN':
##  whitespace, bracket, double quote, or brace
REGEX_PREFIX="[ \t'\[\"{]"
ENABLE_PREFIX=0

visa_regex='4[0-9]{12}(?:[0-9]{3})?'
mastercard_regex='(5[1-5]|[23][6-7]|8[0-9]|2[0-1][0-9]|22[1-8])\d{14}'
amex_regex='3[47][0-9]{13}'
discover_regex='(6(?:011|5[0-9]{2})|[4-7][0-9])[0-9]{12}'
diners_regex='3(?:0[0-5]|[68][0-9])[0-9]{11}'
jcb_regex='(35[0-9]{2})[0-9]{12}'
PATTERNS="(${visa_regex}|${mastercard_regex}|${amex_regex}|${discover_regex}|${diners_regex}|${jcb_regex})"

## see also: https://baymard.com/checkout-usability/credit-card-patterns


function help()
{
    echo 
    echo "Usage: $(basename $0) --dir DIRECTORY"
    echo 
    echo "--path DIRECTORY  The filesystem to search."
    echo "--rgx-prefix      Require the REGEX prefix of '$REGEX_PREFIX'"
    echo "--help|-help|-h   This information."
    echo
}

function finder()
{
    ## Formulate our REGEX patterns using 'ENABLE_PREFIX'
    if [[ $ENABLE_PREFIX -eq 1 ]]; then
        REGEX="${REGEX_PREFIX}${PATTERNS}"
            else
        REGEX="${PATTERNS}"
        fi
    log_info "Processing ${1}"

    if command grep -E "${REGEX}" "$1" > $TMPFILE 2>/dev/null; then
            log_info "$ftype: $1 (matches)"
            if [[ -f $_LOG_FILE ]] ; then
                # cat $TMPFILE && echo | tee -a $_LOG_FILE
                cat $TMPFILE | tee -a $_LOG_FILE
            else
                cat $TMPFILE 
                echo
            fi
        fi

}

function findFiles()
{
    find "$1" -type f | while read -r FILE
    do
        ftype=$(file --mime-type "$FILE" | cut -d ':' -f 2 | sed 's/ //g')
        log_debug "Testing: $ftype: $FILE"
        case "${ftype}" in
            "application/x-mach-binary")
                log_info "Skipping binary file: ${FILE}"
                continue;;
            "application/octet-stream")
                log_info "Skipping binary file: ${FILE}"
                continue;;
            "application/x-git")
                log_info "Skipping binary file: ${FILE}"
                continue;;
            "application/zip")
                log_info "Skipping binary file: ${FILE}"
                continue;;
            "application/x-bzip2")
                log_info "Skipping binary file: ${FILE}"
                continue;;
            "application/gzip")
                log_info "Skipping binary file: ${FILE}"
                continue;;
            "image/jpeg")
                log_info "Skipping Image file: ${FILE}"
                continue;;
            "image/png")
                log_info "Skipping Image file: ${FILE}"
                continue;;
            *) 
                log_debug "Testing: $ftype: $FILE"
                finder "$FILE"
                ;;
        esac
    done
}


while [[ $# -gt 0 ]]; do
    # log_info "arg count: $#"
    case "$1" in 
        '--help|-help|-h')
            help
            exit
            ;;

        '--path')
            shift
            directory=$1
            shift
            ;;

       '--rgx-prefix')
            ENABLE_PREFIX=1
            shift
            ;;
        *)
            help
            exit
            ;;
    esac
done

if [[ ! -z "$directory" ]] ; then
    findFiles "${directory}"
else
    help
fi


