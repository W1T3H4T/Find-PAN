#!/bin/bash
#   ==========================================================================
#   File    :   grep-find-track.sh
#   What    :   Stupid-simple script for discovering the possiblity of
#           :   TRACK 1 or TRACK 2 data within files.
#   Who:    :   David Means <w1t3h4t@gmail.com>
#   Notes   :   Hits reported by this tool do not necessarily indicate the 
#           :   presence of actual TRACK data used in a financial 
#           :   transaction.  Luhn checking is NOT performed, and test
#           :   TRACK data is detected as valid findings.
#   ==========================================================================
#
#   MIT License
#
#   Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
##  -----------------------------------------------
##  Control our logging functions
##  -----------------------------------------------
_LOG_INFO=1
_LOG_DEBUG=0
_LOG_WARN=1
_LOG_ERROR=1
_LOG_TIMESTAMP=1
_LOG_INIT_MESSAGE=0
_LOG_FILE=$(pwd)/$(basename $0 .sh).log
rm -f ${_LOG_FILE}

##  --------------------------------------------
##  Load our logging functions
##  --------------------------------------------
loggersh=$(which logger.sh)
if [[ -f $HOME/bin/logger.sh ]] ; then
    source $HOME/bin/logger.sh 
elif [[ -f /usr/local/bin/logger.sh ]]; then
    source $HOME/bin/logger.sh 
elif [[ -f "${loggersh}" ]]; then
    source ${loggersh}
else 
    echo "Error: 'logger.sh' not found in"
    echo "-> $HOME/bin"
    echo "-> /usr/local/bin"
    exit 1 
fi

TMPFILE=/tmp/$(basename $0 .sh).tmp
directory=""

##  Require a prefix of one of the following before the track data: 
##  whitespace, bracket, double quote, or brace
REGEX_PREFIX="[ \t'\[\"{]"
ENABLE_PREFIX=0

TRACK1="%[BM][0-9]{12,21}[\^][[:print:]]+[\^][0-9]+[?]"
TRACK2=";[0-9{21,21}=[0-9]+[?]"
PATTERNS="${TRACK1}|${TRACK2}"

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

