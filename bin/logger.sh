##  ===========================================================================
##  File    :   logger.sh
##  Who     :   David Means <w1t3h4t@gmail.com>
##  What    :   Functions to log messages with date/time stamp
##
##  Instructions
##      Set these variables in your script to enable (1) or 
##      disable (0) the associated logging functions, then 'source'
##      this file in your script: 'source $HOME/bin/logger.sh'
##  ===========================================================================
##  _LOG_INFO=1
##  _LOG_DEBUG=1
##  _LOG_WARN=1
##  _LOG_ERROR=1
##  _LOG_FILE=""
##  _LOG_TIMESTAMP=1
##  _LOG_INIT_MESSAGE=0

[ -z "$_LOG_TIMESTAMP"    ] && _LOG_TIMESTAMP=1
[ -z "$_LOG_INIT_MESSAGE" ] && _LOG_INIT_MESSAGE=0
[ -z "$_LOG_INFO"  ] && echo "logger.sh error: _LOG_INFO not set"  && exit 1
[ -z "$_LOG_DEBUG" ] && echo "logger.sh error: _LOG_DEBUG not set" && exit 1
[ -z "$_LOG_WARN"  ] && echo "logger.sh error: _LOG_WARN not set"  && exit 1
[ -z "$_LOG_ERROR" ] && echo "logger.sh error: _LOG_ERROR not set" && exit 1 
[ -z "$_LOG_FILE"  ] || ( touch $_LOG_FILE  && [ -f "$_LOG_FILE" ] || "logger.sh error: $_LOG_FILE not found" )

log_message() {
    local LEVEL=$1
    local MESSAGE=$2
    local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    #   No log file defined
    if [[ -z "${_LOG_FILE}" ]] ; then
        [[ $_LOG_TIMESTAMP -eq 1 ]] && echo "[$TIMESTAMP] [$LEVEL] $MESSAGE" || echo "[$LEVEL] $MESSAGE"
        return
    fi

    #   Log file defined and found
    if [[ -f "${_LOG_FILE}" ]]; then
        [[ $_LOG_TIMESTAMP -eq 1 ]] && (echo "[$TIMESTAMP] [$LEVEL] $MESSAGE" | tee -a ${_LOG_FILE} ) || \
            ( echo "[$LEVEL] $MESSAGE" | tee -a ${_LOG_FILE} )
    fi
}

# Function for info level logging
log_info() {
    [[ $_LOG_INFO -eq 0 ]] && return
    log_message "INFO" "$1"
}

# Function for debug level logging
log_debug() {
    [[ $_LOG_DEBUG -eq 0 ]] && return
    log_message "DEBUG" "$1"
}

# Function for warn level logging
log_warn() {
    [[ $_LOG_WARN -eq 0 ]] && return
    log_message "WARN" "$1"
}

# Function for error level logging
log_error() {
    [[ $_LOG_ERROR -eq 0 ]] && return
    log_message "ERROR" "$1"
}

[[ ${_LOG_INIT_MESSAGE} -eq 1 ]] && log_info "Log functions initialized"


#  ---------------------------------------------------------------------------------
#  MIT License
#  
#  Copyright (c) 2023 David Means  <w1t3h4t@gmail.com>
#  
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#  
#  The above copyright notice and this permission notice shall be included in all
#  copies or substantial portions of the Software.
#  
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#  SOFTWARE.
#  ---------------------------------------------------------------------------------
