#!/bin/bash
PREFIX=$(grep '^S\[\"prefix\"\]' config.status | cut -d'"' -f4)
if [[ ! -z "$PREFIX" ]]; then
    if [[ -f "$PREFIX" ]]; then
        rm -rf "$PREFIX"
    fi
fi
make clean > /dev/null 2>&1
rm -rf ./autom4te.cache
rm -f ./aclocal.m4 \
    ./configure \
    ./Makefile.in \
    ./configure~ \
    ./config.log \
    ./install-sh \
    ./Makefile \
    ./missing \
    ./config.status \
    ./env.conf

