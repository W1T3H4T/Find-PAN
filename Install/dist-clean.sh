#!/bin/bash
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
    ./config.status 

