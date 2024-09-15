#!/bin/bash
make clean 2>&1 > /dev/null
rm -rf ./autom4te.cache
rm -f ./aclocal.m4 \
    ./configure \
    ./Makefile.in \
    ./configure~ \
    ./config.log \
    ./install-sh \
    ./missing \
    ./config.status 

