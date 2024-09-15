#!/bin/bash
set -x
aclocal
autoconf
automake --add-missing
./configure
make
sudo make install
set +x
echo
echo "Use 'sudo make uninstall' to remove."
echo
