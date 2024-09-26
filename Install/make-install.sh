#!/bin/bash
aclocal
autoconf
automake --add-missing
./configure
PREFIX=$(grep '^S\[\"prefix\"\]' config.status | cut -d'"' -f4)
make
echo "Creating directory '${PREFIX}'"
USER=$(id -un)
GROUP=$(id -gn)
[[ -z "$USER"  ]] && echo "Can't get user-name" && exit 1
sudo gmkdir -p ${PREFIX}
echo "Changing ownership to ${USER}:${GROUP}"
sudo gchown -R ${USER}: ${PREFIX}
make install
echo
echo "Use 'make uninstall' to remove configurations."
echo "You must manually remove '${PREFIX}'"
