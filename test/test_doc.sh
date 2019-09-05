#!/bin/bash

SEDCLI="../src/sedcli"

# Test checking if sedcli documentation doesn't have any spelling problems
# No output is a positive sign indicating that no potential problem has
# been found. Some output indicates a potential problem it is recommended to
# investigate deeper before assuming this is an error.

CMDS="-O -A -R -S -L -P -V -H"

man --no-hyphenation -P cat ../doc/sedcli.8 | aspell list --lang=en_US --add-extra-dicts=./sedcli.en.pws

${SEDCLI} -H | aspell list --lang=en_US --add-extra-dicts=./sedcli.en.pws

for cmd in ${CMDS}; do
	${SEDCLI} ${cmd} -H | aspell list --lang=en_US --add-extra-dicts=./sedcli.en.pws
done
