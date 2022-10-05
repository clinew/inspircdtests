#!/bin/bash

# Sanity checks for InspIRCd on Gentoo.
# Copyright (C) 2022  Wade T. Cline
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Load includes.
source include.sh

# Array to store test results in.
RESULTS=()

# Sanity-check logrotate.
i=0
RESULTS[$i]=""
dir="/etc/logrotate.d"
file="inspircd"
realpath="${dir}/${file}"
for f in "${dir}/"._cfg*_inspircd; do
	# Unmerged config file.
	[ -f "${f}" ] && RESULTS[$i]+="\tUnmerged config file '${f}'\n"
done
if [ ! -f "${realpath}" ]; then
	# File not found.
	RESULTS[$i]+="\tlogrotate file at '${realpath}' not found\n"
else
	pattern="^\\s+create\\s+\\d+\\s+inspircd\s+inspircd$"
	grep -P "${pattern}" "${realpath}" > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		# Unable to find line.
		RESULTS[$i]+="\tLogrotate file '${realpath}' does not match expected pattern '${pattern}'; exit status '${ret}'.\n"
	fi
fi

# Print results.
set +x
passed=1
for (( i=0 ; i<${#RESULTS[@]} ; i++ )); do
	echo -n "Test $i: "
	if [ -z "${RESULTS[$i]}" ]; then
		echo "PASSED!"
	else
		passed=0
		echo "FAILED"
		echo -en "${RESULTS[$i]}"
	fi
done
if [ $passed -ne 1 ]; then
	# Exit failure.
	exit 1
fi
