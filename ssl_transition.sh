#!/bin/bash

# Test transition architecture between unofficial v0.0.1 "Friend of friend" PKI
# and v0.0.2 "Admin, Friend, Referrer" PKI.  This will likely not be of
# interest to most people.
#
# Copyright (C) 2020  Wade T. Cline
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

# Global configuration.
set -ex

# Load includes.
source include.sh

# Test dir home to backup original config.
DIR_HOME="${HOME}/.inspircdtests"
# Home dir for the InspIRCd configuration.
DIR_IRCD="/etc/inspircd"
# Home dir for the OpenSSL files.
DIR_SSL="/var/lib/afr/inspircdtests"
# Array to store test results in.
RESULTS=()

# Connect to the server and return whether or not the client was granted access
# by the server.  '0' means the client was granted access, '1' means the client
# was denied access, '2' means it is unknown whether the client was granted
# access or not.
# 1: Name of the CA to connect with.
connect() {
	name=$1
	output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 3; echo "QUIT") | openssl s_client -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" -connect localhost:6697 -ign_eof)
	if echo "${output}" | grep "You are connected"; then
		echo "Access granted to '${name}'"
		return 0
	elif echo "${output}" | grep "Access denied by configuration"; then
		echo "Access denied for '${name}'"
		return 1
	fi
	echo "UNKNOWN RESULT for '${name}'"
	return 2
}

# Restore original configuration.
restore() {
	rm -rf "${DIR_SSL}"
	rm -rf "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_IRCD}`" "${DIR_IRCD}"
	[ -d $(basename ${DIR_SSL}) ] && cp -rp "${DIR_HOME}/`basename ${DIR_SSL}`" "${DIR_SSL}"
	#rm -rf "${DIR_HOME}"
	rc-service inspircd restart
	exit 0
}

# Print out the current subtest number and increment the subtest counter.
subtest_mark() {
	echo "Test $i.$j"
	j=$(($j + 1))
}

# Backup config dirs.
mkdir -p "${DIR_HOME}"
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
[ -f "${DIR_SSL}" ] && cp -rp "${DIR_SSL}" "${DIR_HOME}/"
trap "restore" EXIT

# Set-up.
mkdir -p "${DIR_SSL}"
cp "openssl.cnf" "${DIR_SSL}/openssl.cnf"
cp "afr.conf" "${DIR_SSL}/afr.conf"
cp "afrc.conf" "${DIR_SSL}/afrc.conf"
pushd "${DIR_SSL}"

# Generate old CA certificate.
ca_gen "old_root"
ca_selfsign "old_root"
ca_crl_gen "old_root"

# Generate old-style friend certificate.
ca_gen "old_friend"
ca_req_gen "old_friend"
ca_req_submit "old_root" "old_friend"
ca_req_sign "old_root" "old_friend"
ca_req_receive "old_root" "old_friend"

# Initialize new AFR CA.
afr -c afr.conf init

# Generate AFR friend certificate.
cp afrc.conf new_friend.conf
sed -i "s/FIXME/new_friend/" new_friend.conf
afrc -c new_friend.conf init "new_friend"
afr -c afr.conf sign-friend "new_friend/csr/new_friend.pem" "new_friend"
afrc -c new_friend.conf receive-client "signing_ca/certs/new_friend.pem"

# Test 0: Old PKI.
# This test configures InspIRCd for the old-style PKI.  In this configuration,
# the old friend certificate should work but not the new friend certificate.
i=0
j=0
RESULTS[$i]=""
echo "Test $i: Old PKI"

## Configure InspIRCd to use the old PKI.
chown -R "root:inspircd" "${DIR_SSL}"
sed -ri "s!#*(cafile=\")[^\"]+!\1${DIR_SSL}/old_root/certs/old_root.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/old_root/certs/old_root.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlfile=\")[^\"]+!\1${DIR_SSL}/old_root/crl/old_root.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/old_root/private/old_root.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/old_root/private/old_root.pem!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Connect as the old friend.
set +e
subtest_mark
connect "old_friend"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: Old friend unable to authenticate to service\n"
fi

## Connect as the new friend.
subtest_mark
connect "new_friend"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: New friend authenticated to old service\n"
fi

# Test 1: Transition PKI.
#   new_root
#       |
#   signing_ca
#       |
#   old_root
# This test configures InspIRCd for the transition PKI.  In this configuration,
# the old friend certificate and new friend certificate should both be
# authorized.
i=$(($i + 1))
j=0
RESULTS[$i]=""
echo "Test $i: Transition PKI"

## Cross-certify the old root as a referrer.
set -e
ca_req_gen "old_root"
ca_req_submit "signing_ca" "old_root"
ca_req_sign "signing_ca" "old_root" "v3_referrer"
#afr -c afr.conf sign-referrer "old_root/csr/old_root.pem" "old_root"
cat "${DIR_SSL}/ca.pem" "${DIR_SSL}/signing_ca/certs/old_root.pem" > "${DIR_SSL}/transition_ca.pem"
cat "${DIR_SSL}/crl.pem" "${DIR_SSL}/old_root/crl/old_root.pem" > "${DIR_SSL}/transition_crl.pem"

## Configure InspIRCd to use the new PKI.
set -e
chown -R "root:inspircd" "${DIR_SSL}"
sed -ri "s!#*(cafile=\")[^\"]+!\1${DIR_SSL}/transition_ca.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/certs.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlfile=\")[^\"]+!\1${DIR_SSL}/transition_crl.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/localhost/private/localhost.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/localhost/private/localhost.pem!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Connect as the old friend.
set +e
subtest_mark
connect "old_friend"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: Old friend not authenticated to service\n"
fi

## Connect as the new friend.
subtest_mark
connect "new_friend"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: New friend not authenticated to service\n"
fi

# Test 2: New PKI.
# This test configures InspIRCd for the new-style AFR PKI.  In this
# configuration, the old friend certificate should not be authorized but the
# new friend certificate should be authorized.
i=$(($i + 1))
j=0
RESULTS[$i]=""
echo "Test $i: New PKI"

## Configure InspIRCd to use the new PKI.
set -e
chown -R "root:inspircd" "${DIR_SSL}"
sed -ri "s!#*(cafile=\")[^\"]+!\1${DIR_SSL}/ca.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/certs.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlfile=\")[^\"]+!\1${DIR_SSL}/crl.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/localhost/private/localhost.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/localhost/private/localhost.pem!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Connect as the old friend.
set +e
subtest_mark
connect "old_friend"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: Old friend authenticated to service\n"
fi

## Connect as the new friend.
subtest_mark
connect "new_friend"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: New friend not authenticated to service\n"
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
