#!/bin/bash

# Test "Admin, Friend, Referred" PKI.
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
source include.sh

# Test dir home to backup original config.
DIR_HOME="${HOME}/.inspircdtests"
# Home dir for the InspIRCd configuration.
DIR_IRCD="/etc/inspircd"
# Home dir for the OpenSSL files.
DIR_SSL="/etc/ssl/frostsnow"
# Array to store test results in.
RESULTS=()

# Connect to the server and return whether or not the client was granted access
# by the server.  '0' means the client was granted access, '1' means the client
# was denied access, '2' means it is unknown whether the client was granted
# access or not.
connect() {
	name=$1
	output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 3; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/CAfile.pem" -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" -connect localhost:6697 -ign_eof)
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

# Sanity checks.
if [ ! -d "${DIR_IRCD}" ]; then
	echo "InspIRCd directory '${DIR_IRCD}' does not exist, quitting."
	exit 1
fi
set +e
grep "crlfile=" "${DIR_IRCD}/modules.conf"
if [ $? -ne 0 ]; then
	echo "No 'crlfile' option in IRCd, quitting."
	exit 1
fi
grep "crlpath=" "${DIR_IRCD}/modules.conf"
if [ $? -ne 0 ]; then
	echo "No 'crlpath' option in IRCd, quitting."
	exit 1
fi
grep "crlmode=" "${DIR_IRCD}/modules.conf"
if [ $? -ne 0 ]; then
	echo "No 'crlmode' option in IRCd, quitting."
	exit 1
fi
set -e

# Backup config dirs.
rm -rf "${DIR_HOME}"
mkdir -p "${DIR_HOME}"
## Backup InspIRCd dir.
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
## Backup SSL dir.
[ -f "${DIR_SSL}" ] && cp -rp "${DIR_SSL}" "${DIR_HOME}/"
rm -rf "${DIR_SSL}"
trap "restore" EXIT

# Set-up.
mkdir -p "${DIR_SSL}"
cp "openssl.cnf" "${DIR_SSL}/openssl.cnf"
pushd "${DIR_SSL}"

# Test 00: Initialize.
# This tests that the PKI was initialized successfully.  This means that the
# service is offering the correct server certificate and will only accept
# connections from a valid client certificate.
i=0
RESULTS[$i]=""

## Initialize root certificate.
ca_gen "root_ca"
ca_selfsign "root_ca"
ca_crl_gen "root_ca"

## Initialize service certificate.
ca_gen "localhost"
ca_req_gen "localhost"
ca_req_submit "root_ca" "localhost"
ca_req_sign "root_ca" "localhost" "v3_service"
ca_req_receive "root_ca" "localhost"

## Initialize signing certificate.
ca_gen "signing_ca"
ca_req_gen "signing_ca"
ca_req_submit "root_ca" "signing_ca"
ca_req_sign "root_ca" "signing_ca" "v3_signing"
ca_req_receive "root_ca" "signing_ca"
ca_crl_gen "signing_ca"

## Initialize admin's client certificate.
ca_gen "admin"
ca_req_gen "admin"
ca_req_submit "signing_ca" "admin"
ca_req_sign "signing_ca" "admin" "v3_client"
ca_req_receive "signing_ca" "admin"

## Initialize fake root certificate.
ca_gen "fake_root_ca"
ca_selfsign "fake_root_ca"
ca_crl_gen "fake_root_ca"

## Initialize fake service certificate.
ca_gen "fake_localhost"
ca_req_gen "fake_localhost"
ca_req_submit "fake_root_ca" "fake_localhost"
ca_req_sign "fake_root_ca" "fake_localhost" "v3_service"
ca_req_receive "fake_root_ca" "fake_localhost"

## Initialize fake signing certificate.
ca_gen "fake_signing_ca"
ca_req_gen "fake_signing_ca"
ca_req_submit "fake_root_ca" "fake_signing_ca"
ca_req_sign "fake_root_ca" "fake_signing_ca" "v3_signing"
ca_req_receive "fake_root_ca" "fake_signing_ca"
ca_crl_gen "fake_signing_ca"

## Initialize fake admin's client certificate.
ca_gen "fake_admin"
ca_req_gen "fake_admin"
ca_req_submit "fake_signing_ca" "fake_admin"
ca_req_sign "fake_signing_ca" "fake_admin" "v3_client"
ca_req_receive "fake_signing_ca" "fake_admin"

## Assemble certificate data for the client.
cat "${DIR_SSL}/localhost/certs/localhost.pem" "${DIR_SSL}/root_ca/certs/root_ca.pem" > "${DIR_SSL}/CAfile.pem"
cat "${DIR_SSL}/signing_ca/certs/signing_ca.pem" "${DIR_SSL}/root_ca/certs/root_ca.pem" > "${DIR_SSL}/certfile.pem"
cat "${DIR_SSL}/fake_localhost/certs/fake_localhost.pem" "${DIR_SSL}/fake_root_ca/certs/fake_root_ca.pem" > "${DIR_SSL}/fake_CAfile.pem"
cat "${DIR_SSL}/signing_ca/crl/signing_ca.pem" "${DIR_SSL}/root_ca/crl/root_ca.pem" > "${DIR_SSL}/crl.pem"
cat "${DIR_SSL}/fake_signing_ca/crl/fake_signing_ca.pem" "${DIR_SSL}/fake_root_ca/crl/fake_root_ca.pem" > "${DIR_SSL}/fake_crl.pem"

## Configure InspIRCd to use the fake server.
chown -R "root:inspircd" "${DIR_SSL}"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/fake_localhost/certs/fake_localhost.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/fake_localhost/private/fake_localhost.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/fake_localhost/private/fake_localhost.pem!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Test client successfully rejects fake server.
set +e
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/CAfile.pem" -connect localhost:6697
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\tClient authenticated illegitimate service\n"
fi
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/fake_CAfile.pem" -connect localhost:6697
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\tIllegitimate service probably not set-up properly\n"
fi
set -e

## Configure InspIRCd to use both the service certificate, the signing
## certificate, and the CRL file.
sed -ri "s!#*(cafile=\")[^\"]+!\1${DIR_SSL}/certfile.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/CAfile.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/localhost/private/localhost.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/localhost/private/localhost.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlfile=\")[^\"]+!\1${DIR_SSL}/crl.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlpath=\")[^\"]+!#\1!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlmode=\")[^\"]+!#\1chain!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Test client successfully authenticates service.
set +e
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/CAfile.pem" -connect localhost:6697
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\tClient unable to authenticate service\n"
fi
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/fake_CAfile.pem" -connect localhost:6697
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\tClient authenticated despite illlegitimate certificate\n"
fi

## Test client successfully authenticates with valid client cert.
connect "admin"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\tClient unable to authenticate to service\n"
fi

## Test client fails to authenticate with invalid client cert.
connect "fake_admin"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\tIllegitimate client authenticated successfully\n"
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
