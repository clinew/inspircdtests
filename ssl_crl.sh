#!/bin/bash

# This tests the CRL functionality.
# Copyright (C) 2018  Wade T. Cline
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

#      A
#     / \
#    B   C
#   /     \
#  D       E
#
# Test 01: Confirm that A, B, C, D, and E can connect via CRL file.
# Test 02: Test that A, B, C, D, and E can connect via CRL path (chain mode).
# Test 03: Test that A, B, C, D, and E can connect via CRL file (leaf mode).
# Test 04: Test that D cannot connect via CRL file (chain mode).
# Test 05: Test that D cannot connect via CRL path (chain mode).
# Test 06: Test that D cannot connect via CRL file (leaf mode).
# Test 07: Test that neither C, D, nor E can connect via CRL file (chain mode).
# Test 08: Test that neither C, D, nor E can connect via CRL path (chain mode).
# Test 09: Test that neither C nor D can connect via CRL file (leaf mode).
# Test 10: No CRL file (error starting).
# Test 11: Invalid CRL mode.
# Test ??: No CRL path (error starting).


# Test dir home to backup original config.
DIR_HOME="${HOME}/.inspircdtests"
# Home dir for the InspIRCd configuration.
DIR_IRCD="/etc/inspircd"
# Home dir for the OpenSSL files.
DIR_SSL="/etc/ssl/frostsnow.net"

# Function to generate CA shenanegains.
# 1: Name of CA to generate.
ca_gen() {
	mkdir $1
	pushd $1
	cp "${DIR_SSL}/openssl.cnf" ./
	sed -ri "s/^dir\\s+=\\s+.*/dir = .\\//" openssl.cnf
	mkdir certs csr crl newcerts private
	touch index.txt
	echo 1000 > serial
	echo 1000 > crlnumber
	umask 0077
	openssl genrsa -out "private/$1.pem" 4096
	umask 0022
	popd
}

# Test whether or not the specified client can connect.
# 1: Name of the client that will try connecting
# Returns 0 if connect successful, 1 if connection failed, 2 if unknown.
cli_test() {
	name=$1
	output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs/cert.pem" -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" -connect 127.0.0.1:6697 -ign_eof)
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

# OpenSSL is too retarded to just read a directory of files, instead it
# expects to find a hash of the issuer and uses that to find the CRL, wtf?
# 1: CRL directory
crlpath_gen() {
	for crl in `ls ${1}/*.pem`; do
		hash=$(openssl crl -hash -in "${crl}" -noout)
		# Just assume no collisions for simplicity.
		ln -s "${crl}" "${1}/${hash%$'\n'}.r0"
	done
}

# Restore original configuration.
restore() {
	for name in a b c d e; do
		rm -rf "${DIR_HOME}/${name}"
	done
	rm -rf "${DIR_SSL}"
	rm -rf "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_IRCD}`" "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_SSL}`" "${DIR_SSL}"
	rc-service inspircd restart
	exit 0
}

# Sanity checks.
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

# Backup config dirs.
mkdir -p "${DIR_HOME}"
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
cp -rp "${DIR_SSL}" "${DIR_HOME}/"
pushd ${DIR_HOME}
trap "restore" INT

# Generate certificates.
echo "Generating Certificates"
# A
ca_gen "a"
pushd "a"
openssl req -key private/a.pem -new -x509 -days 7200 -sha512 -out certs/a.pem -subj '/CN=a/'
popd
# B
ca_gen "b"
pushd "b"
openssl req -new -sha512 -key private/b.pem -out csr/b.pem -subj '/CN=b/'
cp csr/b.pem ../a/csr/b.pem
popd
pushd "a"
openssl ca -config openssl.cnf -keyfile private/a.pem -cert certs/a.pem -extensions v3_friend -days 7200 -notext -md sha512 -in csr/b.pem -out certs/b.pem -batch
cp certs/b.pem ../b/certs/b.pem
popd
# C
ca_gen "c"
pushd "c"
openssl req -new -sha512 -key private/c.pem -out csr/c.pem -subj '/CN=c/'
cp csr/c.pem ../a/csr/c.pem
popd
pushd "a"
openssl ca -config openssl.cnf -keyfile private/a.pem -cert certs/a.pem -extensions v3_friend -days 7200 -notext -md sha512 -in csr/c.pem -out certs/c.pem -batch
cp certs/c.pem ../c/certs/c.pem
popd
# D
ca_gen "d"
pushd "d"
openssl req -new -sha512 -key private/d.pem -out csr/d.pem -subj '/CN=d/'
cp csr/d.pem ../b/csr/d.pem
popd
pushd "b"
openssl ca -config openssl.cnf -keyfile private/b.pem -cert certs/b.pem -extensions v3_fof -days 7200 -notext -md sha512 -in csr/d.pem -out certs/d.pem -batch
cp certs/d.pem ../d/certs/d.pem
popd
# E
ca_gen "e"
pushd "e"
openssl req -new -sha512 -key private/e.pem -out csr/e.pem -subj '/CN=e/'
cp csr/e.pem ../c/csr/e.pem
popd
pushd "c"
openssl ca -config openssl.cnf -keyfile private/c.pem -cert certs/c.pem -extensions v3_fof -days 7200 -notext -md sha512 -in csr/e.pem -out certs/e.pem -batch
cp certs/e.pem ../e/certs/e.pem
popd

# Configure inspircd to trust A, B, and C.
cat a/certs/a.pem b/certs/b.pem c/certs/c.pem > "${DIR_SSL}/certs/client_cas.pem"
# Generate CRLs.
pushd "a"
openssl ca -gencrl -config openssl.cnf -cert certs/a.pem -keyfile private/a.pem -out crl/a.pem
popd
pushd "b"
openssl ca -gencrl -config openssl.cnf -cert certs/b.pem -keyfile private/b.pem -out crl/b.pem
popd
pushd "c"
openssl ca -gencrl -config openssl.cnf -cert certs/c.pem -keyfile private/c.pem -out crl/c.pem
popd

# TEST 01: Confirm that A, B, C, D, and E can connect via CRL file.
# Create CRL for inspircd.
test01=""
echo "Test 01"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Actually run the test.
cli_test "a"
if [ $? -ne 0 ]; then
	test01="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test01="${test01}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 0 ]; then
	test01="${test01}Expected 'c' to authenticate\n"
fi
cli_test "d"
if [ $? -ne 0 ]; then
	test01="${test01}Expected 'd' to authenticate\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test01="${test01}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/crl.pem"
# Test 02: Test that A, B, C, D, and E can connect via CRL path (chain mode).
test02=""
echo "Test 02"
cp a/crl/a.pem "${DIR_SSL}/crl/a.pem"
cp b/crl/b.pem "${DIR_SSL}/crl/b.pem"
cp c/crl/c.pem "${DIR_SSL}/crl/c.pem"
crlpath_gen "${DIR_SSL}/crl"
sed -ri "s/crlfile/#crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlpath/crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Actually run the test.
cli_test "a"
if [ $? -ne 0 ]; then
	test02="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test02="${test02}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 0 ]; then
	test02="${test02}Expected 'c' to authenticate\n"
fi
cli_test "d"
if [ $? -ne 0 ]; then
	test02="${test02}Expected 'd' to authenticate\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test02="${test02}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/"*
# Test 03: Test that A, B, C, D, and E can connect via CRL file (leaf mode).
test03=""
echo "Test 03"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"leaf\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Actually run the test.
cli_test "a"
if [ $? -ne 0 ]; then
	test03="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test03="${test03}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 0 ]; then
	test03="${test03}Expected 'c' to authenticate\n"
fi
cli_test "d"
if [ $? -ne 0 ]; then
	test03="${test03}Expected 'd' to authenticate\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test03="${test03}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/crl.pem"
# Revoke D's certificate.
pushd "b"
openssl ca -config openssl.cnf -keyfile private/b.pem -cert certs/b.pem -revoke certs/d.pem
openssl ca -gencrl -config openssl.cnf -cert certs/b.pem -keyfile private/b.pem -out crl/b.pem
popd
# Test 04: Test that D cannot connect via CRL file (chain mode).
test04=""
echo "Test 04"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
cli_test "a"
if [ $? -ne 0 ]; then
	test04="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test04="${test04}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 0 ]; then
	test04="${test04}Expected 'c' to authenticate\n"
fi
cli_test "d"
if [ $? -ne 1 ]; then
	test04="${test04}Expected 'd' to be denied\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test04="${test04}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/crl.pem"
# Test 05: Test that D cannot connect via CRL path (chain mode).
test05=""
echo "Test 05"
cp a/crl/a.pem "${DIR_SSL}/crl/a.pem"
cp b/crl/b.pem "${DIR_SSL}/crl/b.pem"
cp c/crl/c.pem "${DIR_SSL}/crl/c.pem"
crlpath_gen "${DIR_SSL}/crl"
sed -ri "s/crlfile/#crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlpath/crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
cli_test "a"
if [ $? -ne 0 ]; then
	test05="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test05="${test05}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 0 ]; then
	test05="${test05}Expected 'c' to authenticate\n"
fi
cli_test "d"
if [ $? -ne 1 ]; then
	test05="${test05}Expected 'd' to be denied\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test05="${test05}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/"*
# Test 06: Test that D cannot connect via CRL file (leaf mode).
test06=""
echo "Test 06"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"leaf\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
cli_test "a"
if [ $? -ne 0 ]; then
	test06="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test06="${test06}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 0 ]; then
	test06="${test06}Expected 'c' to authenticate\n"
fi
cli_test "d"
if [ $? -ne 1 ]; then
	test06="${test06}Expected 'd' to be denied\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test06="${test06}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/crl.pem"
# Revoke C's certificate.
pushd "a"
openssl ca -config openssl.cnf -keyfile private/a.pem -cert certs/a.pem -revoke certs/c.pem
openssl ca -gencrl -config openssl.cnf -cert certs/a.pem -keyfile private/a.pem -out crl/a.pem
popd
# Test 07: Test that neither C, D, nor E can connect via CRL file (chain mode).
test07=""
echo "Test 07"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
cli_test "a"
if [ $? -ne 0 ]; then
	test07="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test07="${test07}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 1 ]; then
	test07="${test07}Expected 'c' to be denied\n"
fi
cli_test "d"
if [ $? -ne 1 ]; then
	test07="${test07}Expected 'd' to be denied\n"
fi
cli_test "e"
if [ $? -ne 1 ]; then
	test07="${test07}Expected 'e' to be denied\n"
fi
rm "${DIR_SSL}/crl/crl.pem"
# Test 08: Test that neither C, D, nor E can connect via CRL path (chain mode).
test08=""
echo "Test 08"
cp a/crl/a.pem "${DIR_SSL}/crl/a.pem"
cp b/crl/b.pem "${DIR_SSL}/crl/b.pem"
cp c/crl/c.pem "${DIR_SSL}/crl/c.pem"
crlpath_gen "${DIR_SSL}/crl"
sed -ri "s/crlfile/#crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlpath/crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
cli_test "a"
if [ $? -ne 0 ]; then
	test08="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test08="${test08}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 1 ]; then
	test08="${test08}Expected 'c' to be denied\n"
fi
cli_test "d"
if [ $? -ne 1 ]; then
	test08="${test08}Expected 'd' to be denied\n"
fi
cli_test "e"
if [ $? -ne 1 ]; then
	test08="${test08}Expected 'e' to be denied\n"
fi
rm "${DIR_SSL}/crl/"*
# Test 09: Test that neither C nor D can connect via CRL file (leaf mode).
echo "Test 09"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"leaf\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
cli_test "a"
if [ $? -ne 0 ]; then
	test09="Expected 'a' to authenticate\n"
fi
cli_test "b"
if [ $? -ne 0 ]; then
	test09="${test09}Expected 'b' to authenticate\n"
fi
cli_test "c"
if [ $? -ne 1 ]; then
	test09="${test09}Expected 'c' to be denied\n"
fi
cli_test "d"
if [ $? -ne 1 ]; then
	test09="${test09}Expected 'd' to be denied\n"
fi
cli_test "e"
if [ $? -ne 0 ]; then
	test09="${test09}Expected 'e' to authenticate\n"
fi
rm "${DIR_SSL}/crl/crl.pem"
# Test 10: No CRL file (error starting).
echo "Test 10"
cp a/crl/a.pem "${DIR_SSL}/crl/crl.pem"
cat b/crl/b.pem >> "${DIR_SSL}/crl/crl.pem"
cat c/crl/c.pem >> "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlfile/crlfile=\"\/broken\/crl\/path\" #crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -eq 0 ]; then
	test10="Expected InspIRCd failure on startup"
else
	test10=""
fi
sed -ri "s/crlfile=\"\/broken\/crl\/path\" #crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
# Test 11: Invalid CRL mode.
echo "Test 11"
sed -ri "s/#*crlfile/crlfile/" "${DIR_IRCD}/modules.conf"
sed -ri "s/crlpath/#crlpath/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*crlmode=\".*\"/crlmode=\"forest\"/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -eq 0 ]; then
	test11="Expected InspIRCd failure on startup"
else
	test11=""
fi
sed -ri "s/#*crlmode=\".*\"/crlmode=\"chain\"/" "${DIR_IRCD}/modules.conf"
# Test NULL: No CRL path (error starting).  OpenSSL doesn't return an error if the path doesn't exist, WTF?

# Print results:
echo -n "Test 01: "
if [ -z "${test01}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test01})"
fi
echo -n "Test 02: "
if [ -z "${test02}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test02})"
fi
echo -n "Test 03: "
if [ -z "${test03}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test03})"
fi
echo -n "Test 04: "
if [ -z "${test04}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test04})"
fi
echo -n "Test 05: "
if [ -z "${test05}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test05})"
fi
echo -n "Test 06: "
if [ -z "${test06}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test06})"
fi
echo -n "Test 07: "
if [ -z "${test07}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test07})"
fi
echo -n "Test 08: "
if [ -z "${test08}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test08})"
fi
echo -n "Test 09: "
if [ -z "${test09}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test09})"
fi
echo -n "Test 10: "
if [ -z "${test10}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test10})"
fi
echo -n "Test 11: "
if [ -z "${test11}" ]; then
	echo "PASSED!"
else
	echo "FAILED (${test11})"
fi

# Restore inspircd dir.
restore
