#!/bin/bash

# This tests that the server will only verify "strong" certs, defined
# by a whitelist of minimum keytype+keysize pairs and a whitelist of signature
# algorithms.
#
# Copyright (C) 2018,2020  Wade T. Cline
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

# Test whether or not the specified client can connect.
# 1: Name of the client that will try connecting.
# 2: Path to the client's key.
# 3: (optional) Name of client's CA.
# 4: (optional) Client intermediate cert(s).
# Returns 0 if connect successful, 1 if connection failed, 2 if unknown.
cli_con_test() {
	name=$1
	key=$2
	cli_ca=${3:-root_ca}
	chain=$4
	if [ ! -z "${chain}" ]; then
		chain="-cert_chain ${chain}"
	fi

	output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs/cert.pem" -cert "${cli_ca}/certs/${name}.pem" -key "${key}" -connect 127.0.0.1:6697 -ign_eof ${chain})
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

# Restore configuration handler on SIGINT.
restore() {
	for name in root_ca intr_4k intr_2k; do
		rm -rf "${DIR_HOME}/${name}"
	done
	rm -rf ${DIR_HOME}/*.pem
	rm -rf "${DIR_SSL}"
	rm -rf "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_IRCD}`" "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_SSL}`" "${DIR_SSL}"
	rc-service inspircd restart
	exit 0
}

# Load includes.
source include.sh

# Check InspIRCd config.
grep -E 'peer_keysize_min=' "${DIR_IRCD}/modules.conf"
if [ $? -ne 0 ]; then
	echo "Expected to find 'peer_keysize_min=' in OpenSSL config file"
	exit 1
fi
grep -E 'peer_sigalg=' "${DIR_IRCD}/modules.conf"
if [ $? -ne 0 ]; then
	echo "Expected to find 'peer_sigalg=' in OpenSSL config file"
	exit 1
fi

# Configure InspIRCd OpenSSL.
inspircd_conf

# Backup config dirs.
mkdir -p "${DIR_HOME}"
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
cp -rp "${DIR_SSL}" "${DIR_HOME}/"
trap "restore" INT
pushd "${DIR_HOME}"

# Generate keys + certificates.
# Root CA
ca_gen "root_ca"
ca_selfsign "root_ca"
# Generate keys
openssl genrsa -out rsa-8k.pem 8192
openssl genrsa -out rsa-4k.pem 4096
openssl genrsa -out rsa-2k.pem 2048
openssl ecparam -out ec.pem -name secp521r1 -genkey
openssl genrsa -out intr-4k.pem 4096
openssl genrsa -out intr-2k.pem 2048
# Generate certs
# 8k-RSA + SHA512
openssl req -new -key rsa-8k.pem -out req.pem -subj "/CN=RSA-8k-SHA512/"
mv "req.pem" "root_ca/csr/rsa-8k-sha512.pem"
ca_req_sign "root_ca" "rsa-8k-sha512" "" "sha512"
# 4k-RSA + SHA512
openssl req -new -key rsa-4k.pem -out req.pem -subj "/CN=RSA-4k-SHA512/"
mv "req.pem" "root_ca/csr/rsa-4k-sha512.pem"
ca_req_sign "root_ca" "rsa-4k-sha512" "" "sha512"
# 2k-RSA + SHA512
openssl req -new -key rsa-2k.pem -out req.pem -subj "/CN=RSA-2k-SHA512/"
mv "req.pem" "root_ca/csr/rsa-2k-sha512.pem"
ca_req_sign "root_ca" "rsa-2k-sha512" "" "sha512"
# 4k-RSA + SHA256
openssl req -new -key rsa-4k.pem -out req.pem -subj "/CN=RSA-4k-SHA256/"
mv "req.pem" "root_ca/csr/rsa-4k-sha256.pem"
ca_req_sign "root_ca" "rsa-4k-sha256" "" "sha256"
# 2k-RSA + SHA256
openssl req -new -key rsa-2k.pem -out req.pem -subj "/CN=RSA-2k-SHA256/"
mv "req.pem" "root_ca/csr/rsa-2k-sha256.pem"
ca_req_sign "root_ca" "rsa-2k-sha256" "" "sha256"
# 4k-RSA + SHA1
openssl req -new -key rsa-4k.pem -out req.pem -subj "/CN=RSA-4k-SHA1/"
mv "req.pem" "root_ca/csr/rsa-4k-sha1.pem"
ca_req_sign "root_ca" "rsa-4k-sha1" "" "sha1"
# EC + SHA512
openssl req -new -key ec.pem -out req.pem -subj "/CN=EC-SHA512/"
mv "req.pem" "root_ca/csr/ec-sha512.pem"
ca_req_sign "root_ca" "ec-sha512" "" "sha512"
# Generate intermediate CAs
# 4k intermediate
ca_gen "intr_4k"
ca_req_gen "intr_4k"
cp "intr_4k/csr/intr_4k.pem" "root_ca/csr/intr_4k.pem"
ca_req_sign "root_ca" "intr_4k"
cp "root_ca/certs/intr_4k.pem" "intr_4k/certs/intr_4k.pem"
# 2k intermediate
ca_gen "intr_2k" 2048
ca_req_gen "intr_2k"
cp "intr_2k/csr/intr_2k.pem" "root_ca/csr/intr_2k.pem"
ca_req_sign "root_ca" "intr_2k"
cp "root_ca/certs/intr_2k.pem" "intr_2k/certs/intr_2k.pem"
# Generate certs with intermediate CAs
# 4k intermediate, 4k leaf
openssl req -new -key rsa-4k.pem -out req.pem -subj "/CN=intr-4k-leaf-4k/"
mv "req.pem" "intr_4k/csr/intr-4k-leaf-4k.pem"
ca_req_sign "intr_4k" "intr-4k-leaf-4k"
# 4k intermediate, 2k leaf
openssl req -new -key rsa-2k.pem -out req.pem -subj "/CN=intr-4k-leaf-2k/"
mv "req.pem" "intr_4k/csr/intr-4k-leaf-2k.pem"
ca_req_sign "intr_4k" "intr-4k-leaf-2k"
# 2k intermediate, 4k leaf
openssl req -new -key rsa-4k.pem -out req.pem -subj "/CN=intr-2k-leaf-4k/"
mv "req.pem" "intr_2k/csr/intr-2k-leaf-4k.pem"
ca_req_sign "intr_2k" "intr-2k-leaf-4k"

# Configure InspIRCd properly.
ca_crl_gen "root_ca"
ca_crl_gen "intr_4k"
ca_crl_gen "intr_2k"
cp "root_ca/certs/root_ca.pem" "${DIR_SSL}/certs/cert.pem"
cp "root_ca/certs/root_ca.pem" "${DIR_SSL}/certs/client_cas.pem"
cp "root_ca/private/root_ca.pem" "${DIR_SSL}/private/key.pem"
cat {root_ca,intr_4k,intr_2k}/crl/*.pem > "${DIR_SSL}/crl/crl.pem"
sed -ri "s/#(crlfile)/\1/" "${DIR_IRCD}/modules.conf"
results=()

### No options set, connect regularly
sed -ri "s/(peer_keysize_min)/#\1/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Test 00: 4k RSA, SHA512 passes
echo "Test 00"
cli_con_test "rsa-4k-sha512" "rsa-4k.pem"
if [ $? -eq 0 ]; then
	results[0]=""
else
	results[0]="FAILED"
fi

### Single cert/alg tests
## Sigalg SHA512 + RSA4k
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:4096/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*(peer_sigalg=\")[^\"]+/\1RSA-SHA512/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Test 01: 8k RSA, SHA512 passes
echo "Test 01"
cli_con_test "rsa-8k-sha512" "rsa-8k.pem"
if [ $? -eq 0 ]; then
	results[1]=""
else
	results[1]="FAILED"
fi
# Test 02: 4k RSA, SHA512 passes
echo "Test 02"
cli_con_test "rsa-4k-sha512" "rsa-4k.pem"
if [ $? -eq 0 ]; then
	results[2]=""
else
	results[2]="FAILED"
fi
# Test 03: 2k RSA, SHA512 fails
echo "Test 03"
cli_con_test "rsa-2k-sha512" "rsa-2k.pem"
if [ $? -eq 1 ]; then
	results[3]=""
else
	results[3]="FAILED"
fi
# Test 04: 4k RSA, SHA256 fails
echo "Test 04"
cli_con_test "rsa-4k-sha256" "rsa-4k.pem"
if [ $? -eq 1 ]; then
	results[4]=""
else
	results[4]="FAILED"
fi
# Test 05: 2k RSA, SHA256 fails
echo "Test 05"
cli_con_test "rsa-2k-sha256" "rsa-2k.pem"
if [ $? -eq 1 ]; then
	results[5]=""
else
	results[5]="FAILED"
fi
# Test 06: EC 256 fails
# TODO: Refactor keysize specifications to allow more precisely specifying
# elliptic curves, and create a test that checks for success so that it's
# clear that the certificate didn't fail for some other reason.
echo "Test 06"
cli_con_test "ec-sha512" "ec.pem"
if [ $? -eq 1 ]; then
	results[6]=""
else
	results[6]="FAILED"
fi

### Multi cert/alg tests
## Sigalg SHA512 + SHA256 test
sed -ri "s/(peer_keysize_min)/#\1/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*(peer_sigalg=\")[^\"]+/\1RSA-SHA512,RSA-SHA256/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Test 07: 4k RSA, SHA512 passes
echo "Test 07"
cli_con_test "rsa-4k-sha512" "rsa-4k.pem"
if [ $? -eq 0 ]; then
	results[7]=""
else
	results[7]="FAILED"
fi
# Test 08: 4k RSA, SHA256 passes
echo "Test 08"
cli_con_test "rsa-4k-sha256" "rsa-4k.pem"
if [ $? -eq 0 ]; then
	results[8]=""
else
	results[8]="FAILED"
fi
# Test 09: 4k RSA, SHA1 fails
echo "Test 09"
cli_con_test "rsa-4k-sha1" "rsa-4k.pem"
if [ $? -eq 1 ]; then
	results[9]=""
else
	results[9]="FAILED"
fi

### Parsing tests
# Test 10: Bogus key type test
echo "Test 10"
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1fakeKeyAlg:4096/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[10]=""
else
	results[10]="FAILED"
fi
# Test 11: Zero key size
echo "Test 11"
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:0/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[11]=""
else
	results[11]="FAILED"
fi
# Test 12: Negative key size
echo "Test 12"
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:-4096/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[12]=""
else
	results[12]="FAILED"
fi
# Test 13: Bogus key size value
echo "Test 13"
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:FooBar/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[13]=""
else
	results[13]="FAILED"
fi
# Test 14: Multiple ':' delimiters in key size
echo "Test 14"
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:2048:4096/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[14]=""
else
	results[14]="FAILED"
fi
# Test 15: Bogus algorithm
echo "Test 15"
sed -ri "s/(peer_keysize_min)/#\1/" "${DIR_IRCD}/modules.conf"
sed -ri "s/#*(peer_sigalg=\")[^\"]+/\1FakeSignatureAlgorithm/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[15]=""
else
	results[15]="FAILED"
fi
# Test 16: Same key specified multiple times
echo "Test 16"
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:4096,rsaEncryption:2048/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
grep peer "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
if [ $? -ne 0 ]; then
	results[16]=""
else
	results[16]="FAILED"
fi

### Peer chain tests.
sed -ri "s/#*(peer_keysize_min=\")[^\"]+/\1rsaEncryption:4096/" "${DIR_IRCD}/modules.conf"
sed -ri "s/(peer_sigalg)/#\1/" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart
# Test 17: 4k intermediate, 4k leaf passes
echo "Test 17"
cli_con_test "intr-4k-leaf-4k" "rsa-4k.pem" "intr_4k" "intr_4k/certs/intr_4k.pem"
if [ $? -eq 0 ]; then
	results[17]=""
else
	results[17]="FAILED"
fi
# Test 18: 4k intermediate, 2k leaf fails
echo "Test 18"
rc-service inspircd restart
cli_con_test "intr-4k-leaf-2k" "rsa-2k.pem" "intr_4k" "intr_4k/certs/intr_4k.pem"
if [ $? -eq 1 ]; then
	results[18]=""
else
	results[18]="FAILED"
fi
# Test 19: 2k intermediate, 4k leaf fails
echo "Test 19"
rc-service inspircd restart
cli_con_test "intr-2k-leaf-4k" "rsa-4k.pem" "intr_2k" "intr_2k/certs/intr_2k.pem"
if [ $? -eq 1 ]; then
	results[19]=""
else
	results[19]="FAILED"
fi

# Print results.
for i in $(seq 0 $((${#results[*]} - 1))); do
	echo -n "Test '$i' "
	if [ -z "${results[$i]}" ]; then
		echo "PASSED"
	else
		echo "FAILED"
	fi
done

restore
