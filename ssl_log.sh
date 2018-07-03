#!/bin/bash

# Test InspIRCd OpenSSL logging functionality.

# Test 01: Valid certificate
#   A -> B (Server has root CA 'A' and client connects using signed
#   cert 'B').
# Test 02: Invalid certificate
#   A,  D -> E (Server has root CA 'A' and client connects using cert 'E'
#   which is signed by untrusted root CA 'D').
# Test 03: Missing certificate
#   Client presents no certificate.
# Test 04: Server uses root and intermediate CA
#   A -> B -> C (Server trusts root CA 'A' and intermediate CA 'B', client
#   presents signed cert 'C')
# Test 05: Client presents intermediate CA and leaf cert
#   A -> B -> C (Server trusts root CA 'A' and client connects using
#   intermediate CA 'B' and signed cert 'C')

# Load includes.
source include.sh

# Restore original configuration.
restore() {
	for name in root_ca leaf_ca fake_ca fail_ca a b c; do
		rm -rf "${DIR_HOME}/${name}"
	done
	rm -rf "${DIR_SSL}"
	rm -rf "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_IRCD}`" "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_SSL}`" "${DIR_SSL}"
	rc-service inspircd restart
	exit 0
}

# Connect to the server.
# $1 User to connect.
# $2 Additional cert to connect with.
connect() {
	local name="$1"
	local chain="${2:+-cert_chain $2/certs/$2.pem}"
	local output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs/cert.pem" -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" ${chain} -connect 127.0.0.1:6697 -ign_eof)
}

# Sanity check for log 'flush=1'.
grep -E 'log.*flush="1"' "${DIR_IRCD}/inspircd.conf"
if [ $? -ne 0 ]; then
	# Can't parse log for status if it's buffered.
	echo "Unable to find 'flush=\"1\"' attribute in log tag, quitting"
	exit -1
fi

# Backup config dirs.
mkdir -p "${DIR_HOME}"
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
cp -rp "${DIR_SSL}" "${DIR_HOME}/"
pushd "${DIR_HOME}"
trap "restore" INT

# Generate CA certificate
ca_gen "root_ca"
ca_selfsign "root_ca"
ca_crl_gen "root_ca"

# Generate valid client certificate
ca_gen "leaf_ca"
ca_req_gen "leaf_ca"
cp "leaf_ca/csr/leaf_ca.pem" "root_ca/csr/leaf_ca.pem"
ca_req_sign "root_ca" "leaf_ca"
cp "root_ca/certs/leaf_ca.pem" "leaf_ca/certs/leaf_ca.pem"

# Run test #01 (Connect with valid certificate)
echo "Test 01:"
## Configure server.
cp "root_ca/certs/root_ca.pem" "${DIR_SSL}/certs/cert.pem"
cp "root_ca/certs/root_ca.pem" "${DIR_SSL}/certs/client_cas.pem"
cp "root_ca/private/root_ca.pem" "${DIR_SSL}/private/key.pem"
cp "root_ca/crl/root_ca.pem" "${DIR_SSL}/crl/crl.pem"
rm ${LOG}
rc-service inspircd restart
## Connect to server.
connect "leaf_ca"
## Check IRCd log.
fingerprint=$(openssl x509 -in "leaf_ca/certs/leaf_ca.pem" -fingerprint -sha256 -noout | cut -d '=' -f 2 | sed 's/://g' | sed 'y/ABCDEF/abcdef/')
if cat ${LOG} | grep "${fingerprint}"; then
	echo "Fingerprint found"
	TEST01=1
else
	echo "Fingerprint not found: $(cat ${LOG})"
	TEST01=0
fi

# Generate invalid root certificate
ca_gen "fake_ca"
ca_selfsign "fake_ca"
ca_crl_gen "fake_ca"

# Generate invalid client certificate
ca_gen "fail_ca"
ca_req_gen "fail_ca"
cp "fail_ca/csr/fail_ca.pem" "fake_ca/csr/fail_ca.pem"
ca_req_sign "fake_ca" "fail_ca"
cp "fake_ca/certs/fail_ca.pem" "fail_ca/certs/fail_ca.pem"

# Run test #02 (Connect with invalid certificate)
echo "Test 02:"
rm ${LOG}
rc-service inspircd restart
## Connect to server.
connect "fail_ca"
## Check IRCd log.
if cat ${LOG} | grep "unable to verify the first certificate"; then
	echo "Invalid certificate detected"
	TEST02=1
else
	echo "Invalid certificate not detected: $(cat ${LOG})"
	TEST02=0
fi

# Run test #03 (No certificate)
echo "Test 03:"
rm ${LOG}
rc-service inspircd restart
## Connect to server.
(echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs/cert.pem" -connect 127.0.0.1:6697 -ign_eof > /dev/null
## Check IRCd log.
if cat ${LOG} | grep "Could not get peer certificate"; then
	echo "Successfully detected lack of peer certificate"
	TEST03=1
else
	echo "Failed to detect lack of peer certificate: $(cat ${LOG})"
	TEST03=0
fi

# Setup chain for tests 04 and 05.
# A
ca_gen "a"
ca_selfsign "a"
ca_crl_gen "a"
# B
ca_gen "b"
ca_req_gen "b"
cp "b/csr/b.pem" "a/csr/b.pem"
ca_req_sign "a" "b"
cp "a/certs/b.pem" "b/certs/b.pem"
ca_crl_gen "b"
# C
ca_gen "c"
ca_req_gen "c"
cp "c/csr/c.pem" "b/csr/c.pem"
ca_req_sign "b" "c"
cp "b/certs/c.pem" "c/certs/c.pem"

# Test 04: Server uses root and intermediate CAs.
echo "Test 04:"
## Configure server.
cp "a/certs/a.pem" "${DIR_SSL}/certs/cert.pem"
cat "a/certs/a.pem" "b/certs/b.pem" > "${DIR_SSL}/certs/client_cas.pem"
cp "a/private/a.pem" "${DIR_SSL}/private/key.pem"
cat "a/crl/a.pem" "b/crl/b.pem" > "${DIR_SSL}/crl/crl.pem"
rm "${LOG}"
rc-service inspircd restart
## Connect to server.
connect "c"
## Check IRCd log.
fingerprint=$(openssl x509 -in "c/certs/c.pem" -fingerprint -sha256 -noout | cut -d '=' -f 2 | sed 's/://g' | sed 'y/ABCDEF/abcdef/')
if cat ${LOG} | grep "${fingerprint}"; then
	echo "Fingerprint found"
	TEST04=1
else
	echo "Fingerprint not found: $(cat ${LOG})"
	TEST04=0
fi

# Test 05: Client presents multiple certificates.
# FIXME: This fails unless the server already has a CRL for 'B', is there a way
# for the client to pass B's CRL?
echo "Test 05:"
## Configure server.
cp "a/certs/a.pem" "${DIR_SSL}/certs/cert.pem"
cp "a/certs/a.pem" "${DIR_SSL}/certs/client_cas.pem"
cp "a/private/a.pem" "${DIR_SSL}/private/key.pem"
cat "a/crl/a.pem" "b/crl/b.pem" > "${DIR_SSL}/crl/crl.pem"
rm "${LOG}"
rc-service inspircd restart
## Connect to server.
connect "c" "b"
## Check IRCd log.
fingerprint_b=$(openssl x509 -in "b/certs/b.pem" -fingerprint -sha256 -noout | cut -d '=' -f 2 | sed 's/://g' | sed 'y/ABCDEF/abcdef/')
fingerprint_c=$(openssl x509 -in "c/certs/c.pem" -fingerprint -sha256 -noout | cut -d '=' -f 2 | sed 's/://g' | sed 'y/ABCDEF/abcdef/')
if cat ${LOG} | grep "${fingerprint_b}"; then
	echo "Fingerprint for b found"
else
	echo "Fingerprint b not found ($fingerprint_b)"
	fingerprint_b=""
fi
if cat ${LOG} | grep "${fingerprint_c}"; then
	echo "Fingerprint for c found"
else
	echo "Fingerprint c not found ($fingerprint_c)"
	fingerprint_c=""
fi
if [ -z "${fingerprint_b}" -o -z "${fingerprint_c}" ]; then
	echo "Log: $(cat ${LOG})"
	TEST05=0
else
	TEST05=1
fi

# Report results.
PASS=1
if [ $TEST01 -eq 1 ]; then
	echo "Test 01 PASSED!"
else
	PASS=0
	echo "Test 01 FAILED"
fi
if [ $TEST02 -eq 1 ]; then
	echo "Test 02 PASSED!"
else
	PASS=0
	echo "Test 02 FAILED"
fi
if [ $TEST03 -eq 1 ]; then
	echo "Test 03 PASSED!"
else
	PASS=0
	echo "Test 03 FAILED"
fi
if [ $TEST04 -eq 1 ]; then
	echo "Test 04 PASSED!"
else
	PASS=0
	echo "Test 04 FAILED!"
fi
if [ $TEST05 -eq 1 ]; then
	echo "Test 05 PASSED!"
else
	PASS=0
	echo "Test 05 FAILED!"
fi

restore

if [ $PASS -eq 1 ]; then
	exit 0
else
	exit -1
fi
