#!/bin/bash

# Test InspIRCd OpenSSL logging functionality.

# Test 01: Valid certificate
# Test 02: Invalid certificate
# Test 03: Missing certificate

# Load includes.
source include.sh

# Restore original configuration.
restore() {
	for name in root_ca leaf_ca fake_ca fail_ca; do
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
connect() {
	local name="$1"
	local output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs/cert.pem" -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" -connect 127.0.0.1:6697 -ign_eof)
}

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
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
## Check IRCd log.
fingerprint=$(openssl x509 -in "leaf_ca/certs/leaf_ca.pem" -fingerprint -sha256 -noout | cut -d '=' -f 2 | sed 's/://g' | sed 'y/ABCDEF/abcdef/')
if cat ${LOG} | grep "${fingerprint}"; then
	echo "Fingerprint found"
	TEST01=1
else
	echo "Fingerprint not found: $(cat ${LOG})"
	TEST01=0
fi

# Generate invalid client certificate
ca_gen "fake_ca"
ca_selfsign "fake_ca"
ca_crl_gen "fake_ca"

# Generate valid client certificate
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
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
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
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
kill -HUP `cat /run/inspircd/inspircd.pid` # Fuck the log buffering.
## Check IRCd log.
if cat ${LOG} | grep "Could not get peer certificate"; then
	echo "Successfully detected lack of peer certificate"
	TEST03=1
else
	echo "Failed to detect lack of peer certificate: $(cat ${LOG})"
	TEST03=0
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

restore

if [ $PASS -eq 1 ]; then
	exit 0
else
	exit -1
fi
