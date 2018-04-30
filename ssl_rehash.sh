#!/bin/bash

# This is to help test the SSL rehashing functionality.  A new set of
# certificates is generated for the "owner", their "friend" and their
# "fof" (friend-of-friend).  Before rehashing the fof shouldn't be
# able to connect with their certificate; after rehashing, they should
# be able to connect.

source "include.sh"

# Test whether or not the specified client can connect.
# 1: Name of the client that will try connecting.
# 2: Set to nonempty to rehash.
# Returns 0 if connect successful, 1 if connection failed, 2 if unknown.
cli_con_test() {
	name=$1
	rehash=${2:-""}

	# Build input to the server.
	input="echo -e \"USER a hostess servant rjhacker\nNICK a\"; sleep 5;"
	if [ ! -z "${rehash}" ]; then
		input="${input} echo \"rehash\"; sleep 5; echo \"rehash -ssl\"; sleep 5;"
	fi
	input="${input} echo \"QUIT\";"

	# Connect and send input.  This is getting quite evil.
	output=$( (eval "${input}") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs/cert.pem" -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" -connect 127.0.0.1:6697 -ign_eof)
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

# Return to original configuration.
restore() {
	rm -rf "${DIR_SSL}"
	rm -rf "${DIR_IRCD}"
	rm -rf "${DIR_HOME}/"{owner,friend,fof}
	cp -rp "${DIR_HOME}/`basename ${DIR_IRCD}`" "${DIR_IRCD}"
	cp -rp "${DIR_HOME}/`basename ${DIR_SSL}`" "${DIR_SSL}"
	rc-service inspircd restart
}

# Backup config dirs.
mkdir -p "${DIR_HOME}"
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
cp -rp "${DIR_SSL}" "${DIR_HOME}/"
trap "restore" EXIT

# Create owner cert.
cd "${DIR_HOME}"
ca_gen "owner"
ca_selfsign "owner"
ca_crl_gen "owner"

# Create friend cert.
ca_gen "friend"
ca_req_gen "friend"
cp "friend/csr/friend.pem" "owner/csr/friend.pem"
ca_req_sign "owner" "friend"
cp "owner/certs/friend.pem" "friend/certs/friend.pem"
ca_crl_gen "friend"

# Create fof cert.
ca_gen "fof"
ca_req_gen "fof"
cp "fof/csr/fof.pem" "friend/csr/fof.pem"
ca_req_sign "friend" "fof"
cp "friend/certs/fof.pem" "fof/certs/fof.pem"

# Reconfigure InspIRCd.
cp owner/certs/owner.pem "${DIR_SSL}/certs/cert.pem"
cp owner/private/owner.pem "${DIR_SSL}/private/key.pem"
cat owner/certs/owner.pem > "${DIR_SSL}/certs/client_cas.pem"
cat owner/crl/owner.pem > "${DIR_SSL}/crl/crl.pem"
FINGERPRINT=`openssl x509 -fingerprint -sha256 -in owner/certs/owner.pem -noout | sed 's/.*=//' | sed 's/://g' | sed 'y/ABCDEF/abcdef/'`
sed -ri "s/fingerprint=\".*\"/fingerprint=\"${FINGERPRINT}\"/" "${DIR_IRCD}/opers.conf"
rc-service inspircd restart

# fof sends cert, fails.
chown -R inspircd:inspircd "${DIR_SSL}"
echo "Connecting with fof client (should fail)"
cli_con_test "fof"
ret=$?
if [ $ret -eq 0 ]; then
	echo "Test should have failed but it passed"
	exit 1
elif [ $ret -ne 1 ]; then
	echo "Unknown result, dying"
	exit 1
fi

# Reconfigure to add friend cert as CA.
echo "Rehashing InspIRCd"
cat friend/certs/friend.pem >> "${DIR_SSL}/certs/client_cas.pem"
cat friend/crl/friend.pem >> "${DIR_SSL}/crl/crl.pem"
cli_con_test "owner" "rehash"
ret=$?
if [ ${ret} -eq 1 ]; then
	echo "Owner should have connected but didn't"
	exit 1
elif [ ${ret} -ne 0 ]; then
	echo "Unknown result, dying"
	exit 1
fi

# fof sends cert, success.
echo "Reconnect with fof client (should now work)"
cli_con_test "fof"
ret=$?
if [ ${ret} -eq 1 ]; then
	echo "fof failed to connect but should have succeeded"
	exit 1
elif [ ${ret} -ne 0 ]; then
	echo "Unknown result, dying"
	exit 1
fi
exit 0 # Test passed.
