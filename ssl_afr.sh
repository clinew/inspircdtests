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
DIR_SSL="/var/lib/afr/inspircdtests"
# Array to store test results in.
RESULTS=()

# Connect to the server and return whether or not the client was granted access
# by the server.  '0' means the client was granted access, '1' means the client
# was denied access, '2' means it is unknown whether the client was granted
# access or not.
connect() {
	name=$1
	output=$( (echo -e "USER a hostess servant rjhacker\nNICK a"; sleep 3; echo "QUIT") | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs.pem" -cert "${name}/certs/${name}.pem" -key "${name}/private/${name}.pem" -connect localhost:6697 -ign_eof)
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
cp "afr.conf" "${DIR_SSL}/afr.conf"
cp "afrc.conf" "${DIR_SSL}/afrc.conf"
cp "afr_fake.conf" "${DIR_SSL}/afr_fake.conf"
pushd "${DIR_SSL}"

# Test 00: Initialize.
#        root_ca                          fake_root_ca
#         /   \                           /         \
# localhost   signing_ca          fake_localhost   fake_signing_ca
#             /                                     /
#         admin                             fake_admin
# This tests that the PKI was initialized successfully.  This means that the
# service is offering the correct server certificate and will only accept
# connections from a valid client certificate.
i=0
j=0
RESULTS[$i]=""
echo "Test $i: Initialize"

## Initialize AFR root CA.
afr -c afr.conf init

## Initialize admin's client certificate.
cp afrc.conf admin.conf
sed -i "s/FIXME/admin/" admin.conf
afrc -c admin.conf init "admin"
afr -c afr.conf sign-friend "admin/csr/admin.pem" "admin"
afrc -c admin.conf receive-client "signing_ca/certs/admin.pem"

## Initialize AFR fake root CA.
afr -c afr_fake.conf init

## Initialize fake admin's client certificate.
cp afrc.conf fake_admin.conf
sed -i "s/FIXME/fake_admin/" fake_admin.conf
afrc -c fake_admin.conf init "fake_admin"
afr -c afr_fake.conf sign-friend "fake_admin/csr/fake_admin.pem" "fake_admin"
afrc -c fake_admin.conf receive-client "fake_signing_ca/certs/fake_admin.pem"

## Configure InspIRCd to use the fake server.
chown -R "root:inspircd" "${DIR_SSL}"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/fake_localhost/certs/fake_localhost.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/fake_localhost/private/fake_localhost.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/fake_localhost/private/fake_localhost.pem!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Test client successfully rejects fake server.
set +e
subtest_mark
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs.pem" -connect localhost:6697
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: Client authenticated illegitimate service\n"
fi
subtest_mark
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/fake_certs.pem" -connect localhost:6697
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: Illegitimate service probably not set-up properly\n"
fi
set -e

## Configure InspIRCd to use both the service certificate, the signing
## certificate, and the CRL file.
sed -ri "s!#*(cafile=\")[^\"]+!\1${DIR_SSL}/ca.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(certfile=\")[^\"]+!\1${DIR_SSL}/certs.pem!" "${DIR_IRCD}/modules.conf"
chmod 0740 "${DIR_SSL}/localhost/private/localhost.pem"
sed -ri "s!#*(keyfile=\")[^\"]+!\1${DIR_SSL}/localhost/private/localhost.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlfile=\")[^\"]+!\1${DIR_SSL}/crl.pem!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlpath=\")[^\"]+!#\1!" "${DIR_IRCD}/modules.conf"
sed -ri "s!#*(crlmode=\")[^\"]+!#\1chain!" "${DIR_IRCD}/modules.conf"
rc-service inspircd restart

## Test client successfully authenticates service.
set +e
subtest_mark
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/certs.pem" -connect localhost:6697
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: Client unable to authenticate service\n"
fi
subtest_mark
(sleep 3) | openssl s_client -verify_return_error -CAfile "${DIR_SSL}/fake_certs.pem" -connect localhost:6697
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: Client authenticated despite illlegitimate certificate\n"
fi

## Test client successfully authenticates with valid client cert.
subtest_mark
connect "admin"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: Client unable to authenticate to service\n"
fi

## Test client fails to authenticate with invalid client cert.
subtest_mark
connect "fake_admin"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: Illegitimate client authenticated successfully\n"
fi

# Test 01: Sign friend.
#        root_ca                     fake_root_ca
#         /   \                      /         \
# localhost   signing_ca     fake_localhost   fake_signing_ca
#             /    |                           /
#         admin   friend               fake_admin
# Sign a friend's certificate and verify that they can then connect to the
# service.  Parity: Ensure that a non-authorized certificate is unable to
# connect.
i=$(($i + 1))
j=0
RESULTS[$i]=""

## Initialize friend's certificate.
set -e
cp afrc.conf friend.conf
sed -i 's/FIXME/friend/' friend.conf
afrc -c friend.conf init "friend"
afr -c afr.conf sign-friend "friend/csr/friend.pem" "friend"
afrc -c friend.conf receive-client "signing_ca/certs/friend.pem"

## Test authenticating to the server as "friend".
set +e
subtest_mark
connect "friend"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'friend' unable to authenticate to service\n"
fi

## Test authentication failure to the server as "fake_admin".
subtest_mark
connect "fake_admin"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: 'fake_admin' successfully authenticated\n"
fi

# Test 02: Revoke friend.
#        root_ca
#         /   \
# localhost   signing_ca -
#             /    |      \
#         admin   friend   friend_bad (R)
# Revoke a bad friend's client certificate and verify that the bad friend can
# then no longer connect to the service.  Parity: Ensure that a regular friend
# can still connect to the service.
i=$(($i + 1))
j=0
RESULTS[$i]=""

## Initialize bad friend's certificate.
set -e
cp afrc.conf friend_bad.conf
sed -i 's/FIXME/friend_bad/' friend_bad.conf
afrc -c friend_bad.conf init "friend_bad"
afr -c afr.conf sign-friend "friend_bad/csr/friend_bad.pem" "friend_bad"
afrc -c friend_bad.conf receive-client "signing_ca/certs/friend_bad.pem"

## Test authenticating to the server as 'friend_bad'.
set +e
subtest_mark
connect "friend_bad"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'friend_bad' unable to authenticate to service\n"
fi

## Revoke the certificate of 'friend_bad'.
set -e
afr -c afr.conf revoke-friend "friend_bad"
rc-service inspircd restart

## Test authentication failure for revoked 'friend_bad'.
set +e
subtest_mark
connect "friend_bad"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: 'friend_bad' not unauthorized by service\n"
fi

## Test authentication success for 'friend'.
subtest_mark
connect "friend"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'friend' unable to authenticate to service\n"
fi

# Test 03: Generate friend signing cert.
#        root_ca                                    fake_root_ca
#         /   \                                     /         \
# localhost   signing_ca -                  fake_localhost   fake_signing_ca
#             /    |      \                                   /
#         admin   friend   friend.ref                    fake_admin
#                             |
#                          referred
# Give a friend referrer access and then ensure that the referred person is
# able to authorize against the service.  Parity: Ensure that an unauthorized
# certificate is not authorized.
i=$(($i + 1))
j=0
RESULTS[$i]=""

## Create friend's signing cert.
set -e
afrc -c friend.conf request-referrer
afr -c afr.conf sign-referrer "friend.ref/csr/friend.ref.pem" "friend"
afrc -c friend.conf receive-referrer "signing_ca/certs/friend.ref.pem"
afr -c afr.conf receive-crl "friend.ref/crl/friend.ref.pem" "friend"
rc-service inspircd restart

## Friend creates referred certificate.
cp afrc.conf referred.conf
sed -i 's/FIXME/referred/' referred.conf
afrc -c referred.conf init "referred"
afrc -c friend.conf sign-referred "referred/csr/referred.pem" "referred"
afrc -c referred.conf receive-client "friend.ref/certs/referred.pem"

## Test referred certificate.
set +e
subtest_mark
connect "referred"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'referred' unable to authenticate to service\n"
fi

## Test unauthorized certificate.
subtest_mark
connect "fake_admin"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: 'fake_admin' not unauthenticated to service\n"
fi

# Test 04: Revoke a referrer cert.
#        root_ca
#         /   \
# localhost   signing_ca -------------------------------
#             /    |      \            \                \
#         admin   friend   friend.ref   friend_bad_ref   friend_bad_ref.ref (R)
#                             |                                 |
#                          referred                         referred_bad
# Give a friend referrer access but then revoke their referrer access and
# ensure that their referred users are unauthorized.  Parity: Ensure another
# friend's referred users are still able authorized by the service.
i=$(($i + 1))
j=0
RESULTS[$i]=""

## Create friend's certificate for the bad referrer.
set -e
cp afrc.conf friend_bad_ref.conf
sed -i 's/FIXME/friend_bad_ref/' friend_bad_ref.conf
afrc -c friend_bad_ref.conf init "friend_bad_ref"
afr -c afr.conf sign-friend "friend_bad_ref/csr/friend_bad_ref.pem" "friend_bad_ref"
afrc -c friend_bad_ref.conf receive-client "signing_ca/certs/friend_bad_ref.pem"

## Create bad referrer certificate.
afrc -c friend_bad_ref.conf request-referrer
afr -c afr.conf sign-referrer "friend_bad_ref.ref/csr/friend_bad_ref.ref.pem" "friend_bad_ref"
afrc -c friend_bad_ref.conf receive-referrer "signing_ca/certs/friend_bad_ref.ref.pem"
afr -c afr.conf receive-crl "friend_bad_ref.ref/crl/friend_bad_ref.ref.pem" "friend_bad_ref"
rc-service inspircd restart

## Bad referrer creates a bad referred user.
cp afrc.conf referred_bad.conf
sed -i 's/FIXME/referred_bad/' referred_bad.conf
afrc -c referred_bad.conf init "referred_bad"
afrc -c friend_bad_ref.conf sign-referred "referred_bad/csr/referred_bad.pem" "referred_bad"
afrc -c referred_bad.conf receive-client "friend_bad_ref.ref/certs/referred_bad.pem"

## Test the bad referred user is authorized.
set +e
subtest_mark
connect "referred_bad"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'referred_bad' not authorized by service\n"
fi

## Revoke the bad referrer certificate.
set -e
afr -c afr.conf revoke-referrer "friend_bad_ref"
rc-service inspircd restart

## Test the bad referred user is unauthorized.
set +e
subtest_mark
connect "referred_bad"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: 'referred_bad' not unauthorized by service\n"
fi

## Test the (not bad) referred user is authorized.
subtest_mark
connect "referred"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'referred' not authorized by service\n"
fi

# Test 05: Indirectly revoke a referrer cert.
#        root_ca
#         /   \
# localhost   signing_ca -
#             /    |      \
#         admin   friend   friend.ref -
#                             |        \
#                          referred     referred_bad_indirect (R)
# A friend invites a referred (referred_bad_indirect) user, but the admin
# decides to revoke the referred user without revoking the friend's referrer
# certificate.  Parity: Ensure that other users the friend has invited are
# still authorized.
# FIXME: There doesn't appear to be a way to issue an indrect revocation via
# the OpenSSL command-line utilities.  Nor does InspIRCd appear to offer a way
# to ban a user's certificate globally via a fingerprint; at most there is a
# way to ban users from a specific channel with the '+b z:${fingerprint}'
# extban.  As a workaround this test currently logs in as the 'admin' user,
# creates an unregistered channel '#temp', sets the 'extban' for the
# 'referred_bad_indirect' user's certificate, then attempts to join the channel
# with said certificate.  Parity: Able to join the channel as 'referred'.
i=$(($i + 1))
j=0
RESULTS[$i]=""

## Create the bad referred certificate.
set -e
cp afrc.conf referred_bad_indirect.conf
sed -i 's/FIXME/referred_bad_indirect/' referred_bad_indirect.conf
afrc -c referred_bad_indirect.conf init "referred_bad_indirect"
afrc -c friend.conf sign-referred "referred_bad_indirect/csr/referred_bad_indirect.pem" "referred_bad_indirect"
afrc -c referred_bad_indirect.conf receive-client "friend.ref/certs/referred_bad_indirect.pem"

## Test that the bad referred user is authorized.
set +e
subtest_mark
connect "referred_bad_indirect"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'referred_bad_indirect' not authorized by service pre-revocation\n"
fi

## Obtain bad referred fingerprint for banning.
set -e
fingerprint=$(openssl x509 -in "referred_bad_indirect/certs/referred_bad_indirect.pem" -fingerprint -sha256 -noout | cut -d '=' -f 2 | sed 's/://g' | sed 'y/ABCDEF/abcdef/')

## Join the temporary channel and set the ban on it.
## Yes, this is all a terrible hack and full of race conditions.
(echo -e "USER a hostess servant rjhacker\nNICK admin"; sleep 3; echo -e "JOIN #temp\nMODE #temp +b z:${fingerprint}"; sleep 40; echo "QUIT") | openssl s_client -verify_return_error -CAfile "certs.pem" -cert "admin/certs/admin.pem" -key "admin/private/admin.pem" -connect localhost:6697 -ign_eof &

## Attempt to join the temporary channel as the banned 'referred_bad_indirect'.
subtest_mark
output=$( (echo -e "USER a hostess servant rjhacker\nNICK referred_bad_indirect"; sleep 3; echo -e "JOIN #temp"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "certs.pem" -cert "referred_bad_indirect/certs/referred_bad_indirect.pem" -key "referred_bad_indirect/private/referred_bad_indirect.pem" -connect localhost:6697 -ign_eof)
set +e
if ! echo "${output}" | grep "#temp :Cannot join channel (you're banned)"; then
	RESULTS[$i]+="\t$j: 'referred_bad_indirect' not banned from '#temp'\n"
fi

## Attempt to join the temporary channel as 'referred'.
set -e
subtest_mark
output=$( (echo -e "USER a hostess servant rjhacker\nNICK referred"; sleep 3; echo -e "JOIN #temp"; sleep 5; echo "QUIT") | openssl s_client -verify_return_error -CAfile "certs.pem" -cert "referred/certs/referred.pem" -key "referred/private/referred.pem" -connect localhost:6697 -ign_eof)
set +e
if echo "${output}" | grep "#temp :Cannot join channel (you're banned)"; then
	RESULTS[$i]+="\t$j: 'referred' banned from '#temp'\n"
fi
set -e

## Wait for connect 'admin' to quit.
wait

# Test 06: Referrer revokes one of their referred users.
#        root_ca
#         /   \
# localhost   signing_ca -
#             /    |      \
#         admin   friend   friend.ref -
#                             |        \
#                          referred     referred_bad2 (R)
# A friend invites a referred (referred_bad2) user, but then decides to revoke
# the referred user's authorization.  Parity: Ensure another referred user is
# still authorized.
# TODO: How will this interact with IndirectCRLs?
i=$(($i + 1))
j=0
RESULTS[$i]=""

## Create the bad referred2 certificate.
set -e
cp afrc.conf referred_bad2.conf
sed -i 's/FIXME/referred_bad2/' referred_bad2.conf
afrc -c referred_bad2.conf init "referred_bad2"
afrc -c friend.conf sign-referred "referred_bad2/csr/referred_bad2.pem" "referred_bad2"
afrc -c referred_bad2.conf receive-client "friend.ref/certs/referred_bad2.pem"

## Test that bad referred2 is authorized.
set +e
subtest_mark
connect "referred_bad2"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'referred_bad2' not authorized pre-revocation\n"
fi

## Ban the referred user.
set -e
ca_revoke "friend.ref" "referred_bad2"
afr -c afr.conf receive-crl "friend.ref/crl/friend.ref.pem" "friend"
rc-service inspircd restart

## Test that bad referred2 is now unauthorized.
set +e
subtest_mark
connect "referred_bad2"
if [ $? -ne 1 ]; then
	RESULTS[$i]+="\t$j: 'referred_bad2' not unauthorized post-revocation\n"
fi

## Test that referred is still authorized.
subtest_mark
connect "referred"
if [ $? -ne 0 ]; then
	RESULTS[$i]+="\t$j: 'referred' not authorized post-revocation\n"
fi

# Test 07: Friend revokes their client certificate.
#        root_ca
#         /   \
# localhost   signing_ca -
#             /    |      \
#         admin   friend   friend_bad2 (R)
# A friend finds it necessary to revoke their own client certificate (perhaps
# a private key compromise).  Ensure that the friend can do so and thus becomes
# unauthorized.  Parity: Other clients can still connect.
# TODO: There doesn't appear to be a way for clients to revoke their own
# certificates, hence the issuer will have to do the revocation.  With a proper
# AFR network protocol in place, this could actually test having the client
# request a revocation from the issuer; right now, this would just be a repeat
# of Test #02, so don't even bother to implement it.
i=$(($i + 1))
j=0
RESULTS[$i]="\tNot implemented\n"

# Test 08: Referrer revokes their referring certificate.
#        root_ca
#         /   \
# localhost   signing_ca --------------
#             /    |      \            \
#         admin   friend   friend.ref   referrer_bad2 (R)
#                             |            |
#                          referred     referred_bad3
# A friend needs to revoke their referrer certificate.  Ensure that any
# referred users from their revoked certificate are not authorized.  Parity:
# Ensure that users referred by a non-revoked certificate are authorized.
# TODO: Same caveats as the previous test, except it'd be a repeat of Test #04.
i=$(($i + 1))
j=0
RESULTS[$i]="\tNot implemented\n"

# Test 09: Referred user revokes their client certificate.
#        root_ca
#         /   \
# localhost   signing_ca -
#             /    |      \
#         admin   friend   friend.ref -----
#                             |            \
#                          referred     referred_bad4 (R)
# A referred user needs to revoke their client certificate.  Ensure that the
# revoked referred user is unauthorized.  Parity: Ensure that another, non-
# revoked referred user is authorized.
# TODO: Same caveats as the previous two tests, except it'd be a repeat of Test
# #05 or #06.
i=$(($i + 1))
j=0
RESULTS[$i]="\tNot implemented\n"

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
