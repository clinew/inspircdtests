#!/bin/bash

# This is to help test the SSL rehashing functionality.  A new set of
# certificates is generated for the "owner", their "friend" and their
# "fof" (friend-of-friend).  Before rehashing the fof shouldn't be
# able to connect with their certificate; after rehashing, they should
# be able to connect.
#
# TODO: Automate IRC client connecting.  Need IRC client automation
#       software...

# Test dir home to backup original config.
DIR_HOME="${HOME}/.inspircdtests"
# Home dir for the InspIRCd configuration.
DIR_IRCD="/etc/inspircd"
# Home dir for the OpenSSL files.
DIR_SSL="/etc/ssl/frostsnow.net"

# Backup config dirs.
mkdir -p "${DIR_HOME}"
cp -rp "${DIR_IRCD}" "${DIR_HOME}/"
cp -rp "${DIR_SSL}" "${DIR_HOME}/"

# Create owner cert.
mkdir -p "${DIR_SSL}"
cd "${DIR_SSL}"
rm -rf ./*
umask 0077
mkdir certs csr crl newcerts private
touch index.txt
echo 1000 > serial
cp "${DIR_HOME}/`basename ${DIR_SSL}`/openssl.cnf" ./
cp "${DIR_HOME}/`basename ${DIR_SSL}`/dhparams.pem" ./
openssl genrsa -out private/owner.pem 4096
openssl req -config openssl.cnf -key private/owner.pem -new -x509 -days 7200 -sha512 -extensions v3_ca -out certs/owner.pem -subj '/CN=owner/'
ln certs/owner.pem certs/cert.pem
ln private/owner.pem private/key.pem

# Create friend cert.
mkdir -p "friend"
cp openssl.cnf friend/openssl.cnf
pushd "friend"
mkdir certs csr crl newcerts private
touch index.txt
echo 1000 > serial
#sed -ri 's/(\/etc\/ssl\/frostsnow\.net)/\1\/friend/' openssl.cnf
sed -ri "s/^dir\\s+=\\s+.*/dir = .\\//" openssl.cnf
openssl genrsa -out private/friend.pem 4096
openssl req -new -sha512 -key private/friend.pem -out csr/friend.pem -subj '/CN=friend/'
popd
cp friend/csr/friend.pem csr/friend.pem
openssl ca -config openssl.cnf -keyfile private/owner.pem -cert certs/owner.pem -extensions v3_friend -days 7200 -notext -md sha512 -in csr/friend.pem -out certs/friend.pem -batch
cp certs/friend.pem friend/certs/friend.pem

# Create fof cert.
pushd friend
mkdir -p "fof"
pushd fof
mkdir certs csr crl newcerts private
openssl genrsa -out private/fof.pem 4096
openssl req -new -sha512 -key private/fof.pem -out csr/fof.pem -subj '/CN=fof/'
popd
cp fof/csr/fof.pem csr/fof.pem
openssl ca -config openssl.cnf -keyfile private/friend.pem -cert certs/friend.pem -extensions v3_fof -days 7200 -notext -md sha512 -in csr/fof.pem -out certs/fof.pem -batch
cp certs/fof.pem fof/certs/fof.pem
popd

# Owner cert for client validation.
cp certs/cert.pem certs/client_cas.pem
umask 0044

# fof sends cert, fails.
chown -R inspircd:inspircd "${DIR_SSL}"
FINGERPRINT=`openssl x509 -fingerprint -in ${DIR_SSL}/certs/owner.pem -noout | sed 's/.*=//' | sed 's/://g' | sed 'y/ABCDEF/abcdef/'`
sed -ri "s/fingerprint=\".*\"/fingerprint=\"${FINGERPRINT}\"/" "${DIR_IRCD}/opers.conf"
rc-service inspircd restart
echo "Connect with fof client (should fail)"
echo "    /connect -ssl -ssl_cert friend/fof/certs/fof.pem -ssl_pkey friend/fof/private/fof.pem 127.0.0.1 6697 herp derp"
read

# Reconfigure to add friend cert as CA.
cat certs/friend.pem >> certs/client_cas.pem
echo "Reconfigure server with rehash then rehash -ssl"
echo "    /connect -ssl -ssl_cert certs/owner.pem -ssl_pkey private/owner.pem 127.0.0.1 6697 herp derp"
echo "    /rehash"
echo "    /rehash -ssl"
read

# fof sends cert, success.
echo "Reconnect with fof client (should now work)"
echo "    /connect -ssl -ssl_cert friend/fof/certs/fof.pem -ssl_pkey friend/fof/private/fof.pem 127.0.0.1 6697 herp derp"
read

# Restore inspircd dir.
rm -rf "${DIR_SSL}"
rm -rf "${DIR_IRCD}"
cp -rp "${DIR_HOME}/`basename ${DIR_IRCD}`" "${DIR_IRCD}"
cp -rp "${DIR_HOME}/`basename ${DIR_SSL}`" "${DIR_SSL}"
rc-service inspircd restart
