#!/bin/bash

# Various helper functions
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

# Test dir home to backup original config.
DIR_HOME="${HOME}/.inspircdtests"
# Home dir for the InspIRCd configuration.
DIR_IRCD="/etc/inspircd"
# Home dir for the OpenSSL files.
DIR_SSL="/etc/ssl/frostsnow.net"

LOG="/var/log/inspircd/ircd.log"

# Generate a CRL for the specified CA.
# $1 The CA to generate the CRL for.
ca_crl_gen() {
	pushd "$1"
	openssl ca -gencrl -config openssl.cnf -cert "certs/${1}.pem" -keyfile "private/${1}.pem" -out "crl/${1}.pem"
	popd
}

# Function to generate CA shenanegains.
# 1: Name of CA to generate.
# 2: (optional) RSA key size of the CA
ca_gen() {
	local keysize=${2:-4096}

	mkdir "$1"
	pushd "$1"
	ca_gen_skel_
	umask 0077
	openssl genrsa -out "private/$1.pem" ${keysize}
	umask 0022
	popd
}

# Generate a CA whose private key is a named elliptic curve.
# 1: The name of the CA to generate.
# 2: The named elliptic curve for the private key
ca_gen_ec() {
	mkdir $1
	pushd $1
	ca_gen_skel_
	umask 0077
	openssl ecparam -out "private/$1.pem" -name "${2}" -genkey
	umask 0022
	popd
}

# Generate all the cruft (skeleton) stuff for a CA, but do not generate the
# private key.  Private function.
ca_gen_skel_() {
	cp "${DIR_SSL}/openssl.cnf" ./
	sed -ri "s/^dir\\s+=\\s+.*/dir = .\\//" openssl.cnf
	mkdir certs csr crl newcerts private
	touch index.txt
	echo 1000 > serial
	echo 1000 > crlnumber
}

# Function to generate a CSR.
# $1 The CA to generate a CSR for.
ca_req_gen() {
	pushd "$1"
	openssl req -new -sha512 -key "private/$1.pem" -out "csr/$1.pem" -subj "/CN=$1/"
	popd
}

# Function to retrieve a signed certificate from the signing CA back to the
# requesting CA.  This is currently a glorified wrapper for a copy function.
# $1 The CA which did the signing.
# $2 The CA which was signed.
ca_req_receive() {
	cp "$1/certs/$2.pem" "$2/certs/$2.pem"
}

# Function to sign a CSR from a CA.
# Signing a certificate and then immediately using it has been known to cause
# 'Not activated, or expired certificate' errors, so sign it 3 seconds in the
# past.
# $1 The CA which will sign.
# $2 The CA which will be signed.
# $3 (optional) Extensions to use.
# $4 (optional) Hash to sign the cert with.
ca_req_sign() {
	local extensions=${3:-v3_friend}
	local md=${4:-sha512}
	pushd "$1"
	openssl ca -config openssl.cnf -keyfile "private/${1}.pem" -cert "certs/${1}.pem" -extensions "$extensions" -days 7200 -notext -md ${md} -in "csr/${2}.pem" -out "certs/${2}.pem" -batch -startdate $(TZ=UTC date +%Y%m%d%H%M%SZ --date "now - 3 seconds")
	popd
}

# Function to submit one CA's CSR to another CA for signing.  This is currently
# a glorified wrapper for a copy function.
# $1 The CA which will sign.
# $2 The CA which will be signed.
ca_req_submit() {
	cp "$2/csr/$2.pem" "$1/csr/$2.pem"
}

# Have the specified CA revoke the specified CA's certificate.  This also
# updates the former CA's CRL.
# $1 The CA which will be issuing the revocation.
# $2 The CA which will be revoked.
ca_revoke() {
	pushd "$1"
	openssl ca -config openssl.cnf -keyfile "private/${1}.pem" -cert "certs/${1}.pem" -revoke "certs/${2}.pem"
	popd
	ca_crl_gen "${1}"
}

# Function to self-sign a CA.
# $1 The CA to self-sign.
ca_selfsign() {
	pushd "$1"
	openssl req -key "private/$1.pem" -new -x509 -days 7200 -sha512 -out "certs/$1.pem" -subj "/CN=$1/"
	popd
}

# Return 1 if the OpenSSL module is using SHA-256, 0 otherwise.
openssl_sha256() {
	grep -zPo '(?s)<openssl.*\n\h*hash="sha256".*>' "${DIR_IRCD}/modules.conf" > "/dev/null"
}
