#!/bin/bash

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
	openssl ca -gencrl -config openssl.cnf -cert "certs/$1.pem" -keyfile "private/$1.pem" -out "crl/$1.pem"
	popd
}

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

# Function to generate a CSR.
# $1 The CA to generate a CSR for.
ca_req_gen() {
	pushd "$1"
	openssl req -new -sha512 -key "private/$1.pem" -out "csr/$1.pem" -subj "/CN=$1/"
	popd
}

# Function to sign a CSR from a CA.
# $1 The CA which will sign.
# $2 The CA which will be signed.
# $3 (optional) Extensions to use.
# $4 (optional) Hash to sign the cert with.
ca_req_sign() {
	local extensions=${3:-v3_friend}
	local md=${4:-sha512}
	pushd "$1"
	openssl ca -config openssl.cnf -keyfile "private/$1.pem" -cert "certs/$1.pem" -extensions "$extensions" -days 7200 -notext -md ${md} -in "csr/$2.pem" -out "certs/$2.pem" -batch
	popd
}

# Function to self-sign a CA.
# $1 The CA to self-sign.
ca_selfsign() {
	pushd "$1"
	openssl req -key "private/$1.pem" -new -x509 -days 7200 -sha512 -out "certs/$1.pem" -subj "/CN=$1/"
	popd
}

