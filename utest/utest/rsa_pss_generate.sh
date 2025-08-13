#! /bin/bash

scriptfile=`readlink -f $0`
scriptdir=`dirname $scriptfile`
cadir=$scriptdir/rsa_pss

if [ ! -d $cadir ]
then
	mkdir -p $cadir
fi

 openssl genpkey -algorithm rsa-pss -pkeyopt rsa_keygen_bits:4096  -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256  -pkeyopt rsa_pss_keygen_saltlen:32 -out $cadir/root.key

 openssl req -new -nodes -x509 -days 3650 -pkeyopt rsa_keygen_bits:4096 -sigopt rsa_pss_saltlen:32 -key $cadir/root.key -subj "/C=CN/ST=Beijing/L=Beijing/O=example/OU=Personal/CN=yourdomain.com" -out $cadir/rootcert.pem
