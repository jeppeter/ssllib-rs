#! /bin/bash


scriptfile=`readlink -f $0`
scriptdir=`dirname $scriptfile`
cadir=$scriptdir/wca

if [ ! -d $cadir ]
then
	mkdir -p $cadir
fi

openssl genrsa -out $cadir/ca_private_key.pem 4096

openssl req -x509 -days 365 -key $cadir/ca_private_key.pem -out $cadir/ca_cert.pem -config - << EOF
[req]
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
default_days     = 1000  
# this is names
[dn]
CN=ca Root CA
EOF

openssl genrsa -out $cadir/my_private_key.pem 4096

openssl req -new -key $cadir/my_private_key.pem -out $cadir/my_cert_req.pem -config - << EOF
[req]
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
default_days     = 1000  

# this is names
[dn]
CN=my Root CA

EOF


openssl x509 -req -in $cadir/my_cert_req.pem -days 365 -CA $cadir/ca_cert.pem -CAkey $cadir/ca_private_key.pem -CAcreateserial -out $cadir/my_signed_cert.pem

openssl genrsa -out $cadir/sub_private_key.pem 4096

openssl req -new -key $cadir/sub_private_key.pem -out $cadir/sub_cert_req.pem -config - << EOF
[req]
prompt = no
utf8 = yes
string_mask = utf8only
distinguished_name = dn
default_days     = 1000  

# this is names
[dn]
CN=sub Root CA

EOF


openssl x509 -req -in $cadir/sub_cert_req.pem -days 365 -CA $cadir/my_signed_cert.pem -CAkey $cadir/my_private_key.pem -CAcreateserial -out $cadir/sub_signed_cert.pem

openssl verify -CAfile $cadir/ca_cert.pem -untrusted $cadir/my_signed_cert.pem $cadir/sub_signed_cert.pem
