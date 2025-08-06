#! /bin/bash

openssl genrsa -out ca_private_key.pem 4096

openssl req -x509 -days 365 -key ca_private_key.pem -out ca_cert.pem -config - << EOF
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

openssl genrsa -out my_private_key.pem 4096

openssl req -new -key my_private_key.pem -out my_cert_req.pem -config - << EOF
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


openssl x509 -req -in my_cert_req.pem -days 365 -CA ca_cert.pem -CAkey ca_private_key.pem -CAcreateserial -out my_signed_cert.pem