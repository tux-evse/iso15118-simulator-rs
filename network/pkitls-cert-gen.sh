#!/bin/sh
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

ok=:
for x in devel-key.pem devel-cert.pem; do
  if test -f $x; then
    echo "error the file $x already exist"
    ok=false
  fi
done
$ok || exit

# comment or modify the below line to enter real data
HOSTNAME=localhost
SUBJ="-subj /C=Fr/ST=Breizh/L=Lorient/O=IoT.bzh/OU=R&D/CN=$HOSTNAME/emailAddress=fulup@hostname"

# set the duration of the certificates in days
DAYS=50

ext=$(mktemp)

cat > $ext << EOC
[default]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
EOC

rm -f _*.pem _*.crt

openssl genpkey \
	-algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
	-outform PEM \
	-out _server-key.pem
openssl req -new \
	-key _server-key.pem \
	$SUBJ |
openssl x509 -req \
    -sha256 \
	-days $DAYS \
	-signkey _server-key.pem \
	-extfile $ext \
	-extensions default \
	-out _server-cert.crt


SUBJ="-subj /C=Fr/ST=Breizh/L=Lorient/O=IoT.bzh/OU=R&D/CN=client/emailAddress=fulup@hostname"
openssl genpkey \
	-algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
	-outform PEM \
	-out _client-key.pem
openssl req -new \
	-key _client-key.pem \
	$SUBJ |
openssl x509 -req \
        -sha256 \
	-days $DAYS \
	-signkey _client-key.pem  \
	-extfile $ext \
	-extensions default \
	-out _client-cert.crt

cat _client-key.pem  _client-cert.crt >_client-cert.pem
rm $ext