#!/bin/sh
#-----------------------------
START=`pwd`

if test $# -eq 1; then
  mkdir -p $1
  cd $1
  DST=`pwd`
else
  DST=.
fi

BASE=$START/$(dirname $0)
cd $BASE
#-----------------------------

#-----------------------------
make_root_certificate() {
	local name=${1:-root}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                \
		--outfile=$DST/_${name}_key.pem
	certtool \
		--generate-self-signed \
		--template=templ-root.cfg \
		--load-privkey=$DST/_${name}_key.pem \
		--no-text \
                 \
                \
		--outfile=$DST/_${name}.pem
}
#-----------------------------
make_sub_certificate() {
	local name=${1:-sub} auth=${2:-root}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                \
		--outfile=$DST/_${name}_key.pem
	certtool \
		--generate-certificate \
		--template=templ-sub.cfg \
		--load-privkey=$DST/_${name}_key.pem \
		--load-ca-privkey=$DST/_${auth}_key.pem \
		--load-ca-certificate=$DST/_${auth}.pem \
		--no-text \
                 \
                \
		--outfile=$DST/_${name}.pem
	cat _${name}.pem _${auth}.pem > _${name}_chain.pem
}
#-----------------------------
make_end_certificate() {
	local name=${1:-end} auth=${2:-sub}
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                \
		--outfile=$DST/_${name}_key.pem
	certtool \
		--generate-certificate \
		--template=templ-end.cfg \
		--load-privkey=$DST/_${name}_key.pem \
		--load-ca-privkey=$DST/_${auth}_key.pem \
		--load-ca-certificate=$DST/_${auth}.pem \
		--no-text \
                 \
                \
		--outfile=$DST/_${name}.pem
	cat _${name}.pem _${auth}_chain.pem > _${name}_chain.pem
}
#-----------------------------
make_root_certificate root
make_sub_certificate  server root
make_end_certificate  client server

