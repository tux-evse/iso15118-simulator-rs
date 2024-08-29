#!/bin/bash
#-----------------------------

function usage {
    printf "Usage: \n\
        -h|--help \t displays this text\n
        -d|--debug \t run the script in debug mode\n\
        -i|--destination \t distination directory\n\
        "
    exit
}

template_cert_dir="/etc/default/"
DST="."

while [[ $# -gt 0 ]];do
    key="$1"
    case $key in
        -d|--debug)
            DEBUG="YES";
            template_cert_dir="../afb-test/certs"
            shift 1;
        ;;
        -i|--destination)
            mkdir -p "$2"
            cd "$2"
            DST=$(pwd)
            shift 2;
        ;;
        -h|--help)
            usage;
        ;;
        *)
            usage;
        ;;
    esac
done

#BASE="${START}/$(dirname $0)"
#cd "${BASE}"
#mkdir -p "${DST}/trusted"

#-----------------------------

#-----------------------------
make_root_certificate() {
	local name="${1:-root}"
	certtool \
		--generate-privkey \
		--key-type=ecdsa \
                --curve=secp256r1 \
		--no-text \
                \
		--outfile="${DST}/_${name}_key.pem"
	certtool \
		--generate-self-signed \
		--template="${template_cert_dir}/templ-root.cfg" \
		--load-privkey="${DST}/_${name}_key.pem" \
		--no-text \
                 \
                \
		--outfile="${DST}/_${name}.pem"
    cp "${DST}/_${name}.pem" "${DST}/trusted"
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
		--outfile=${DST}/_${name}_key.pem
	certtool \
		--generate-certificate \
		--template="${template_cert_dir}/templ-sub.cfg" \
		--load-privkey=${DST}/_${name}_key.pem \
		--load-ca-privkey=${DST}/_${auth}_key.pem \
		--load-ca-certificate=${DST}/_${auth}.pem \
		--no-text \
                 \
                \
		--outfile=${DST}/_${name}.pem
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
		--outfile=${DST}/_${name}_key.pem
	certtool \
		--generate-certificate \
		--template="${template_cert_dir}/templ-end.cfg" \
		--load-privkey=${DST}/_${name}_key.pem \
		--load-ca-privkey=${DST}/_${auth}_key.pem \
		--load-ca-certificate=${DST}/_${auth}.pem \
		--no-text \
                 \
                \
		--outfile=${DST}/_${name}.pem
	cat _${name}.pem _${auth}_chain.pem > _${name}_chain.pem
}
#-----------------------------
make_root_certificate root
make_sub_certificate  server root
make_end_certificate  client server
make_end_certificate  contract server

