#!/bin/sh

CURDIR=$(dirname $0)
cd $CURDIR
TSTDIR=$(cd ..; pwd)
PRJDIR=$(cd ../..; pwd)
INFILE=$1

if test -z "$2"; then
    OUTFILE=$(echo "$TSTDIR/etc/`basename $INFILE .pcap`.json")
else
    OUTFILE=$2
fi

if test $# -lt 1; then
    echo Syntax: $0 path-to-pcap.pcap [path-scenario.json]
    exit 1
fi



if ! test -f "$1"; then
	echo "Fail to access file:$1"
	exit 1
fi

if test -n "${CARGO_TARGET_DIR}"; then
    for BINDIR in `ls -d $CARGO_TARGET_DIR/[d,r]*`; do
        export PATH=$BINDIR:$PATH
    done
else
    for BINDIR in $PRJDIR/build/[d,r]*; do
        export PATH=$BINDIR:$PATH
    done
fi

PCAPISO=which `pcap-iso15118`
if test -z "$PCAPISO"; then
    echo "Fail to find pcap-iso15118 binary within default PATH"
    exit 1
fi

echo pcap-iso15118 --compact=true --pcap_in=$INFILE --json_out=$OUTFILE --compact=true --verbose=0
pcap-iso15118 --compact=true --pcap_in=$INFILE --json_out=$OUTFILE --compact=true --verbose=0
