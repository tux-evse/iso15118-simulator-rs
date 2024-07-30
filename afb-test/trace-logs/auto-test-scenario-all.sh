#!/bin/bash
TRACEDIR=$(cd `dirname $0`; pwd)
CONFDIR=$(cd $TRACEDIR/../etc;pwd`)
TSTDIR=$(cd $TRACEDIR/..;pwd`)

if test -z "$1"; then
    echo "syntax: $0 path to ISO/DIN scenatio dump"
    exit 1
fi

PCAP_DIR=$1
if ! test -d $PCAP_DIR; then
    echo "Invalid pcal dump directory:[$PCAP_DIR]"
    exit 1
fi

for IN_FILE in $(find $PCAP_DIR -name '*dump') ; do
    export SCENARIO_UID=$(basename $IN_FILE .dump)
    OUT_FILE=$CONFDIR/_autorun-scenario.json
    $TRACEDIR/pcap-to-json.sh `pwd`/$IN_FILE $OUT_FILE && \
    $CONFDIR/auto-test-scenario.sh afb-test/etc/_autorun-scenario.json
done

