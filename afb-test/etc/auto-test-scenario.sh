#!/bin/bash

if test -z "$1"; then
    echo "syntax: $0 relative_path_to_scenario.json"
    exit 1
else
    INFILE=`pwd`/"$1"
    if test ! -f "$INFILE"; then
        echo "Fail to open scenario:$INFILE"
        exit 1
    fi
fi

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT
function ctrl_c() {
        echo "CTRL-C kill afbevcc+afb-evcc"
        pkill afb-evcc
        pkill afb-evse
}

BASEDIR=$(dirname $0)
TESTDIR=$(cd $BASEDIR/..; pwd)
PRJDIR=$(cd $TESTDIR/..; pwd)

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
export CARGO_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
export PKI_TLS_DIR="$PRJDIR/afb-test/certs"

ip -6 addr show $IFACE_SIMU | grep -i fe80 >/dev/null
if test $? -ne 0; then
    echo "Error: invalid $IFACE_SIMU (0xFE80 localink missing)"
    echo " check: ./afb-test/network/client-server-bridge.sh to create a fake evse/evcc network"
fi

# clean up old processed if any
pkill afb-evcc
pkill afb-evse

# start responder in background
export IFACE_SIMU=evse-veth
export SIMULATION_MODE="responder"
if test -z "$SCENARIO_UID"; then
    export SCENARIO_UID=`basename $INFILE .json`
fi
afb-binder --name afb-evse \
    -v \
    --config=$PRJDIR/afb-evse/etc/binding-simu15118-evse.yaml \
    --config=$INFILE &

export SIMULATION_MODE="injector"
export IFACE_SIMU=evcc-veth
export SCENARIO_AUTORUN=1
afb-binder --name afb-evcc \
    -v \
    --config=$PRJDIR/afb-evcc/etc/binding-simu15118-evcc.yaml \
    --config=$INFILE

# evse does not quit automatically
pkill afb-evse