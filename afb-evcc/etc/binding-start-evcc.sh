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

cd $(dirname $0)/..
CONFDIR=`pwd`/etc
ROOTDIR=`pwd`/..

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
export CARGO_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
export IFACE_SIMU=evcc-veth
export PKI_TLS_DIR="$ROOTDIR/afb-test/certs"
export SIMULATION_MODE="injector"

ip -6 addr show $IFACE_SIMU | grep -i fe80 >/dev/null
if test $? -ne 0; then
    echo "Error: invalid $IFACE_SIMU (0xFE80 localink missing)"
    echo " check: ./afb-test/network/client-server-bridge.sh to create a fake evse/evcc network"
fi

clear
pwd

# kill any previous instance
pkill afb-evcc

# start binder with test config
afb-binder -v --name afb-evcc \
    --config=$CONFDIR/binding-simu15118-evcc.yaml \
    --config=$INFILE
