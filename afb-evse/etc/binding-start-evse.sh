#!/bin/bash

cd $(dirname $0)/..
CONFDIR=`pwd`/etc
ROOTDIR=`pwd`/..

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
export CARGO_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
export IFACE_SIMU=evse-veth
export PKI_TLS_DIR="$ROOTDIR/afb-test/certs"
export SIMULATION_MODE="responder"

ip -6 addr show $IFACE_SIMU | grep -i fe80 >/dev/null
if test $? -ne 0; then
    echo "Error: invalid $IFACE_SIMU (0xFE80 localink missing)"
    echo " check: ./afb-test/network/client-server-bridge.sh to create a fake evse/evcc network"
fi

clear
pwd

# start binder with test config
afb-binder -v --name=afb-evse \
    --config=$CONFDIR/binding-simu15118-evse.yaml \
    --config=$ROOTDIR/afb-test/etc/small-dc-iso2.json \
   $*
