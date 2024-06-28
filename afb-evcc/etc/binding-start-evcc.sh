#!/bin/bash

cd $(dirname $0)/..
CONFDIR=`pwd`/etc
ROOTDIR=`pwd`/..

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
export CARGO_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
export IFACE_SIMU=lo
export PKI_TLS_DIR="$ROOTDIR/afb-test/certs"
export SIMULATION_MODE="injector"


clear
pwd

# start binder with test config
afb-binder -v \
    --config=$CONFDIR/binding-simu15118-evcc.yaml \
    --config=$ROOTDIR/afb-test/etc/audi-dc-iso2.json \
   $*
