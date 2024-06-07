#!/bin/bash

cd $(dirname $0)/..
CONFDIR=`pwd`/etc

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
clear
pwd
export CARGO_BINDING_DIR=$CARGO_TARGET_DIR/debug
export BINDING=libafb_iso15118.so
if ! test -f $CARGO_TARGET_DIR/debug/$BINDING; then
    echo "FATAL: missing $CARGO_TARGET_DIR/debug/$BINDING use: cargo build"
    exit 1
fi

# start binder with test config
afb-binder -v \
   --config=$CONFDIR/binding-iso15118.yaml \
   --config=$CONFDIR/audi-dc-iso2.json \
   $*
