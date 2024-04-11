#!/bin/bash

cd $(dirname $0)/..
CONFDIR=`pwd`/etc

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
clear
pwd
export BINDING=libafb_iso15118_2.so
if ! test -f $CARGO_TARGET_DIR/debug/$BINDING; then
    echo "FATAL: missing $CARGO_TARGET_DIR/debug/$BINDING use: cargo build"
    exit 1
fi

# start binder with test config
afb-binder -v \
   --config=$CONFDIR/binding-iso2.yaml \
   $*
