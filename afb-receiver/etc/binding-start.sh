#!/bin/bash

cd $(dirname $0)/..
CONFDIR=`pwd`/etc
ROOTDIR=`pwd`/..

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"
clear
pwd

for BINDING in libafb_iso15118.so
do
    if ! test -f $CARGO_TARGET_DIR/debug/$BINDING; then
        echo "FATAL: missing $CARGO_TARGET_DIR/debug/$BINDING use: cargo build"
        exit 1
    fi
done

# start binder with test config
afb-binder -v \
   --config=$CONFDIR/binding-iso15118.yaml \
   $*
