#!/bin/bash

function usage {
    printf "Usage: \n\
        -h|--help \t displays this text\n\
        -d|--debug \t run the script in debug mode\n\
        -f|--scenario_file path \t \n\
        -p|--pki_tls_sim_dir \t specify *.pem files directory (_client_chain.pem,_client_key.pem,_contract_chain.pem,_contract_key.pem)\n\
        "
    exit
}
#----------------------------------------
DEBUG="NO"

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"

export CARGO_BINDING_DIR="/usr/redpesk/iso15118-simulator-rs/lib"
export INJECTOR_BINDING_DIR="/usr/redpesk/injector-binding-rs/lib"

export IFACE_SIMU=evse-veth
export SIMULATION_MODE="responder"
export SCENARIO_UID="evse"

#----------------------------------------

while [[ $# -gt 0 ]];do
    key="$1"
    case $key in
        -d|--debug)
            DEBUG="YES";
            export CARGO_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
            export INJECTOR_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
            CONFDIR=`pwd`/etc
            ROOTDIR=`pwd`/..
            shift 1;
        ;;
        -f|--scenario_file)
            export INFILE=$2;
            shift 2;
        ;;
        -p|--pki_tls_sim_dir)
            export PKI_TLS_DIR=$2;
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

#----------------------------------------
if test -z "$INFILE"; then
    echo "Error: No scenario"
    usage;
fi

if test ! -f "$INFILE"; then
    echo "Fail to open scenario:$INFILE"
    usage;
fi
#----------------------------------------

export SCENARIO_UID=`basename $INFILE .json`

CONFDIR="/etc/default/"

ip -6 addr show "$IFACE_SIMU" | grep -i fe80 >/dev/null
if test $? -ne 0; then
    echo "Error: invalid ${IFACE_SIMU} (0xFE80 localink missing)"
    echo " check: ./afb-test/network/client-server-bridge.sh to create a fake evse/evcc network"
fi

if ! test -z "$PKI_TLS_DIR"; then
    if test -z "$SIMULATION_CONF"; then
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evse.yaml"
    fi
    if test ! -f "${PKI_TLS_DIR}/_client_chain.pem"; then
        echo "Fail to open pem file:${PKI_TLS_DIR}/_client_chain.pem"
        usage
    fi
    if test ! -f "${PKI_TLS_DIR}/_client_key.pem"; then
        echo "Fail to open pem file:${PKI_TLS_DIR}/_client_key.pem"
        usage
    fi
    if test ! -f "${PKI_TLS_DIR}/_contract_chain.pem"; then
        echo "Fail to open pem file:${PKI_TLS_DIR}/_contract_chain.pem"
        usage
    fi
    if test ! -f "${PKI_TLS_DIR}/_contract_key.pem"; then
        echo "Fail to open pem file:${PKI_TLS_DIR}/_contract_key.pem"
        usage
    fi
else
    if test -z "$SIMULATION_CONF"; then
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evse-no-tls.yaml"
    fi
    echo "Warning: To active tls support, PKI_TLS_DIR must be define (-p|--pki_tls_sim_dir) $PKI_TLS_DIR"
fi

clear
pwd

# kill any previous instance
pkill afb-evse

# start binder with test config
afb-binder -v --name=afb-evse \
    --config="${SIMULATION_CONF}" \
    --config="${INFILE}"
