#!/bin/bash
if test -f /etc/default/iso15118-simulator.conf; then
   source /etc/default/iso15118-simulator.conf
fi

function usage {
    printf "Usage: \n\
        -h|--help \t displays this text\n
        -d|--debug \t run the script in debug mode\n\
        -i|--iface \t specify the network interface (default:\"evcc-veth\")\n\
        -c|--scenario_uid \t specify the scenario uid (default:\"evcc\")\n\
        -f|--scenario_file \t \n\
        -s|--simulation \t specify the simulator mode (default:\"injector\")\n\
        -p|--pki_tls_sim_dir \t specify *.pem files directory (_client_chain.pem,_client_key.pem,_contract_chain.pem,_contract_key.pem)\n\
        "
    exit
}
CONFDIR="/etc/default/"

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"

#----------------------------------------
DEBUG="NO"
export CARGO_BINDING_DIR="/usr/redpesk/iso15118-simulator-rs/lib"
export INJECTOR_BINDING_DIR="/usr/redpesk/injector-binding-rs/lib"

if test -z "$IFACE_SIMU"; then
export IFACE_SIMU="evcc-veth"
fi

if test -z "$SCENARIO_UID"; then
export SCENARIO_UID="evcc"
fi

if test -z "$SIMULATION_MODE"; then
export SIMULATION_MODE="injector"
fi

#----------------------------------------

while [[ $# -gt 0 ]];do
    key="$1"
    case $key in
        -d|--debug)
            DEBUG="YES";
            export CARGO_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
            export INJECTOR_BINDING_DIR="${CARGO_TARGET_DIR}/debug"
            CONFDIR=$(pwd)/etc
            ROOTDIR=$(pwd)/..
            export PKI_TLS_DIR="$ROOTDIR/afb-test/certs"
            shift 1;
        ;;
        -i|--iface)
            export IFACE_SIMU=$2;
            shift 2;
        ;;
        -c|--scenario_uid)
            export SCENARIO_UID=$2;
            shift 2;
        ;;
        -f|--scenario_file)
            export SCENARIO_FILE=$2;
            shift 2;
        ;;
        -s|--simulation)
            export SIMULATION_MODE=$2;
            shift 2;
        ;;
        -p|--pki_tls_sim_dir)
            export PKI_TLS_DIR=$2;
            shift 2;
        ;;
        -m|--simulation_conf)
            export SIMULATION_CONF=$2;
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

ip -6 addr show "${IFACE_SIMU}" | grep -i fe80 >/dev/null
if test $? -ne 0; then
    echo "Error: invalid ${IFACE_SIMU} (0xFE80 localink missing)"
    echo " check: client-server-bridge (./afb-test/network/client-server-bridge.sh) to create a fake evse/evcc network"
    exit 1
fi
clear
pwd

# kill any previous instance
pkill afb-evcc

if ! test -z "$PKI_TLS_DIR"; then
    if test -z "$SIMULATION_CONF"; then
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evcc.yaml"
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
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evcc-no-tls.yaml"
    fi
    echo "Warning: To active tls support, PKI_TLS_DIR must be define (-p|--pki_tls_sim_dir) $PKI_TLS_DIR"
fi

if ! test -z "$SIMULATION_CONF"; then
    if test ! -f "$SIMULATION_CONF"; then
        echo "Fail to open scenario:$SIMULATION_CONF"
        usage
    fi
else
    echo "Fail: The scenario conf file must be define ( -m|--simulation_conf) $SIMULATION_CONF"
    usage
fi

if ! test -z "$SCENARIO_FILE"; then
    if test ! -f "$SCENARIO_FILE"; then
        echo "Fail to open scenario:$SCENARIO_FILE"
        usage
    fi
else
    echo "Fail: The scenario  file must be define (-f|--scenario_file) $SCENARIO_FILE"
    usage
fi

# start binder with test config
afb-binder -v --name afb-evcc \
    --config="${SIMULATION_CONF}" \
    --config="${SCENARIO_FILE}"
