#!/bin/bash

RED='\e[0;31m'
LGRAY="\e[37m"
LGREEN="\e[32m"
LBLEU="\e[94m"
NC='\e[0m'

BOLD="\e[1m"
NB="\e[0m"

FLASH="\e[5m"
NF="\e[0m"

print_Warning() {
  echo -e "${LGRAY}${BOLD}WARNING${NB}${NC}: $1\e[0m"
}

print_Failed() {
  echo -e "${RED}${BOLD}${FLASH}FAILED${NF}${NB}${NC}: $1\e[0m"
}

print_Failed_parameter() {
  print_Failed "No parameter for $1"
  exit 1
}


function usage {
    printf "Usage: \n\
        -h|--help \t displays this text\n\
        -d|--debug \t run the script in debug mode\n\
        -f|--scenario_file \t mandatory(default:\"${LBLEU}${CONFDIR}/audi-dc-iso2-compact.json${NC}\")\n\
        -m|--simulation_conf \t specify the simulator conf \n\
                \t\t\t(default:\"${CONFDIR}/binding-simu15118-evcc.yaml\" if ${LBLEU}tls${NC} support\n\
                \t\t\t or     :\"${CONFDIR}/binding-simu15118-evcc-no-tls.yaml\" if ${LBLEU}no tls${NC} support\n\
                \t\t\t or from env var ${LBLEU}SIMULATION_CONF${NC})\n\
        -p|--pki_tls_sim_dir \t specify *.pem files directory (_client_chain.pem,_client_key.pem,_contract_chain.pem,_contract_key.pem)\n\
        "
    exit
}

CONFDIR="/usr/share/iso15118-simulator-rs/"
#----------------------------------------
DEBUG="NO"

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"

if test -z "$CARGO_BINDING_DIR"; then
export CARGO_BINDING_DIR="/usr/redpesk/iso15118-simulator-rs/lib"
fi

if test -z "$INJECTOR_BINDING_DIR"; then
export INJECTOR_BINDING_DIR="/usr/redpesk/injector-binding-rs/lib"
fi


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
            if [ -z "${INFILE}" ]; then
                print_Failed_parameter  "-f|--scenario_file"
            fi;
        ;;
        -p|--pki_tls_sim_dir)
            export PKI_TLS_DIR=$2;
            shift 2;
            if [ -z "${PKI_TLS_DIR}" ]; then
                print_Failed_parameter  "-p|--pki_tls_sim_dir"
            fi;
        ;;
        -m|--simulation_conf)
            export SIMULATION_CONF=$2;
            shift 2;
            if [ -z "${SIMULATION_CONF}" ]; then
                print_Failed_parameter  "-m|--simulation_conf"
            fi;
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
    print_Failed "No scenario"
    exit 1;
fi

if test ! -f "$INFILE"; then
    print_Failed "to open scenario:$INFILE"
    exit 1;
fi
#----------------------------------------

export SCENARIO_UID=`basename $INFILE .json`

CONFDIR="/usr/share/iso15118-simulator-rs/"

ip -6 addr show "$IFACE_SIMU" | grep -i fe80 >/dev/null
if test $? -ne 0; then
    print_Failed "invalid ${IFACE_SIMU} (0xFE80 localink missing)"
    echo " check: client-server-bridge to create a fake evse/evcc network"
fi

if ! test -z "$PKI_TLS_DIR"; then
    if test -z "$SIMULATION_CONF"; then
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evse.yaml"
    fi
    if test ! -f "${PKI_TLS_DIR}/_client_chain.pem"; then
        print_Failed "to open pem file:${PKI_TLS_DIR}/_client_chain.pem"
        usage
    fi
    if test ! -f "${PKI_TLS_DIR}/_client_key.pem"; then
        print_Failed "to open pem file:${PKI_TLS_DIR}/_client_key.pem"
        usage
    fi
    if test ! -f "${PKI_TLS_DIR}/_contract_chain.pem"; then
        print_Failed "to open pem file:${PKI_TLS_DIR}/_contract_chain.pem"
        usage
    fi
    if test ! -f "${PKI_TLS_DIR}/_contract_key.pem"; then
        print_Failed "to open pem file:${PKI_TLS_DIR}/_contract_key.pem"
        usage
    fi
else
    if test -z "$SIMULATION_CONF"; then
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evse-no-tls.yaml"
    fi
    print_Warning "To active tls support, PKI_TLS_DIR must be define (-p|--pki_tls_sim_dir) $PKI_TLS_DIR"
fi

clear
pwd

# kill any previous instance
pkill afb-evse

echo afb-binder -v --name=afb-evse \
    --config="${SIMULATION_CONF}" \
    --config="${INFILE}"

# start binder with test config
afb-binder -v --name=afb-evse \
    --config="${SIMULATION_CONF}" \
    --config="${INFILE}"
