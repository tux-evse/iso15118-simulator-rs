#!/bin/bash
if test -f /usr/share/iso15118-simulator-rs/iso15118-simulator.conf; then
   source /usr/share/iso15118-simulator-rs/iso15118-simulator.conf
fi

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
        -d|--debug \t run the script in local+debug mode\n\
        -f|--scenario_file \t mandatory(default:\"${LBLEU}${CONFDIR}/audi-dc-iso2-compact.json${NC}\")\n\
        -i|--iface \t specify the network interface (default:\"${LBLEU}evcc-veth${NC}\" or from env var ${LBLEU}IFACE_SIMU${NC})\n\
        -c|--scenario_uid \t specify the scenario uid (default:\"${LBLEU}evcc${NC}\" or from env var ${LBLEU}SCENARIO_UID${NC})\n\
        -s|--simulation \t specify the simulator mode (default:\"${LBLEU}injector${NC}\" or from env var ${LBLEU}SIMULATION_MODE${NC})\n\
        -m|--simulation_conf \t specify the simulator conf \n\
                \t\t\t(default:\"${CONFDIR}/binding-simu15118-evcc.yaml\" if ${LBLEU}tls${NC} support\n\
                \t\t\t or     :\"${CONFDIR}/binding-simu15118-evcc-no-tls.yaml\" if ${LBLEU}no tls${NC} support\n\
                \t\t\t or from env var ${LBLEU}SIMULATION_CONF${NC})\n\
        -p|--pki_tls_sim_dir \t specify *.pem files directory (_client_chain.pem,_client_key.pem,_contract_chain.pem,_contract_key.pem)\n\
        -n|--no-clean \t do not clean the terminal\n\
"
    exit
}
CONFDIR="/usr/share/iso15118-simulator-rs/"

# use libafb development version if any
export LD_LIBRARY_PATH="/usr/local/lib64:$LD_LIBRARY_PATH"
export PATH="/usr/local/lib64:$PATH"

#----------------------------------------
DEBUG="NO"
NO_CLEAN=false

if test -z "$CARGO_BINDING_DIR"; then
export CARGO_BINDING_DIR="/usr/redpesk/iso15118-simulator-rs/lib"
fi

if test -z "$INJECTOR_BINDING_DIR"; then
export INJECTOR_BINDING_DIR="/usr/redpesk/injector-binding-rs/lib"
fi

if test -z "$IFACE_SIMU"; then
export IFACE_SIMU="evcc-veth"
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
            CONFDIR=$(pwd)/afb-evcc/etc
            ROOTDIR=$(pwd)/..
            shift 1;
        ;;
        -i|--iface)
            export IFACE_SIMU=$2;
            shift 2;
            if [ -z "${IFACE_SIMU}" ]; then
                print_Failed_parameter  "-i|--iface"
            fi;
        ;;
        -c|--scenario_uid)
            export SCENARIO_UID=$2;
            shift 2;
            if [ -z "${SCENARIO_UID}" ]; then
                print_Failed_parameter  "-c|--scenario_uid"
            fi;
        ;;
        -f|--scenario_file)
            export SCENARIO_FILE=$2;
            shift 2;
            if [ -z "${SCENARIO_FILE}" ]; then
                print_Failed_parameter  "-f|--scenario_file"
            fi;
        ;;
        -s|--simulation)
            export SIMULATION_MODE=$2;
            shift 2;
            if [ -z "${SIMULATION_MODE}" ]; then
                print_Failed_parameter  "-s|--simulation"
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
        -n|--no-clean)
            NO_CLEAN=true
            shift 1;
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
    print_Failed "invalid ${IFACE_SIMU} (0xFE80 localink missing)"
    echo "check: client-server-bridge (client-server-bridge) to create a fake evse/evcc network"
    exit 1
fi

if [ "${NO_CLEAN}" == false ]; then
    clear
    pwd
    # kill any previous instance
    pkill afb-evcc
fi

if ! test -z "$PKI_TLS_DIR"; then
    if test -z "$SIMULATION_CONF"; then
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evcc.yaml"
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
        export SIMULATION_CONF="${CONFDIR}/binding-simu15118-evcc-no-tls.yaml"
    fi
    print_Warning "To active tls support, PKI_TLS_DIR must be defined (-p|--pki_tls_sim_dir) $PKI_TLS_DIR"
fi

if ! test -z "$SIMULATION_CONF"; then
    if test ! -f "$SIMULATION_CONF"; then
        print_Failed "to open scenario:$SIMULATION_CONF"
        usage
    fi
else
    print_Failed "The scenario conf file must be defined ( -m|--simulation_conf) $SIMULATION_CONF"
    usage
fi

if ! test -z "$SCENARIO_FILE"; then
    if test ! -f "$SCENARIO_FILE"; then
        print_Failed "to open scenario:$SCENARIO_FILE"
        usage
    fi
else
    print_Failed "The scenario  file must be defined (-f|--scenario_file) $SCENARIO_FILE"
    usage
fi

echo afb-binder -v --name afb-evcc \
    --config="${SIMULATION_CONF}" \
    --config="${SCENARIO_FILE}"

# start binder with test config
afb-binder -v --name afb-evcc \
    --config="${SIMULATION_CONF}" \
    --config="${SCENARIO_FILE}"
