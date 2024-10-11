#!/bin/sh

# Small script to tap eth2/codico interface and send layer2 paquet to a development desktop
# This allow to debug from native development environement SLAC and ISO15118 protocol
# -----------------------------------------------------------------------------------
# references:
# https://gist.github.com/zOrg1331/a2a7ffb3cfe3b3b821d45d6af00cb8f6
# https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/9/html/configuring_and_managing_networking/configuring-a-gretap-tunnel-to-transfer-ethernet-frames-over-ipv4_configuring-ip-tunnels
#

export WG_PORT=51820
export SLAC_IFACE=eth2
export FWALL_ZONE=work


set -x

echo "Fake evcc/evse network config for development desktop"
echo ---
if test "$(id -u)" != 0; then
    echo "(hoops) this command requires admin privileges (use sudo)"
    exit 1
fi

echo -- clean previous config
 ip link delete evse-tun 2> /dev/null
 ip link delete evse-veth 2> /dev/null
 ip link delete evcc-veth 2> /dev/null

echo "-- configure bridge "
  ip link add name evse-tun type bridge
  ip link set dev evse-tun up
  ip addr add 10.1.1.10/24 dev evse-tun

echo "-- create a virtual interface for iso-binding/simulator listen"
  ip link add evse-veth type veth peer name evse-link;
  ip link set evse-link up;
  ip link set evse-veth up;
  ip link set evse-link master evse-tun;

  ip link add evcc-veth type veth peer name evcc-link;
  ip link set evcc-link up;
  ip link set evcc-veth up;
  ip link set evcc-link master evse-tun;
#  ip addr add 10.1.1.1/24 dev evcc-veth


echo "-- display 'evse-tun' bridge config"
  ip link show master evse-tun


