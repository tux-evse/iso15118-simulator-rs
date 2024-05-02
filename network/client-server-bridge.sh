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

echo "Wireguard config to tap codico/eth2 device from target to development desktop"
echo ---
if test $UID != 0; then
    echo "(hoops) this command requires admin privileges (use sudo)"
    exit 1
fi

mkdir -p $HOME/wg-tap-pki
cd $HOME/wg-tap-pki

echo -- clean previous config
 ip link delete br0-tun 2> /dev/null

echo "-- configure bridge "
  ip link add name br0-tun type bridge
  ip link set dev br0-tun up

echo "-- create a virtual interface for iso-binding/simulator listen"
  ip link add simu-veth type veth peer name simu-private;
  ip link set simu-private up;
  ip link set simu-veth up;
  ip link set simu-private master br0-tun;

  ip link add evse-veth type veth peer name evse-private;
  ip link set evse-private up;
  ip link set evse-veth up;
  ip link set evse-private master br0-tun;


echo "-- display 'br0-tun' bridge config"
  ip link show master br0-tun


