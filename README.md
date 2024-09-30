
# ISO15118 Simulator provides JSON/Rest-Websocket APIs to simulate an EV/EVSE

Provide a JSON Afb-V4 api to ISO15118-encoders. Each ISO message is exposed a Afb-V4 RPCs. In EV mode the simulator start sending an SDP discovery multi-cast message in IPV6 to configured interface and establishes a TCP/TLS connection to start ISO dialogue.

 ![simulator-screencast](./Docs/images/simulator-iso15118-iso2.png)

## Quick video introduction to Tux-Evse Open Source iso15118-simulator

<https://player.vimeo.com/video/1004557448>

## Binary packages

Binary packages are available for Fedora/OpenSuSE/Ubuntu stable and previous-stable versions. *Expect for Cargo+Cmake expert compiling the iso15118-simulator is not as simple as it should. The simulator+dependencies contains 40000 lines of Rust and has multiple C dependencies that recursively pull new dependencies.*

For quick start it is recommended to also install on top of iso15118-simulator-rs:

* iso15118-simulator-rs-test: contains some sample config & scenario
* dsv2gshark: wireshark iso15118 plugin

```bash
wget https://raw.githubusercontent.com/redpesk-devtools/redpesk-sdk-tools/master/install-redpesk-sdk.sh
sh install-redpesk-sdk.sh --no-recommends
sudo dnf/zypper/apt install iso15118-simulator-rs
sudo dnf/zypper/apt install iso15118-simulator-rs-test
sudo dnf/zypper/apt install dsv2gshark
```

After declaring redpesk-sdk repositories, you should see iso15118 package from your preferred package management tool.
![simulator-binary-packages](./Docs/images/redpesk-iso15118-rpm.png)

Note: For manual binary packages directly from repository check: <https://download.redpesk.bzh/redpesk-lts/batz-2.0-update/sdk-third-party/>

## Network configuration

To run the simulator **binding-start-evcc** you need some network interfaces

```bash
ip link show evse-tun // a bridge
ip link show evse-veth
ip link show evcc-veth
```

A script can help you to configure the network interfaces.

```bash
sudo client-server-bridge
```

Note: **binding-start-evcc** has an option to overwrite the **evcc-veth** value

```bash
binding-start-evcc --help
...
-i|--iface       specify the network interface (default:"evcc-veth")
...
```

## GnuTLS certificate configuration

To run the simulator **binding-start-evcc** you need some GnuTLS certificate.

A script can help you to configure the GnuTLS certificate.

```bash
mkcerts -i ./temp
```

## Run EVCC(vehicle) simulator after package installation

Now, select a scenario and run the simulator:

```bash
binding-start-evcc --pki_tls_sim_dir ./temp/ --scenario_file /etc/default/tesla-3-din.json
```

You can use a prebuild configuration without tls/pki:

```bash
binding-start-evcc --simulation_conf /etc/default/binding-simu15118-evcc-no-tls.yaml --scenario_file /etc/default/tesla-3-din.json
```

## Run EVSE(charger) simulator after package installation

Now, select a scenario and run the responder:

```bash
binding-start-evse --pki_tls_sim_dir ./temp/ --scenario_file  /etc/default/tesla-3-din.json
```

You can use a prebuild configuration without tls/pki:

```bash
binding-start-evse --simulation_conf /etc/default/binding-simu15118-evse-no-tls.yaml --scenario_file /etc/default/tesla-3-din.json
```

## Quick run (simulating both EVSE+EVCC)

```bash
sudo client-server-bridge # Create virtual network
mkcerts -i ./temp # Create dev certificate
binding-start-evcc --pki_tls_sim_dir ./temp/ --scenario_file /etc/default/tesla-3-din.json # Start vehicle simulation(injector)
binding-start-evse --pki_tls_sim_dir ./temp/ --scenario_file  /etc/default/tesla-3-din.json # Start charger simulator(responder)
xdg-open http://localhost:1234/devtools/ #(Clic on tesla-3-din:1:0 -> EXEC & SEND)
```

## Open the devtools

You can open the simulator devtools interface with:

```bash
xdg-open http://localhost:1234/devtools/
```

You can open the responder devtools interface with:

```bash
xdg-open http://localhost:1235/devtools/
```

## Dependencies

* <https://github.com/tux-evse/iso15118-encoders-rs>
* <https://github.com/redpesk-common/afb-librust>

## Compilation

```bash
    cargo build --features afbv4
```

## OCI container (podman/docker)

```bash
cd oci-15118
podman build -t afb-iso15118 -f Dockerfile
```

## Configuration

Configuration relies on standard binding/binder json/yaml config file. The config splits into three main part:

* Iso stack to load 15118-2, 15118-20, Din, SLAC, ...
* Network/TLS: defined the interface to use as well as TLS certificates.
* Verbs: defines which ISO message should be exposed.

**Interface to service discovery** prefix allows to select the interface IPV6  to be used. 0xFE80 is the default for ipv6 local-link.

```yaml
iface: ${IFACE_SIMU}   # default lo
ip6_prefix:  0         # default 0xFE80
sdp_port:    15118     # default 15118
```

**TLS configuration** optional pin is private key's password. psklog_in a user defined filepath for Wireshark pre-shared-key. PSK allows to introspect crypt TLS communication from wireshark UI as if it was a clear text TCP channel.

```yaml
    trust: ${PKI_TLS_DIR}/_trialog/
    certs: ${PKI_TLS_DIR}/_trialog/secc-chain.pem
    key: ${PKI_TLS_DIR}/_trialog/secc20Cert.key
    pin: 123456
    proto: SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-ARCFOUR-128:+PSK:+DHE-PSK
    psk_log: /tmp/tls-keys-simu.log
```

**Api Json/Yaml** input query as well as response use JSOn, but configuration on top of JSON also accept YAML.

* iso15118-2 Requests
  * [json](iso15118-2/docs/api-req.json)
  * [yaml](iso15118-2/docs/api-req.yaml)
* iso15118-2 Responses
  * [json](iso15118-2/docs/api-res.json)
  * [yaml](iso15118-2/docs/api-res.yaml)

## Debug

To introspect iso15118  trace use dsv2shark wireshark plugin with nss-key-log master keys.

Plugin:

* source: <https://github.com/dspace-group/dsV2Gshark>
* binary Linux packages: dnf/zypper/apt install dsv2gshark

Using NSS-KEY-LOG master key file to decrypt TLS with wireshark

```bash
wireshark iso15118-binding-rs/afb-test/trace-logs/hello2-tls-1.3.pcapng -o tls.keylog_file:iso15118-binding-rs/afb-test/trace-logs/hello2-tls-1.3.keylog
```

Using socat to check tls server config

```bash
socat -6 "OPENSSL-CONNECT:[fe80::ac52:27ff:fef3:d0d7%evcc-veth]:64109,snihost=xxx,verify=0" stdio
```

## Current development status

This module is under deep development. Initial version supports ISO-2, the other stacks (Iso-20, Din) will come as soon as iso15118-encoder-rs implements them.

## Usage

The simulator might be used in standalone mode to in conjunction with injector-binding-rs to automate testing scenarios.

## Test

```bash
cargo test --package iso15118-2 --lib -- encoders_test --show-output
```

## Scenarios files

You may generate your scenarios directly from pcap/pcapng tcpdump files. You may find few pcap sample into afb-test/trace-logs directory and many more from <https://github.com/EVerest/logfiles.git> where every '*.dump' file uses pcap/wireshark syntax.

Command line

```bash
iso15118 --pcap_in=./afb-test/trace-logs/abb-normal-din.pcap --log_path=/tmp/iso15118-scenario.json
```

Output file

```jsonc
{
  "uid":"./afb-test/trace-logs/abb-normal-din.pcap",
  "info":"/tmp/iso15118-scenario.json",
  "api":"pcap-simu",
  "path":"${CARGO_TARGET_DIR}debug/libafb_iso15118_simulator.so",
  "scenarios":[
    {
      "uid":"scenario-1",
      "target":"iso15118-din",
      "transactions":[
        {
          "uid":"pkg:42",
          "verb":"session_setup_req",
          "delay":16,
          "query":{
            "id":"[02,01,02,03,04,02]",
            "tagid":"session_setup_req"
          },
          "expect":{
            "id":"[00]",
            "rcode":"ok",
            "stamp":0,
            "tagid":"session_setup_res"
          }
        },
        {
          "uid":"pkg:46",
          "verb":"service_discovery_req",
          "delay":12,
          "query":{
            "category":"ev_charger",
            "tagid":"service_discovery_req"
          },
          "expect":{
            "rcode":"ok",
            "charging":{
              "tag":{
                "id":1,
                "category":"ev_charger"
              },
              "transfer":"dc_extended",
              "isfree":false
            },
            "payments":[
              "external"
            ],
            "tagid":"service_discovery_res"
          }
        },
      ],
    }
  ]
}
```
