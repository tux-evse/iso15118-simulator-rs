
# ISO15118 Simulator provides JSON/Rest-Websocket APIs to simulate an EV/EVSE

Provide a JSON Afb-V4 api to ISO15118-encoders. Each ISO message is exposed a Afb-V4 RPCs. In EV mode the simulator start sending an SDP discovery multi-cast message in IPV6 to configured interface and establishes a TCP/TLS connection to start ISO dialogue.

 ![Tux, the Linux mascot](/Docs/images//images/simulator-iso15118-iso2.png)

## Dependencies

* https://github.com/tux-evse/iso15118-encoders-rs
* https://github.com/redpesk-common/afb-librust

## Compilation

```
    cargo build --features afbv4
```

## OCI container (podman/docker)
```
cd oci-15118
podman build -t afb-iso15118 -f Dockerfile
```

## Configuration

Configuration relies on standard binding/binder json/yaml config file. The config splits into three main part:

* Iso stack to load 15118-2, 15118-20, Din, SLAC, ...
* Network/TLS: defined the interface to use as well as TLS certificates
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
 * source: https://github.com/dspace-group/dsV2Gshark
 * binary Linux packages: https://download.redpesk.bzh/redpesk-lts/batz-2.0-update/sdk-third-party/ (dnf/zypper/apt install dsv2gshark)

Using NSS-KEY-LOG master key file to decrypt TLS with wireshark
```
wireshark iso15118-binding-rs/afb-test/trace-logs/hello2-tls-1.3.pcapng -o tls.keylog_file:iso15118-binding-rs/afb-test/trace-logs/hello2-tls-1.3.keylog
```

Using socat to check tls server config
```
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

You may generate your scenarios directly from pcap/pcapng tcpdump files. You may find few pcap sample into afb-test/trace-logs directory and many more from https://github.com/EVerest/logfiles.git where every '*.dump' file uses pcap/wireshark syntax.

Command line
```
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
FULUP: TBD
------------

evcc controller:489 let response = match exi_decode_from_stream

alligner avec le comportement evse
 - lecture du buffer
 - lecture du body
 - mise en jsonc