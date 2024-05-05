
# ISO15118 Simulator provides JSON/Rest-Websocket APIs to simulate an EV/EVSE

Provide a JSON Afb-V4 api to ISO15118-encoders. Each ISO message is exposed a Afb-V4 RPCs. In EV mode the simulator start sending an SDP discovery multi-cast message in IPV6 to configured interface and establishes a TCP/TLS connection to start ISO dialogue.


## Dependencies

* https://github.com/tux-evse/iso15118-encoders-rs
* https://github.com/redpesk-common/afb-librust

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

**TLS configuration** optional pin is private key's password. PSK_LOG a user defined filepath for Wireshark pre-shared-key. PSK allows to introspect crypt TLS communication from wireshark UI as if it was a clear text TCP channel.

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


## Current development status

This module is under deep development. Initial version supports ISO-2, the other stacks (Iso-20, Din) will come as soon as iso15118-encoder-rs implements them.

## Usage

The simulator might be used in standalone mode to in conjunction with injector-binding-rs to automate testing scenarios.

## Test

```bash
cargo test --package iso15118-2 --lib -- encoders_test --show-output
```

