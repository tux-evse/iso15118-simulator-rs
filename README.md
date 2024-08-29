
# ISO15118 Simulator provides JSON/Rest-Websocket APIs to simulate an EV/EVSE

Provide a JSON Afb-V4 api to ISO15118-encoders. Each ISO message is exposed a Afb-V4 RPCs. In EV mode the simulator start sending an SDP discovery multi-cast message in IPV6 to configured interface and establishes a TCP/TLS connection to start ISO dialogue.

 ![simulator-screencast](./Docs/images/simulator-iso15118-iso2.png)

## Dependencies

* https://github.com/tux-evse/iso15118-encoders-rs
* https://github.com/redpesk-common/afb-librust

## Compilation

```
    cargo build --features afbv4
```

## Binary prebuild package.

Binary packages are available for Fedora/OpenSuSE/Ubuntu stable and previous-stable versions.

```
wget https://raw.githubusercontent.com/redpesk-devtools/redpesk-sdk-tools/master/install-redpesk-sdk.sh
sh install-redpesk-sdk.sh --no-recommends
dnf/zypper/apt install iso15118-simulator-rs
```

To upload manually binary packages from repository check: https://download.redpesk.bzh/redpesk-lts/batz-2.0-update/sdk-third-party/


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

## Scenarios files

Creating scenario manually from scratch is long and boring, we recommend to generate scenarios template directly from existing pcap/pcapng tcpdump capture files. You may find few pcap sample into afb-test/trace-logs directory and many more from https://github.com/EVerest/logfiles.git where every '*.dump' file uses pcap/wireshark syntax.

Command line
```
/pcap-iso15118  --pcap_in=./afb-test/trace-logs/audi-dc-iso2.pcap --json_out=./afb-test/trace-logs/_audi-dc-iso2.json
```

options:
* --compact=true group identical sequential request+query into one single request (ex: cable-check) and wait for final expected response.
* --minimal=true identical to --compact except that the injector only check 'response status' and not the other value of the response.
* --key_log=/xxx/master-key this mode allow to decrypt TLS-1.3 crypted tcpdump capture. masterkey file should follow [NSS-KEY_LOG format](https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html)

Output file
```jsonc
{
"uid":"iso15118-simulator",
"info":"./afb-test/trace-logs/audi-dc-iso2.pcap",
"api":"iso15118-${SIMULATION_MODE}",
"path":"${CARGO_BINDING_DIR}/libafb_injector.so",
"simulation":"${SIMULATION_MODE}",
"target":"iso15118-simulator",
"autorun":0,
"delay":{
"percent":10,
"min":50,
"max":100
},
"compact":true,
"scenarios":[
{
    "uid":"audi-dc-iso2:1",
    "timeout":748,
    "transactions":[
    {
        "uid":"sdp-evse",
        "verb":"iso2:sdp_evse_req",
        "injector_only":true,
        "query":{
        "action":"discover"
        },
        "retry":{
        "timeout":3000,
        "delay":100,
        "count":1
        }
    },
    {
        "uid":"app-set-protocol",
        "verb":"iso2:app_proto_req",
        "injector_only":true,
        "retry":{
        "timeout":3000,
        "delay":100,
        "count":1
        }
    },
    {
        "uid":"pkg:51",
        "verb":"iso2:session_setup_req",
        "delay":56,
        "query":{
        "id":"[00,7d,fa,07,5e,4a]",
        "tagid":"session_setup_req",
        "proto":"iso2",
        "msgid":0
        },
        "expect":{
        "id":"DE*PNX*E12345*1",
        "rcode":"new_session",
        "tagid":"session_setup_res",
        "proto":"iso2",
        "msgid":1
        },
        "retry":{
        "timeout":3000,
        "delay":56,
        "count":1
        }
    }
}]}
```

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
