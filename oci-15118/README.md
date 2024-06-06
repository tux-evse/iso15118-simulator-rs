# ISO15118 simulator OCI container

Provide a testing environment for ISO15118 simulator and other iso15118 related tools.

## Building

```
  podman build --no-cache -t afb-iso15118 -f Dockerfile
```
Note: IoT.bzh mostly uses podman. Nevertheless the same command should work with docker.

## Send to git OCI registry

* request authentication token from: https://github.com/settings/tokens/new?scopes=write:packages
* within your bash env ```export CR_PAT=YOUR_TOKEN```
* echo $CR_PAT |podman/docker login ghcr.io -u USERNAME --password-stdin
* podman push localhost/afb-iso15118:latest ghcr.io/tux-evse/iso15118-simulator

## Pull/Run from git repository
* cd /tmp
* podman/docker pull ghcr.io/tux-evse/iso15118-simulator:latest
* wget https://raw.githubusercontent.com/EVerest/logfiles/main/Audi/Q4/ac_iso2-1.dump
* file ac_iso2-1.dump # should be tcpdump format
* podman run -it  -v .:/pcap-logs:Z ghcr.io/tux-evse/iso15118-simulator pcap-iso15118 --pcap_in=/pcap-logs/ac_iso2-1.dump --json_out=/pcap-logs/ac_iso2-1.json
* cat ac_iso2-1.json


### pcap-iso15118

```
ISO_PCAP_DIR="$HOME/Workspace/Tux-Evse/iso15118-simulator-rs/afb-test/trace-logs"
ISO_SCENARIO="abb-normal-din"

podman run -it  -v $ISO_PCAP_DIR:/pcap-logs:Z localhost/afb-iso15118 pcap-iso15118 --pcap_in=/pcap-logs/$ISO_SCENARIO.pcap --json_out=/pcap-logs/$ISO_SCENARIO.json --verbose=2
```
Note: you need to make your input file (--pcap_in) as well as your output file (--json_out) visible from your container with -v/volume option

