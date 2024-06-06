# ISO15118 simulator OCI container

Provide a testing environment for ISO15118 simulator and other iso15118 related tools.

## Building

```
  podman build --no-cache -t afb-iso15118 -f Dockerfile
```
Note: IoT.bzh mostly uses podman. Nevertheless the same command should work with docker.


## Running

### pcap-iso15118

```
ISO_PCAP_DIR="$HOME/Workspace/Tux-Evse/iso15118-simulator-rs/afb-test/trace-logs"
ISO_SCENARIO="abb-normal-din"

podman run -it  -v $ISO_PCAP_DIR:/pcap-logs:Z localhost/afb-iso15118 pcap-iso15118 --pcap_in=/pcap-logs/$ISO_SCENARIO.pcap --json_out=/pcap-logs/$ISO_SCENARIO.json --verbose=2
```
Note: you need to make your input file (--pcap_in) as well as your output file (--json_out) visible from your container with -v/volume option

