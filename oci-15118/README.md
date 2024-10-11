# ISO15118 simulator OCI container

Provide a testing environment for ISO15118 simulator and other iso15118 related tools.

## Run test with oci from coming registry.redpesk.bzh

### configure your host

```bash
sudo client-server-bridge; # Create virtual network
mkcerts -i ./temp_cert ; # Create dev certificate
```

### first binder

```bash
podman run --rm --volume ./temp_cert:/tmp/temp_cert:z --name podman_evcc --network=host --cap-add=NET_ADMIN -it registry.redpesk.bzh/tux-evse/afb-iso15118_almalinux:0.1  bash -c "binding-start-evcc --pki_tls_sim_dir /tmp/temp_cert --scenario_file /usr/share/iso15118-simulator-rs/audi-dc-iso2-compact.json"
```

### second binder

```bash
podman run --rm --volume ./temp_cert:/tmp/temp_cert:z --name podman_evse --network=host --cap-add=NET_ADMIN -it registry.redpesk.bzh/tux-evse/afb-iso15118_almalinux:0.1  bash -c "binding-start-evse --pki_tls_sim_dir /tmp/temp_cert --scenario_file /usr/share/iso15118-simulator-rs/audi-dc-iso2-compact.json"
```

### open your devtools

```bash
  xdg-open http://localhost:1234/devtools/ ;#(Click on tesla-3-din:1:0 -> EXEC & SEND)
```

## Build oci for binder iso15118 simulator

### build a full almalinux oci

```bash
podman build -t afb-iso15118_almalinux -f Dockerfile_almalinux_bin
```

### build a shrunked almalinux oci

```bash
podman build -t afb-iso15118_almalinux_shrunked -f Dockerfile_almalinux_shrunked_bin
```

## Building from source

```bash
  podman build --no-cache -t afb-iso15118 -f Dockerfile_almalinux_source
```

Note: IoT.bzh mostly uses podman. Nevertheless the same command should work with docker.

## Send to git OCI registry

* request authentication token from: https://github.com/settings/tokens/new?scopes=write:packages
* within your bash env ```export CR_PAT=YOUR_TOKEN```
* echo $CR_PAT |podman/docker login ghcr.io -u USERNAME --password-stdin
* podman push localhost/afb-iso15118:latest ghcr.io/tux-evse/iso15118-simulator

## Pull/Run from git repository

```bash
cd /tmp
podman/docker pull ghcr.io/tux-evse/iso15118-simulator:latest
wget https://raw.githubusercontent.com/EVerest/logfiles/main/Audi/Q4/ac_iso2-1.dump
file ac_iso2-1.dump # should be tcpdump format
podman run -it  -v .:/pcap-logs:Z ghcr.io/tux-evse/iso15118-simulator pcap-iso15118 --pcap_in=/pcap-logs/ac_iso2-1.dump --json_out=/pcap-logs/ac_iso2-1.json
cat ac_iso2-1.json
```

### pcap-iso15118

```bash
ISO_PCAP_DIR="$HOME/Workspace/Tux-Evse/iso15118-simulator-rs/afb-test/trace-logs"
ISO_SCENARIO="abb-normal-din"

podman run -it  -v $ISO_PCAP_DIR:/pcap-logs:Z localhost/afb-iso15118 pcap-iso15118 --pcap_in=/pcap-logs/$ISO_SCENARIO.pcap --json_out=/pcap-logs/$ISO_SCENARIO.json --verbose=2
```

Note: you need to make your input file (--pcap_in) as well as your output file (--json_out) visible from your container with -v/volume option
