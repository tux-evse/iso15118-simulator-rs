# syntax=docker/dockerfile:1.2
# podman build -t afb-iso15118 -f Dockerfile
# podman run -it  -v $ISO_PCAP_DIR:/trace-logs:Z localhost/afb-iso15118 pcap-iso15118 --help

# STAGE 1: build the executable
FROM almalinux/9-minimal AS builder
RUN microdnf --enablerepo=crb --nodocs -y install git vim gcc cmake make json-c-devel libyaml-devel libmicrohttpd-devel gnutls-devel wget cpio

ENV LD_LIBRARY_PATH=/usr/local/lib64:/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig
ENV PATH=/usr/local/bin:$PATH
WORKDIR /src

RUN <<EOF
    # clone afb source repositories
    git clone https://github.com/redpesk-core/afb-binding &&
    git clone https://github.com/redpesk-core/afb-libafb  &&
    git clone https://github.com/redpesk-core/afb-binder  &&
    git clone https://github.com/redpesk-core/rp-lib-utils &&

    # build afb-binder + dependencies
    (mkdir -p afb-binding/build && cd afb-binding/build && cmake .. && make -j install) &&
    (mkdir -p rp-lib-utils/build && cd rp-lib-utils/build && cmake .. && make -j install) &&
    (mkdir -p afb-libafb/build && cd afb-libafb/build && cmake -DWITH_SYSTEMD=0 -DWITH_LIBUUID=0 \
       -DWITHOUT_CYNAGORA=1 -DWITHOUT_TESTS=1 -DWITH_LIBMAGIC=0  -DWITH_FNMATCH=0 \
       -DWITH_SIG_MONITOR_DUMPSTACK=0 .. && make -j install) &&
    (mkdir -p afb-binder/build && cd afb-binder/build && cmake .. && make -j install) &&

    # extract devtools from no-archRPM
    rpm -i --badreloc --relocate /usr=/usr/local --nodeps https://download.redpesk.bzh/redpesk-lts/batz-2.0-update/packages/middleware/x86_64/os/Packages/a/afb-ui-devtools-1.0.4-2.redpesk.devtools.rpbatz.noarch.rpm
EOF

# install tux-evse rust building dependencies and compiling afbv4 RUST lib
ENV PROFILE "release"
ENV CARGO_TARGET_DIR "/var/cargo"
ENV RUSTFLAGS "-L/var/cargo/release -Adead_code -Aunused_imports"
ENV PS1="afb-iso15118> "

RUN <<EOF
  microdnf --enablerepo=crb --nodocs -y install cargo gnutls-devel nettle-devel clang clang-devel &&
  git clone https://github.com/redpesk-common/afb-librust &&
  (cd afb-librust; cargo build --release)

EOF

RUN <<EOF
    git clone https://github.com/tux-evse/iso15118-encoders &&
    git clone https://github.com/tux-evse/iso15118-network-rs &&
    git clone https://github.com/tux-evse/iso15118-encoders-rs &&
    git clone https://github.com/tux-evse/ti-am62x-binding-rs &&
    git clone https://github.com/tux-evse/iso15118-simulator-rs &&
    (mkdir -p iso15118-encoders/build && cd iso15118-encoders/build && cmake .. && make -j install)
EOF

# compile rust into CARGO_TARGET_DIR
RUN <<EOF
     microdnf --enablerepo=crb --nodocs -y install  libpcap-devel
    (cd iso15118-simulator-rs; cargo build --release)
EOF

RUN <<EOF
# prepare tiny-root-fs with afb and minimal dependencies
git clone https://github.com/fulup-bzh/mkTinyRootFs &&
(cd mkTinyRootFs &&
# wget https://github.com/fulup-bzh/mkTinyRootFs/raw/master/Samples/oci-sample.conf &&
cat >> minimal-iso15118.conf <<!!conf
# executable searched from path
BINLIST="
    /lib64/ld-linux-x86-64.so.2
    bash
    /usr/local/bin/afb-binder
    $CARGO_TARGET_DIR/$PROFILE/pcap-iso15118
"
SHARELIST="
    /usr/local/share
    /usr/local/share/afb-binder
    /usr/local/share/afb-ui-devtools
"
!!conf
./mkTinyRootFs.bash config=minimal-iso15118.conf target=/tmp/stage2-rootfs
)

EOF

# # # STAGE 2: build the container
FROM scratch As final
WORKDIR /tmp
COPY --from=builder /tmp/stage2-rootfs/ /
COPY --from=builder --chown=1000:1000 --chmod=0777 /var/tmp /tmp

ENV LD_LIBRARY_PATH="/usr/local/lib64:/usr/local/lib6"
ENV PATH="/usr/local/bin:/var/cargo/release:$PATH"
USER 10000:10000
CMD ["/usr/bin/bash"]
