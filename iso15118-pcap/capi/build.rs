/*
 * Copyright (C) 2015-2024 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Redpesk interface code/config use MIT License and can be freely copy/modified even within proprietary code
 * License: $RP_BEGIN_LICENSE$ SPDX:MIT https://opensource.org/licenses/MIT $RP_END_LICENSE$
 *
*/
use std::env;

fn main() {
    // check pkgconfig dependencies
    system_deps::Config::new().probe().unwrap();

    // invalidate the built crate whenever the wrapper changes
    println!("cargo:rustc-link-search=/usr/local/lib64");
    println!("cargo:rustc-link-arg=-lpcap");
    println!("cargo:rustc-link-arg=-liso15118");

    if let Ok(value) = env::var("CARGO_TARGET_DIR") {
        if let Ok(profile) = env::var("PROFILE") {
            println!("cargo:rustc-link-search=crate={}{}", value, profile);
        }
    }
    let header = "
    // -----------------------------------------------------------------------
    //         <- private 'lib-iso15118' Rust/C unsafe binding ->
    // -----------------------------------------------------------------------
    //   Do not exit this file it will be regenerated automatically by cargo.
    //   Check:
    //     - build.rs for C/Rust glue options
    //     - src/capi/capi-pcap.h for C prototype inputs
    // -----------------------------------------------------------------------
    ";
    println!("cargo:rerun-if-changed=capi/capi-pcap.h");
    let libcapi = bindgen::Builder::default()
        .header("capi/capi-pcap.h") // Chargebyte C prototype wrapper input
        .raw_line(header)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .derive_debug(false)
        .layout_tests(false)
        .allowlist_item("pcap_.*")
        .allowlist_var("PCAP_.*")
        .allowlist_item("C_.*")
        .allowlist_item(".*_header")
        .allowlist_function("ntoh.*")
        .generate()
        .expect("Unable to generate _capi_pcap.rs");

    libcapi
        .write_to_file("capi/_capi_pcap.rs")
        .expect("Couldn't write _capi_pcap.rs!");

}