/*
 * Copyright (C) 2015-2024 IoT.bzh Company
 * Author: Fulup Ar Foll <fulup@iot.bzh>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#[cfg(not(afbv4))]
extern crate afbv4;

// pcap C/Rust Api mapping
include!("../capi/capi-pcap.rs");

use afbv4::prelude::*;
use iso15118_jsonc::prelude::*;
use std::env;
use std::io::Write;

#[track_caller]
fn err_usage(uid: &str, data: &str) -> Result<(), AfbError> {
    println!("usage: pcap-scenario --tcpport=xxx --pcapfile=xxx.pcap --logfile=scenario.json [--maxcount=xx]");
    return afb_error!(uid, "invalid argument: {}", data);
}

struct LoggerCtx {
    outfile: Option<File>,
    timestamp: Duration,
    protocol: v2g::ProtocolTagId,
}

impl LoggerCtx {
    pub fn set_log_file(&mut self, filename: &str) -> Result<&mut Self, AfbError> {
        let file = match File::create(filename) {
            Ok(handle) => handle,
            Err(error) => {
                return afb_error!(
                    "pcap-log-file",
                    "fail to create log file:{} error:{}",
                    filename,
                    error
                )
            }
        };
        self.outfile = Some(file);
        Ok(self)
    }

    pub fn _log_data(&mut self, text: &str) -> Result<(), AfbError> {
        match &mut self.outfile {
            None => {
                println!("{}", text)
            }
            Some(fd) => match fd.write_all(text.as_bytes()) {
                Ok(_) => {}
                Err(error) => {
                    return afb_error!("gtls-config-log", "fail to push log entry error:{}", error)
                }
            },
        }
        Ok(())
    }
}

fn packet_handler(
    stream: &MutexGuard<RawStream>,
    count: u32,
    timestamp: Duration,
    user_data: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = user_data.get_mut::<LoggerCtx>()?;

    // compute message relative delay
    let delay = (timestamp - ctx.timestamp).as_millis();
    ctx.timestamp = timestamp;

    match ctx.protocol {
        // decode message
        v2g::ProtocolTagId::Unknown => {
            let v2g_msg = v2g::SupportedAppProtocolExi::decode_from_stream(stream)?;
            match v2g_msg {
                v2g::V2gMsgBody::Response(_body) => {
                    ctx.protocol = v2g::ProtocolTagId::Iso2;
                    println!("{}: SupportAppProtocolRes", count)
                }
                v2g::V2gMsgBody::Request(_body) => {
                    println!("{}: SupportAppProtocolReq", count)
                }
            }
        }

        v2g::ProtocolTagId::Iso2 => {
            let iso2_msg = iso2::Iso2MessageDoc::decode_from_stream(stream)?;
            let _header = iso2_msg.get_header();
            let body = iso2_msg.get_body()?;
            println!("{}: body:{} delay:{}", count, body_to_jsonc(&body)?, delay);
        }

        _ => return afb_error!("packet-handler-protocol", "packet:{} unsupported exi document type", count),
    }

    Ok(())
}

fn main() -> Result<(), AfbError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        return err_usage("arguments missing", args[0].as_str());
    }

    let mut pcaps = PcapHandle::new();
    let mut logger = LoggerCtx {
        protocol: v2g::ProtocolTagId::Unknown,
        timestamp: Duration::new(0, 0),
        outfile: None,
    };

    for idx in 1..args.len() {
        let arg = &args[idx];

        let mut parts = arg.split('=').collect::<Vec<&str>>();
        if parts.len() == 1 {
            parts = arg.split(' ').collect::<Vec<&str>>();
        }

        if parts.len() != 2 {
            return err_usage("invalid argument", arg.as_str());
        }

        match parts[0] {
            "--pcapfile" => {
                pcaps.set_pcap_file(parts[1])?;
            }
            "--logfile" => {
                logger.set_log_file(parts[1])?;
            }
            "--tcpport" => {
                let port = match parts[1].parse() {
                    Ok(value) => value,
                    Err(_) => return err_usage("invalid-port", arg.as_str()),
                };
                pcaps.set_tcp_port(port);
            }
            "--maxcount" => {
                let count = match parts[1].parse() {
                    Ok(value) => value,
                    Err(_) => return err_usage("invalid-port", arg.as_str()),
                };
                pcaps.set_max_packets(count);
            }
            _ => return err_usage("invalid-argument", arg.as_str()),
        }
    }

    pcaps
        .set_callback(packet_handler)
        .set_context(logger)
        .finalize()?;

    Ok(())
}
