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
use iso15118::prelude::*;
use iso15118_jsonc::prelude::*;
use std::env;
use std::io::Write;

#[track_caller]
fn err_usage(uid: &str, data: &str) -> Result<(), AfbError> {
    println!("usage: pcap-scenario --pcap_path=xxx.pcap --log_path=scenario.json [--max_count=xx] [--verbose=1] [--psk_log=/xxx/master-key.log] [--tcp_port=xxx] [--max_count=xxx");
    return afb_error!(uid, "invalid argument: {}", data);
}

struct LoggerCtx {
    log_fd: Option<File>,
    log_path: String,
    pcap_path: String,
    timestamp: Duration,
    pending_din: Option<din_exi::MessageTagId>,
    jtransaction: JsoncObj,
    jtransactions: JsoncObj,
    session_protocol: v2g::ProtocolTagId,
    supported_protocols: Vec<v2g::AppHandAppProtocolType>,
}

impl LoggerCtx {
    pub fn set_pcap_file(&mut self, path: &str) -> &mut Self {
        self.pcap_path= path.to_string();
        self
    }

    pub fn set_log_file(&mut self, filename: &str) -> Result<&mut Self, AfbError> {
        let log_fd = match File::create(filename) {
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
        self.log_path = filename.to_string();
        self.log_fd = Some(log_fd);
        Ok(self)
    }

    pub fn log_to_file(&mut self, jsonc: JsoncObj) -> Result<(), AfbError> {
        match &mut self.log_fd {
            None => println!("--- end scenario ---"),
            Some(fd) => {
                let text = format!("{:#}", jsonc);
                match fd.write_all(text.as_bytes()) {
                    Ok(_) => {}
                    Err(error) => {
                        return afb_error!(
                            "pcap-dump scenario",
                            "fail to push log entry to:{} error:{}",
                            self.log_path,
                            error
                        )
                    }
                }
            }
        }
        Ok(())
    }

    fn log_din_response(
        &mut self,
        pkg_count: i32,
        delay: u128,
        body: &din_exi::MessageBody,
    ) -> Result<(), AfbError> {
        use din_exi::*;
        use din_jsonc::*;

        let msg_id = body.get_tagid();

        // if not response pending store msg_id and with body arguments as json
        match &self.pending_din {
            None => {
                self.jtransaction = {
                    let jsonc = JsoncObj::new();
                    jsonc.add("uid", format!("pkg:{}", pkg_count).as_str())?;
                    jsonc.add("verb", msg_id.to_label())?;
                    jsonc.add("delay", delay as u64)?;
                    jsonc.add("query", body_to_jsonc(body)?)?;
                    jsonc
                };
                let res_id = msg_id.match_res_id();
                if res_id != MessageTagId::Unsupported {
                    self.pending_din = Some(res_id);
                } else {
                    self.pending_din = None;
                }
            }

            Some(pending) => {
                if msg_id == *pending {
                    self.jtransaction.add("expect", body_to_jsonc(body)?)?;
                    self.pending_din = None;
                } else {
                    return afb_error!(
                        "pcap-track-din",
                        "pkg:{} invalid response id, expected:{} got: {}",
                        pkg_count,
                        pending.to_label(),
                        msg_id.to_label()
                    );
                }
            }
        };

        if let None = self.pending_din {
            match Some(&self.log_fd) {
                Some(_fd) => {
                    self.jtransactions.insert(self.jtransaction.clone())?;
                }
                None => {
                    println!("{:#}", self.jtransaction);
                }
            }
        }
        Ok(())
    }

    fn close_scenario(&mut self) -> Result<(), AfbError> {
        let jbinding = JsoncObj::new();
        jbinding.add("uid", &self.pcap_path)?;
        jbinding.add("info",  &self.log_path)?;
        jbinding.add("api", "pcap-simu")?;
        jbinding.add("path", "${CARGO_TARGET_DIR}debug/libafb_iso15118_simulator.so")?;

        let jscenarios = JsoncObj::array();
        let jscenario = JsoncObj::new();
        jscenario.add("uid", "scenario-1")?;
        let target= match self.session_protocol {
            v2g::ProtocolTagId::Din => "iso15118-din",
            v2g::ProtocolTagId::Iso2 => "iso15118-2",
            _ => return afb_error!("pcal-closing-log", "unsuported protocol"),
        };
        jscenario.add("target", target)?;
        jscenario.add("transactions", self.jtransactions.clone())?;

        jscenarios.insert(jscenario)?;
        jbinding.add("scenarios",jscenarios)?;

        self.log_to_file(jbinding)?;
        Ok(())
    }
}

fn packet_handler(
    stream: &MutexGuard<RawStream>,
    pkg_count: i32,
    timestamp: Duration,
    user_data: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = user_data.get_mut::<LoggerCtx>()?;

    // compute message relative delay
    let delay = (timestamp - ctx.timestamp).as_millis();
    ctx.timestamp = timestamp;

    // pcap file parsing stop (on error or not)
    if pkg_count < 0 {
        return ctx.close_scenario()
    }

    match ctx.session_protocol {
        // decode message
        v2g::ProtocolTagId::Unknown => {
            let v2g_msg = v2g::SupportedAppProtocolExi::decode_from_stream(stream)?;
            match v2g_msg {
                v2g::V2gMsgBody::Response(payload) => {
                    // Fulup TBD handle joining old session, ...
                    let rcode = payload.get_rcode();
                    if let v2g::ResponseCode::Success = rcode {
                        let schema = payload.get_schema();
                        for idx in 0..ctx.supported_protocols.len() {
                            let proto = &ctx.supported_protocols[idx];
                            if schema == proto.get_schema() {
                                let proto_name = proto.get_name()?;
                                ctx.session_protocol = v2g::ProtocolTagId::from_urn(proto_name)?;
                            }
                        }
                    }
                    println!("pkg:{} SupportAppProtocolRes:{:?}", pkg_count, payload)
                }
                v2g::V2gMsgBody::Request(payload) => {
                    ctx.supported_protocols = payload.get_protocols();
                    println!("pkg:{} SupportAppProtocolReq:{:?}", pkg_count, payload);
                }
            }
        }

        v2g::ProtocolTagId::Din => {
            let din_msg = din_exi::ExiMessageDoc::decode_from_stream(stream)?;
            let _header = din_msg.get_header();
            let body = din_msg.get_body()?;

            // if no pending response track it otherwise wait for it
            ctx.log_din_response(pkg_count, delay, &body)?;
        }

        v2g::ProtocolTagId::Iso2 => {
            let iso2_msg = iso2_exi::ExiMessageDoc::decode_from_stream(stream)?;
            let _header = iso2_msg.get_header();
            let body = iso2_msg.get_body()?;

            println!(
                "pkg:{} delay:{} iso2-msg:{} ",
                pkg_count,
                delay,
                iso2_jsonc::body_to_jsonc(&body)?
            );
        }

        _ => {
            return afb_error!(
                "packet-handler-session_protocol",
                "packet:{} unsupported exi document type",
                pkg_count
            )
        }
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
        session_protocol: v2g::ProtocolTagId::Unknown,
        supported_protocols: Vec::new(),
        timestamp: Duration::new(0, 0),
        log_fd: None,
        log_path: String::new(),
        pcap_path: String::new(),
        pending_din: None,
        jtransaction: JsoncObj::new(),
        jtransactions: JsoncObj::array(),
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
            "--pcap_path" => {
                pcaps.set_pcap_file(parts[1])?;
                logger.set_pcap_file(parts[1]);
            }
            "--log_path" => {
                logger.set_log_file(parts[1])?;
            }
            "--tcp_port" => {
                let port = match parts[1].parse() {
                    Ok(value) => value,
                    Err(_) => return err_usage("invalid-port", arg.as_str()),
                };
                pcaps.set_tcp_port(port);
            }
            "--psk_log" => {
                pcaps.set_psk_log(parts[1])?;
            }
            "--max_count" => {
                let count = match parts[1].parse() {
                    Ok(value) => value,
                    Err(_) => return err_usage("invalid-count", arg.as_str()),
                };
                pcaps.set_max_packets(count);
            }
            "--verbose" => {
                let verbose = match parts[1].parse() {
                    Ok(value) => value,
                    Err(_) => return err_usage("invalid-verbosity_level", arg.as_str()),
                };
                pcaps.set_verbose(verbose);
            }
            _ => return err_usage("invalid-argument", arg.as_str()),
        }
    }

    let handle = pcaps
        .set_callback(packet_handler)
        .set_context(logger)
        .finalize()?;

    println!("** done pkg_count={}", handle.get_pkg_count());

    Ok(())
}
