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
use std::cell::RefCell;
use std::env;
use std::io::Write;

#[track_caller]
fn err_usage(uid: &str, data: &str) -> Result<(), AfbError> {
    println!("usage: pcap-iso15118 --pcap_in=xxx.pcap --json_out=scenario.json [--max_count=xx] [--verbose=1] [--key_log_in=/xxx/master-key.log] [--tcp_port=xxx] [--max_count=xxx");
    return afb_error!(uid, "{}", data);
}

struct ScenarioDin {
    debug_only: bool,
    jtransaction: JsoncObj,
    pending: Option<din_exi::MessageTagId>,
}

impl ScenarioDin {
    fn new(debug_only: bool) -> Self {
        Self {
            debug_only,
            pending: None,
            jtransaction: JsoncObj::new(),
        }
    }

    fn log_response(
        &mut self,
        jtransactions: JsoncObj,
        pkg_count: u32,
        delay: u128,
        body: &din_exi::MessageBody,
    ) -> Result<(), AfbError> {
        use din_exi::*;
        use din_jsonc::*;

        let msg_id = body.get_tagid();

        // if not response pending store msg_id and with body arguments as json
        match &self.pending {
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
                    self.pending = Some(res_id);
                } else {
                    self.pending = None;
                }
            }

            Some(pending) => {
                if msg_id == *pending {
                    self.jtransaction.add("expect", body_to_jsonc(body)?)?;
                    self.pending = None;
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

        if let None = self.pending {
            if self.debug_only {
                jtransactions.append(self.jtransaction.clone())?;
            } else {
                println!("{:#}", self.jtransaction);
            }
        }
        Ok(())
    }
}

struct ScenarioIso2 {
    debug_only: bool,
    jtransaction: JsoncObj,
    pending: Option<iso2_exi::MessageTagId>,
}

impl ScenarioIso2 {
    fn new(debug_only: bool) -> Self {
        Self {
            debug_only,
            pending: None,
            jtransaction: JsoncObj::new(),
        }
    }

    fn log_response(
        &mut self,
        jtransactions: JsoncObj,
        pkg_count: u32,
        delay: u128,
        body: &iso2_exi::MessageBody,
    ) -> Result<(), AfbError> {
        use iso2_exi::*;
        use iso2_jsonc::*;

        let msg_id = body.get_tagid();

        // if not response pending store msg_id and with body arguments as json
        match &self.pending {
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
                    self.pending = Some(res_id);
                } else {
                    self.pending = None;
                }
            }

            Some(pending) => {
                if msg_id == *pending {
                    self.jtransaction.add("expect", body_to_jsonc(body)?)?;
                    self.pending = None;
                } else {
                    return afb_error!(
                        "pcap-track-iso2",
                        "pkg:{} invalid response id, expected:{} got: {}",
                        pkg_count,
                        pending.to_label(),
                        msg_id.to_label()
                    );
                }
            }
        };

        if let None = self.pending {
            if self.debug_only {
                jtransactions.append(self.jtransaction.clone())?;
            } else {
                println!("{:#}", self.jtransaction);
            }
        }
        Ok(())
    }
}

enum ScenarioProto {
    Din(ScenarioDin),
    Iso2(ScenarioIso2),
    Undef,
}

struct ScenarioLog {
    protocol: ScenarioProto,
    jtransactions: JsoncObj,
    jscenarios: JsoncObj,
    pkg_start: u32,
}

impl ScenarioLog {
    fn new(pkg_count: u32, protocol: v2g::ProtocolTagId, debug_only: bool) -> Result<Self, AfbError> {
        let protocol = match protocol {
            v2g::ProtocolTagId::Din => ScenarioProto::Din(ScenarioDin::new(debug_only)),
            v2g::ProtocolTagId::Iso2 => ScenarioProto::Iso2(ScenarioIso2::new(debug_only)),
            _ => ScenarioProto::Undef,
        };

        let this= Self {
            protocol,
            jscenarios: JsoncObj::array(),
            jtransactions: JsoncObj::array(),
            pkg_start: pkg_count,
        };

        let jsdp = JsoncObj::parse("{'uid':'sdp-evse','query':{'action':'discovery'}}")?;
        this.jtransactions.append(jsdp)?;
        Ok(this)
    }

    fn get_pkg_start(&self) -> u32 {
        self.pkg_start
    }

    fn session_close(&mut self, ctx: &LoggerCtx) -> Result<usize, AfbError> {
        let count = self.jtransactions.count()?;
        if count == 0 {
            return afb_error!("pcap-session-close", "empty iso15118 session");
        }

        // insert sdp session close
        let jend = JsoncObj::parse("{'uid':'sdp-evse','query':{'action':'forget'}}")?;
        self.jtransactions.append(jend)?;

        let jscenario = JsoncObj::new();

        let target = match &ctx.session_protocol {
            v2g::ProtocolTagId::Din => "15118/din",
            v2g::ProtocolTagId::Iso2 => "15118/iso2",
            _ => return afb_error!("pcal-closing-log", "unsupported protocol"),
        };
        let uid = format!("scenario:{}/{}", target, self.jscenarios.count()? + 1);
        jscenario.add("uid", &uid)?;
        jscenario.add("target", target)?;
        jscenario.add("transactions", self.jtransactions.clone())?;

        // save scenario and reset transaction for next tcp/iso session
        self.jscenarios.append(jscenario)?;
        self.jtransactions = JsoncObj::array();
        Ok(count)
    }

    fn import_close(&mut self, ctx: &LoggerCtx) -> Result<JsoncObj, AfbError> {
        let jbinding = JsoncObj::new();

        if self.jscenarios.count()? == 0 {
            return afb_error!("pcap-scenarios-close", "empty iso15118 scenario");
        }

        jbinding.add("uid", "iso15118-simulator")?;
        jbinding.add("info", &ctx.pcap_in)?;
        jbinding.add("api", "iso15118-replay")?;
        jbinding.add(
            "path",
            "${CARGO_BINDING_DIR}/libafb_injector.so",
        )?;

        jbinding.add("scenarios", self.jscenarios.clone())?;
        self.jscenarios = JsoncObj::array();

        // finally embed binding object into binder/bindings array
        let jbindings= JsoncObj::array();
        jbindings.append(jbinding)?;
        let jbinder= JsoncObj::new();
        jbinder.add("binding",jbindings)?;

        Ok(jbinder)
    }
}

struct LoggerCtx {
    scenario: RefCell<ScenarioLog>,
    stream: ExiStream,
    data_len: usize,
    exi_len: usize,
    log_fd: Option<File>,
    json_out: String,
    pcap_in: String,
    timestamp: Duration,
    msg_delay: u128,
    session_protocol: v2g::ProtocolTagId,
    supported_protocols: Vec<v2g::AppHandAppProtocolType>,
}

impl LoggerCtx {
    pub fn set_pcap_file(&mut self, path: &str) -> &mut Self {
        self.pcap_in = path.to_string();
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
        self.json_out = filename.to_string();
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
                            self.json_out,
                            error
                        )
                    }
                }
            }
        }
        Ok(())
    }
}

fn packet_handler_cb(
    pkg_count: u32,
    exi_data: &[u8],
    timestamp: Duration,
    user_data: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = user_data.get_mut::<LoggerCtx>()?;

    // no more message let's close iso15118 scenario
    if exi_data.len() == 0 {
        // we may have more than one iso session in pcap file
        let pkg_start = ctx.scenario.borrow().get_pkg_start();
        match ctx.scenario.borrow_mut().session_close(ctx) {
            Ok(count) => eprintln!(
                "--iso15118-session [start,stop]:[{},{}] proto:{:?} transac_count:{}",
                pkg_start, pkg_count, ctx.session_protocol, count,
            ),
            Err(error) => {
                // pkg_count == 0 at pcap closing. We should then output json even despite empty last session
                if pkg_count != 0 {
                    return Err(error);
                }
            }
        }

        ctx.session_protocol = v2g::ProtocolTagId::Unknown;

        // we are facing the end of pcap file let's output import
        if pkg_count == 0 {
            let jscenario = ctx.scenario.borrow_mut().import_close(ctx)?;
            ctx.log_to_file(jscenario)?;
            eprintln!(
                "--iso15118-import done pcap_in:{} json_out:{}",
                ctx.pcap_in, ctx.json_out
            );
        }
        return Ok(());
    }

    // lock exi buffer stream in rw mode
    let mut lock = ctx.stream.lock_stream();
    let (stream_used, stream_available) = ctx.stream.get_index(&lock);

    // if buffer can hold exi data let's move them in
    if stream_available < exi_data.len() {
        return afb_error!(
            "pkg-cb-stream-available",
            "exi_extract_data buffer full close session",
        );
    } else {
        // move tcp data into exi stream internal buffer
        lock.buffer[stream_used..exi_data.len()].copy_from_slice(exi_data)
    }

    // when facing a new exi compte delay and check how much data should be read
    if stream_used == 0 {
        // compute inter message delay
        if ctx.timestamp.as_millis() > 0 {
            ctx.msg_delay = (timestamp - ctx.timestamp).as_millis()
        }
        ctx.timestamp = timestamp;

        // extract from v2g header exi document size
        let len = ctx.stream.get_payload_len(&lock);
        if len < 0 {
            return afb_error!(
                "pkg-cb-stream-payload",
                "exi_extract_data: packet ignored (invalid v2g header) size:{}",
                exi_data.len()
            );
        } else {
            ctx.exi_len = len as usize;
        };
        ctx.data_len = 0;
    }

    // big EXI document may arrive in multiple TCP chunk that should be assemble before decoding
    ctx.data_len += exi_data.len();
    if ctx.data_len < ctx.exi_len + v2g::SDP_V2G_HEADER_LEN {
        // Exi document not full arrived
        return Ok(());
    }

    // we got full exi document let's prepare to decode it
    if let Err(error) = ctx.stream.finalize(&lock, ctx.exi_len as u32) {
        return afb_error!("pkg-cb-stream-finalize", "{:?}", error);
    }

    match ctx.session_protocol {
        // decode message
        v2g::ProtocolTagId::Unknown => {
            let v2g_msg = v2g::SupportedAppProtocolExi::decode_from_stream(&lock)?;
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

                    let debug_only = match &ctx.log_fd {
                        Some(_) => true,
                        None => false,
                    };

                    // prepare scenario for log
                    ctx.scenario = RefCell::new(ScenarioLog::new(
                        pkg_count,
                        ctx.session_protocol,
                        debug_only,
                    )?);
                }
                v2g::V2gMsgBody::Request(payload) => {
                    ctx.supported_protocols = payload.get_protocols();
                }
            }
        }

        v2g::ProtocolTagId::Din => {
            let mut scenario = ctx.scenario.borrow_mut();
            let jtransactions = scenario.jtransactions.clone();
            if let ScenarioProto::Din(logger) = &mut scenario.protocol {
                let din_msg = din_exi::ExiMessageDoc::decode_from_stream(&lock)?;
                let _header = din_msg.get_header();
                let body = din_msg.get_body()?;

                // if no pending response track it otherwise wait for it
                logger.log_response(jtransactions, pkg_count, ctx.msg_delay, &body)?;
            }
        }

        v2g::ProtocolTagId::Iso2 => {
            let mut scenario = ctx.scenario.borrow_mut();
            let jtransactions = scenario.jtransactions.clone();
            if let ScenarioProto::Iso2(logger) = &mut scenario.protocol {
                let iso2_msg = iso2_exi::ExiMessageDoc::decode_from_stream(&lock)?;
                let _header = iso2_msg.get_header();
                let body = iso2_msg.get_body()?;

                // if no pending response track it otherwise wait for it
                logger.log_response(jtransactions, pkg_count, ctx.msg_delay, &body)?;
            }
        }

        _ => {
            return afb_error!(
                "packet-handler-session_protocol",
                "unsupported exi document type",
            )
        }
    }

    // wipe stream for next request
    ctx.stream.reset(&lock);
    Ok(())
}

fn main() -> Result<(), AfbError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 1 {
        return err_usage("arguments missing", args[0].as_str());
    }

    let mut pcaps = PcapHandle::new();
    let mut logger = LoggerCtx {
        session_protocol: v2g::ProtocolTagId::Unknown,
        scenario: RefCell::new(ScenarioLog::new(0, v2g::ProtocolTagId::Unknown, true)?),
        supported_protocols: Vec::new(),
        timestamp: Duration::new(0, 0),
        log_fd: None,
        json_out: String::new(),
        pcap_in: String::new(),
        stream: ExiStream::new(),
        data_len: 0,
        exi_len: 0,
        msg_delay: 0,
    };

    for idx in 1..args.len() {
        let arg = &args[idx];

        if arg == "--help" {
            return err_usage("usage", "check syntax");
        }

        let mut parts = arg.split('=').collect::<Vec<&str>>();
        if parts.len() == 1 {
            parts = arg.split(' ').collect::<Vec<&str>>();
        }

        if parts.len() != 2 {
            return err_usage("invalid argument", arg.as_str());
        }

        match parts[0] {
            "--pcap_in" => {
                pcaps.set_pcap_file(parts[1])?;
                logger.set_pcap_file(parts[1]);
            }
            "--json_out" => {
                logger.set_log_file(parts[1])?;
            }
            "--tcp_port" => {
                let port = match parts[1].parse() {
                    Ok(value) => value,
                    Err(_) => return err_usage("invalid-port", arg.as_str()),
                };
                pcaps.set_tcp_port(port);
            }
            "--keys_log" => {
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

    // lop on pcap packets
    pcaps
        .set_callback(packet_handler_cb)
        .set_context(logger)
        .finalize()?;

    Ok(())
}
