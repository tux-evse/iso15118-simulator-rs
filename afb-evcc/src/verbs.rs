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

use crate::prelude::*;
use afbv4::prelude::*;
use iso15118::prelude::*;
use iso15118_jsonc::prelude::*;
use nettls::prelude::*;
use serde::{Deserialize, Serialize};
use std::time::Duration;

AfbDataConverter!(sdp_actions, SdpAction);
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase", tag = "action")]
pub enum SdpAction {
    DISCOVER,
    FORGET,
    INFO,
}

struct SdpJobCtx {
    ctrl: &'static Controller,
    sdp_security: v2g::SdpSecurityModel,
    sdp_port: u16,
}

struct SdpJobData {
    sock_sdp: SocketSdpV6,
    sdp_scope: u32,
    afb_rqt: AfbRequest,
}

fn sdp_job_cb(
    _job: &AfbSchedJob,
    _signal: i32,
    data: &AfbCtxData,
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    use v2g::*;

    // retrieve job post arguments
    let ctx = ctx.get_ref::<SdpJobCtx>()?;
    let data = data.get_ref::<SdpJobData>()?;

    // encode and send SDP message as UDP ip6 multicast
    let payload = SdpRequest::new(SdpTransportProtocol::TCP, ctx.sdp_security).encode()?;
    let multicast6 = SockAddrV6::new(&IP6_BROADCAST_ANY, ctx.sdp_port, data.sdp_scope);

    let (lock, cvar) = &*ctx.ctrl.initialized;
    let mut started = lock.lock().unwrap();
    let mut idx = 0;
    // if ctrl not initialized wait
    loop {
        // send SDP discovery request
        data.sock_sdp.sendto(&payload, &multicast6)?;

        let result = cvar
            .wait_timeout(started, Duration::from_millis(SDP_INIT_TIMEOUT))
            .unwrap();
        started = result.0;
        if *started == true {
            break;
        }
        idx += 1;
        afb_log_msg!(
            Notice,
            &data.afb_rqt,
            "v2g-discovery-start[{}] probing v2g-msg message",
            idx
        );

        if idx == SDP_INIT_TRY {
            let error = AfbError::new(
                "v2g-discovery-fail",
                -100,
                "Fail to receive ISO15118-SDP message",
            );
            data.afb_rqt.reply(error, -100);
            return afb_error!("v2g-discovery-fail", "Fail to receive ISO15118-SDP message");
        }
    }

    let state = ctx.ctrl.lock_state()?;
    match &state.connection {
        Some(cnx) => {
            let addr6 = format!("{}", cnx.get_source());
            let jsonc = JsoncObj::new();
            jsonc.add("ipv6", addr6.as_str())?;
            jsonc.add("port", cnx.get_port() as u32)?;
            jsonc.add("tls", cnx.is_secure())?;
            data.afb_rqt.reply(jsonc, 0);
        }
        None => {
            return afb_error!(
                "iso2-discovery-fail",
                "Fail to establish ISO15118-SDP message"
            );
        }
    }
    Ok(())
}

struct DiscoverEvseCtx {
    sdp_job: &'static AfbSchedJob,
    ip6_addr: IfaceAddr6,
    sdp_port: u16,
    ctrl: &'static Controller,
}

fn discover_evse_cb(
    afb_rqt: &AfbRequest,
    args: &AfbRqtData,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = context.get_mut::<DiscoverEvseCtx>()?;
    let action = args.get::<&SdpAction>(0)?;

    match action {
        SdpAction::INFO => {
            let state = ctx.ctrl.lock_state()?;

            let jresponse = JsoncObj::new();
            jresponse.add("local", {
                let addr6 = format!("[{}%{}]", ctx.ip6_addr.get_addr(), ctx.ip6_addr.get_scope());
                let jsonc = JsoncObj::new();
                jsonc.add("iface", ctx.ip6_addr.get_iface())?;
                jsonc.add("ipv6", addr6.as_str())?;
                jsonc.add("sdp", ctx.sdp_port as u32)?;
                jsonc
            })?;

            if let Some(cnx) = &state.connection {
                jresponse.add("remote", {
                    let addr6 = format!("{}", cnx.get_source());
                    let jsonc = JsoncObj::new();
                    jsonc.add("ipv6", addr6.as_str())?;
                    jsonc.add("port", cnx.get_port() as u32)?;
                    jsonc.add("tls", cnx.is_secure())?;
                    jsonc
                })?;
            }

            afb_rqt.reply(jresponse, 0);
            return Ok(());
        }
        SdpAction::FORGET => {
            ctx.ctrl.reset()?;
            afb_rqt.reply(AFB_NO_DATA, 0);
        }
        SdpAction::DISCOVER => {
            let state = ctx.ctrl.lock_state()?;
            if let Some(_) = &state.connection {
                return afb_error!(
                    "discover-evse_cb",
                    "SDP iso15118 session already discovered"
                );
            }

            // Create SDP sock (both client & server)
            let sdp_svc = SdpServer::new("sdp-client", ctx.ip6_addr.get_iface(), ctx.sdp_port)?;
            let sock_sdp = sdp_svc.get_socket();

            // Map SDP receive message to callback
            AfbEvtFd::new("sdp_async_cb")
                .set_fd(sdp_svc.get_sockfd())
                .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
                .set_callback(async_sdp_cb)
                .set_context(AsyncSdpCtx {
                    ctrl: ctx.ctrl,
                    sdp_scope: ctx.ip6_addr.get_scope(),
                    sdp_svc,
                })
                .start()?;

            ctx.sdp_job.post(
                0,
                SdpJobData {
                    afb_rqt: afb_rqt.add_ref(),
                    sock_sdp,
                    sdp_scope: ctx.ip6_addr.get_scope(),
                },
            )?;
        }
    }
    Ok(())
}

pub struct V2gMsgReqCtx {
    pub protocol: v2g::ProtocolTagId,
    pub uid: &'static str,
    pub ctrl: &'static Controller,
    pub msg_id: u32,
    pub timeout: i64,
}

fn v2g_msg_req_cb(
    afb_rqt: &AfbRequest,
    args: &AfbRqtData,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = context.get_ref::<V2gMsgReqCtx>()?;
    let api_params = args.get::<JsoncObj>(0)?;

    match ctx.protocol {
        v2g::ProtocolTagId::Din => ctx.ctrl.din_send_payload(afb_rqt, &ctx, api_params)?,
        v2g::ProtocolTagId::Iso2 => ctx.ctrl.iso2_send_payload(afb_rqt, &ctx, api_params)?,
        _ => return afb_error!("v2g-msg-req-cb", "invalid protocol"),
    }
    Ok(())
}

fn app_proto_req_cb(
    afb_rqt: &AfbRequest,
    _args: &AfbRqtData,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    use v2g::*;

    let ctx = context.get_ref::<V2gMsgReqCtx>()?;
    let iso2_proto = V2G_PROTOCOLS_SUPPORTED_LIST[ProtocolTagId::Iso2 as usize];
    let v2g_body = SupportedAppProtocolReq::new(iso2_proto)?.encode();

    ctx.ctrl.v2g_send_payload(afb_rqt, ctx, &v2g_body)?;
    Ok(())
}

pub fn register_verbs(
    group: &mut AfbGroup,
    config: BindingConfig,
    ctrl: &'static Controller,
) -> Result<(), AfbError> {
    sdp_actions::register()?;

    let protocol_conf = match config.protocol.to_lowercase().as_str() {
        "din" => v2g::ProtocolTagId::Din,
        "iso2" => v2g::ProtocolTagId::Iso2,
        _ => return afb_error!("register-verb", "unsupported iso15118 expect:din|iso2 got:{}", config.protocol),
    };

    let sdp_job = AfbSchedJob::new("sdp-job")
        .set_callback(sdp_job_cb)
        .set_context(SdpJobCtx {
            ctrl,
            sdp_port: config.sdp_port,
            sdp_security: config.sdp_security,
        })
        .finalize();

    let connect_verb = AfbVerb::new("sdp-evse")
        .set_name("sdp_evse_req")
        .set_info("Discover EVSE ISO-15118 services")
        .set_actions("['discover','forget','info']")?
        .set_callback(discover_evse_cb)
        .set_context(DiscoverEvseCtx {
            sdp_job,
            ip6_addr: get_iface_addrs(config.ip6_iface, config.ip6_prefix)?,
            sdp_port: config.sdp_port,
            ctrl,
        });

    let app_proto_verb = AfbVerb::new("v2g-hand-shake")
        .set_name("app_proto_req")
        .set_info("Announce simulated protocol")
        .set_callback(app_proto_req_cb)
        .set_context(V2gMsgReqCtx {
            ctrl,
            protocol: v2g::ProtocolTagId::Unknown,
            uid: "app_proto_req",
            timeout: config.timeout,
            msg_id: v2g::MessageTagId::AppProtocolReq as u32,
        });

    group.add_verb(connect_verb.finalize()?);
    group.add_verb(app_proto_verb.finalize()?);

    for idx in 0..config.jverbs.count()? {
        let msg_name = config.jverbs.index::<&'static str>(idx)?;

        let msg_group = match protocol_conf {
            v2g::ProtocolTagId::Din => din_jsonc::api_from_tagid(msg_name)?,
            v2g::ProtocolTagId::Iso2 => iso2_jsonc::api_from_tagid(msg_name)?,
            _ => return afb_error!("hoop", "invalid protocol"),
        };

        let v2g_msg_verb = AfbVerb::new(msg_group.uid);
        v2g_msg_verb
            .set_name(msg_group.name)
            .set_info(msg_group.info)
            .set_callback(v2g_msg_req_cb)
            .set_context(V2gMsgReqCtx {
                ctrl,
                uid: msg_name,
                timeout: config.timeout,
                msg_id: msg_group.msg_id,
                protocol: protocol_conf,
            });

        if let Some(sample) = msg_group.sample {
            v2g_msg_verb.add_sample(sample)?;
        };
        group.add_verb(v2g_msg_verb.finalize()?);
    }

    Ok(())
}
