/*
 * Copyright (C) 2015-2022 IoT.bzh Company
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
use iso15118::prelude::{iso2::*, *};
use nettls::prelude::*;
use std::time::Duration;

struct SessionSetupReqCtx {
    ctrl: &'static Controller,
    msg_id: MessageTagId,
    timeout: i64,
}

fn session_setup_req_cb(
    afb_rqt: &AfbRequest,
    args: &AfbRqtData,
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<SessionSetupReqCtx>()?;
    let api_params = args.get::<JsoncObj>(0)?;

    ctx.ctrl
        .send_payload(afb_rqt, ctx.msg_id.clone(), api_params, ctx.timeout)?;
    Ok(())
}

struct SdpJobCtx {
    ctrl: &'static Controller,
    sdp_security: SdpSecurityModel,
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
            "iso2-discovery-start[{}] probing v2g-msg message",
            idx
        );

        if idx == SDP_INIT_TRY {
            let error = AfbError::new(
                "iso2-discovery-fail",
                -100,
                "Fail to receive ISO15118-SDP message",
            );
            data.afb_rqt.reply(error, -100);
            return afb_error!(
                "iso2-discovery-fail",
                "Fail to receive ISO15118-SDP message"
            );
        }
    }
    data.afb_rqt.reply(AFB_NO_DATA, 0);
    Ok(())
}

struct DiscoverEvseCtx {
    sdp_job: &'static AfbSchedJob,
    ip6_iface: &'static str,
    ip6_prefix: u16,
    sdp_port: u16,
    ctrl: &'static Controller,
}

fn discover_evse_cb(
    afb_rqt: &AfbRequest,
    _args: &AfbRqtData,
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = ctx.get_mut::<DiscoverEvseCtx>()?;

    afb_log_msg!(
        Notice,
        afb_rqt,
        "iface:{} sdp:{} prefix:{:#0x}",
        ctx.ip6_iface,
        ctx.sdp_port,
        ctx.ip6_prefix
    );

    // build multicast ip6 addr for iface/scope
    let sdp_scope = get_iface_addrs(ctx.ip6_iface, ctx.ip6_prefix)?.get_scope();

    // Create SDP sock (both client & server)
    let sdp_svc = SdpServer::new("sdp-client", ctx.ip6_iface, ctx.sdp_port)?;
    let sock_sdp = sdp_svc.get_socket();

    // Map SDP receive message to callback
    AfbEvtFd::new("sdp_async_cb")
        .set_fd(sdp_svc.get_sockfd())
        .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
        .set_callback(async_sdp_cb)
        .set_autounref(true)
        .set_context(AsyncSdpCtx {
            ctrl: ctx.ctrl,
            sdp_scope,
            sdp_svc,
        })
        .start()?;

    ctx.sdp_job.post(
        0,
        SdpJobData {
            afb_rqt: afb_rqt.add_ref(),
            sock_sdp,
            sdp_scope,
        },
    )?;

    // if ctrl not initialized wait
    // let (lock, cvar) = &*ctx.ctrl.initialized;
    // let mut started = lock.lock().unwrap();
    // let mut idx = 0;
    // sock_sdp.sendto(&payload, &multicast6)?;

    // loop {
    //     // send SDP discovery request
    //     sock_sdp.sendto(&payload, &multicast6)?;

    //     let result = cvar
    //         .wait_timeout(started, Duration::from_millis(SDP_INIT_TIMEOUT))
    //         .unwrap();
    //     started = result.0;
    //     if *started == true {
    //         break;
    //     }
    //     idx += 1;
    //     afb_log_msg!(
    //         Notice,
    //         afb_rqt,
    //         "iso2-discovery-start[{}] probing v2g-msg message",
    //         idx
    //     );

    //     if idx == SDP_INIT_TRY {
    //         return afb_error!(
    //             "iso2-discovery-fail",
    //             "Fail to receive ISO15118-SDP message"
    //         );
    //     }
    // }
    Ok(())
}

pub fn register_verbs(
    api: &mut AfbApi,
    config: BindingConfig,
    ctrl: &'static Controller,
) -> Result<(), AfbError> {
    let sdp_job = AfbSchedJob::new("sdp-job")
        .set_callback(sdp_job_cb)
        .set_context(SdpJobCtx {
            ctrl,
            sdp_port: config.sdp_port,
            sdp_security: config.sdp_security,
        })
        .finalize();

    let connect_verb = AfbVerb::new("sdp-evse")
        .set_name("sdp")
        .set_info("Discover EVSE ISO-15118 services")
        .set_callback(discover_evse_cb)
        .set_context(DiscoverEvseCtx {
            sdp_job,
            ip6_iface: config.ip6_iface,
            ip6_prefix: config.ip6_prefix,
            sdp_port: config.sdp_port,
            ctrl,
        });

    for idx in 0..config.jverbs.count()? {
        let msg_name = config.jverbs.index::<&'static str>(idx)?;
        let msg_api = api_from_tagid(msg_name)?;

        let msg_verb = AfbVerb::new(msg_api.uid);
        msg_verb
            .set_name(msg_api.name)
            .set_info(msg_api.info)
            .set_callback(session_setup_req_cb)
            .set_context(SessionSetupReqCtx {
                timeout: config.timeout,
                ctrl,
                msg_id: msg_api.msg_id,
            });

        if let Some(sample) = msg_api.sample {
            msg_verb.set_sample(sample)?;
        };

        api.add_verb(connect_verb.finalize()?);
        api.add_verb(msg_verb.finalize()?);
    }
    Ok(())
}
