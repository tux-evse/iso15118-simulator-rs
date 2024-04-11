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
use std::sync::{Arc, Mutex, MutexGuard, Condvar};
use std::time::Duration;
use std::{mem, net};

pub const SDP_INIT_TIMEOUT:u64 = 3000;
pub const SDP_INIT_TRY:u64 = 10;
pub struct ControllerPending {
    afb_rqt: AfbRqtV4,
    msg_id: MessageTagId,
    job_id: i32,
}

pub struct JobPostData {
    afb_rqt: AfbRqtV4,
}

pub struct ControllerState {
    pub connection: Box<dyn NetConnection>,
    pub pending: Option<ControllerPending>,
}

struct AsyncTcpClientCtx {
    controller: &'static Controller,
    data_len: u32,
    payload_len: u32,
}

// New TCP client connecting
fn async_tcp_client_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let context = ctx.get_mut::<AsyncTcpClientCtx>()?;
    // read is the only accepted operation
    if revent != AfbEvtFdPoll::IN.bits() {
        ctx.free();
        return Ok(());
    }

    // move tcp socket data into exi stream buffer
    let mut lock = context.controller.stream.lock_stream();
    let state = context.controller.lock_state()?;

    let read_count = {
        let (stream_idx, stream_available) = context.controller.stream.get_index(&lock);

        let read_count = if stream_available == 0 {
            afb_log_msg!(
                Notice,
                None,
                "async_tcp_client {:?}, buffer full close session",
                state.connection.get_source()
            );
            state.connection.close()?;
            return Ok(());
        } else {
            let buffer = &mut lock.buffer[stream_idx..];
            state.connection.get_data(buffer)?
        };

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            context.payload_len = context.controller.stream.header_check(&lock)?;
            context.data_len = 0;
        }
        read_count
    };

    // if data send in chunks let's complete exi buffer before processing it
    context.data_len = context.data_len + read_count;
    if context.data_len == context.payload_len {
        // decode request and encode response
        context.controller.decode_payload(context.data_len)?;
    }

    Ok(())
}

// this callback starts from AfbSchedJob::new. If signal!=0 then callback overpass its watchdog timeout
fn jobpost_callback(
    _job: &AfbSchedJob,
    _signal: i32,
    data: &AfbCtxData,
    _ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    // retrieve job post arguments
    let param = data.get_ref::<JobPostData>()?;
    let request = AfbRequest::from_raw(param.afb_rqt);
    request.reply(AFB_NO_DATA, -110); // timeout
    Ok(())
}

struct AsyncSdpCtx {
    controller: &'static Controller,
}

// async function receive SDP server ipv6 addr::port for iso15118 services
fn async_sdp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncSdpCtx>()?;
    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(Warning, None, "Unexpected SDP async event");
        return Ok(());
    }

    // get SDP/UDP packet
    let mut buffer = [0 as u8; mem::size_of::<SdpResponseBuffer>()];
    ctx.controller.sdp_sock.read_buffer(&mut buffer)?;

    let response = SdpResponse::decode(&buffer)?;
    match response.check_header() {
        Ok(_) => {}
        Err(error) => {
            afb_log_msg!(
                Notice,
                None,
                "iso2-sdp-async: ignoring multicast {}",
                error.get_info()
            );
            return Ok(());
        }
    }

    match response.get_transport() {
        SdpTransportProtocol::TCP => {}
        _ => {
            afb_log_msg!(Critical, None, "UDP transport not supported");
            return Ok(());
        }
    }

    // extract port and server ip from response and build corresponding ip6 addr
    let svc_port = response.get_port();
    let svc_addr = response.get_addr6();
    let remote6 = net::Ipv6Addr::from(svc_addr);

    let connection: Box<dyn NetConnection> = match response.get_security() {
        SdpSecurityModel::TLS => match &ctx.controller.tls_conf {
            None => {
                afb_log_msg!(Critical, None, "TLS request but not configured");
                return Ok(());
            }
            Some(config) => {
                let tcp_client = TcpClient::new(remote6, svc_port, ctx.controller.scope)?;
                let tls_client = TlsConnection::new(config, tcp_client)?;
                Box::new(tls_client)
            }
        },
        SdpSecurityModel::NONE => {
            if let Some(_) = ctx.controller.tls_conf {
                afb_log_msg!(Warning, None, "TLS configured but not refused by server");
            }

            // connect TCL client to server
            let tcp_client = TcpClient::new(remote6, svc_port, ctx.controller.scope)?;

            // register asynchronous tcp callback
            AfbEvtFd::new("iso2-tcp-client")
                .set_fd(tcp_client.get_sockfd()?)
                .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
                .set_autounref(true)
                .set_callback(async_tcp_client_cb)
                .set_context(AsyncTcpClientCtx {
                    controller: ctx.controller,
                    data_len: 0,
                    payload_len: 0,
                })
                .start()?;

            Box::new(tcp_client)
        }
    };

    // update TCP/TLS client connection
    let mut state = ctx.controller.lock_state()?;
    state.connection = connection;

    // unlock controller
    let (lock, cvar) = &*ctx.controller.initialized;
    let mut started = lock.lock().unwrap();
    *started = true;
    cvar.notify_one();

    Ok(())
}

pub struct Controller {
    pub initialized: Arc<(Mutex<bool>, Condvar)>,
    pub data_set: Mutex<ControllerState>,
    pub stream: ExiStream,
    pub session: SessionId,
    pub tls_conf: Option<&'static TlsConfig>,
    pub sdp_sock: SdpServer,
    pub scope: u32,
    pub job_post: &'static AfbSchedJob,
}

pub struct ControllerConfig {
    pub tls_conf: Option<&'static TlsConfig>,
    pub sdp_port: u16,
    pub ip6_prefix: u16,
    pub ip6_iface: &'static str,
    pub session_id: &'static str,
}

impl Controller {
    pub fn new(config: ControllerConfig) -> Result<&'static Self, AfbError> {
        // create a fake session id
        let mut session_u8 = [0; 8];
        let len = hexa_to_byte(config.session_id, &mut session_u8)?;

        // send SDP multicast packet
        let security = match &config.tls_conf {
            None => SdpSecurityModel::NONE,
            Some(_) => SdpSecurityModel::TLS,
        };

        // Create SDP sock (both client & server)
        let sdp_sock = SdpServer::new("sdp-client", config.ip6_iface, config.sdp_port)?;

        // build multicast ip6 addr for iface/scope
        let scope = get_iface_addrs(config.ip6_iface, config.ip6_prefix)?.get_scope();
        let multicast6 = SockAddrV6::new(&IPV6_ANY, config.sdp_port, scope);
        let spd_fd = sdp_sock.get_sockfd();

        // reserve timeout job control
        let job_post = AfbSchedJob::new("iso2-timeout-job")
            .set_exec_watchdog(300) // limit exec time to 100ms;
            .set_callback(jobpost_callback)
            .finalize();

        // create a dummy dataset waitng for SDP to complete
        let data_set = ControllerState {
            connection: Box::new(EmptyNetConnection {}),
            pending: None,
        };

        let controller = Box::leak(Box::new(Self {
            initialized: Arc::new((Mutex::new(false), Condvar::new())),
            tls_conf: config.tls_conf,
            stream: ExiStream::new(),
            session: SessionId::new(&session_u8, len as u16),
            data_set: Mutex::new(data_set),
            sdp_sock,
            scope,
            job_post,
        }));

        // Map SDP receive message to callback
        AfbEvtFd::new("sdp_async_cb")
            .set_fd(spd_fd)
            .set_events(AfbEvtFdPoll::IN)
            .set_callback(async_sdp_cb)
            .set_context(AsyncSdpCtx { controller })
            .start()?;

        // encode and send SDP message as UDP ip6 multicast
        let payload = SdpRequest::new(SdpTransportProtocol::TCP, security).encode()?;
        controller.sdp_sock.send_buffer_to(&payload, &multicast6)?;

        Ok(controller)
    }

    #[track_caller]
    pub fn lock_state(&self) -> Result<MutexGuard<'_, ControllerState>, AfbError> {
        let lock= self.data_set.lock().unwrap();
        Ok(lock)
    }

    pub fn send_payload(
        &self,
        afb_rqt: &AfbRequest,
        msg_id: MessageTagId,
        api_params: JsoncObj,
        timeout: i64,
    ) -> Result<(), AfbError> {

        // if controller not initialized wait
        let (lock, cvar) = &*self.initialized;
        let mut started = lock.lock().unwrap();
        let mut idx=0;
        loop {
            let result= cvar.wait_timeout(started, Duration::from_millis(SDP_INIT_TIMEOUT)).unwrap();
            started = result.0;
            if *started == true {
                break
            }
            idx += 1;
            afb_log_msg!(Notice,afb_rqt,"iso2-controller-start[{}] waiting for SDP message", idx);

            if idx == SDP_INIT_TRY {
                return afb_error!("iso2-controller-start", "Fail to receive ISO15118-SDP message")
            }
        }

        // controller is ready let's send messages
        let mut state = self.lock_state()?;

        // build exi payload from json
        let payload = body_from_json(msg_id.clone(), api_params)?;

        let mut stream = self.stream.lock_stream();
        Iso2MessageExi::encode_to_stream(&mut stream, &payload, &self.session)?;

        // if request expect a response let delay verb response
        let res_id = msg_id.match_res_id();
        if res_id != MessageTagId::Unsupported {
            // delay request response
            let afb_rqt = afb_rqt.add_ref();
            // arm a watchdog before sending request
            let job_id = self
                .job_post
                .post(timeout, JobPostData { afb_rqt: afb_rqt })?;

            state.pending = Some(ControllerPending {
                msg_id: res_id,
                afb_rqt,
                job_id,
            });
        } else {
            state.pending = None;
            afb_rqt.reply(AFB_NO_DATA, 0);
        };

        // send data
        state.connection.put_data(stream.get_buffer())?;

        Ok(())
    }

    pub fn decode_payload(&self, len: u32) -> Result<(), AfbError> {
        // we got message let's lock stream and process it
        let lock = self.stream.lock_stream();
        self.stream.finalize(&lock, len)?;

        // extract message payload and tagid
        let message = Iso2Payload::decode(&lock)?;
        let payload = message.get_payload();
        let tag_id = payload.get_tagid();

        // if we get expected message cleanup pending and watchdog
        let mut state = self.lock_state()?;

        match &state.pending {
            None => {
                return afb_error!(
                    "iso2-decode-payload",
                    "unexpected message:{:?}",
                    tag_id.to_json()
                )
            }
            Some(pending) => {
                if tag_id == pending.msg_id {
                    return afb_error!(
                        "iso2-decode-payload",
                        "unexpected message got :{:?} waiting{:?}",
                        tag_id.to_json(),
                        pending.msg_id.clone().to_json()
                    );
                }

                // respond & cleanup pending message & watchdog
                let request = AfbRequest::from_raw(pending.afb_rqt);
                self.job_post.abort(pending.job_id)?;

                let response = body_to_json(payload)?;
                request.reply(response, 0);
            }
        };
        state.pending = None;

        Ok(())
    }
}
