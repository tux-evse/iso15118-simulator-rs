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
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::{mem, net};

pub const SDP_INIT_TIMEOUT: u64 = 3000;
pub const SDP_INIT_TRY: u64 = 10;
pub struct ControllerPending {
    afb_rqt: AfbRequest,
    msg_id: MessageTagId,
    job_id: i32,
}

pub struct JobPostData {
    afb_rqt: AfbRequest,
}

pub struct ControllerState {
    pub connection: Option<Box<dyn NetConnection>>,
    pub pending: Option<ControllerPending>,
}

struct AsyncTcpClientCtx {
    ctrl: &'static Controller,
    data_len: u32,
    payload_len: u32,
}

// New TCP client connecting
fn async_tcp_client_cb(_evtfd: &AfbEvtFd, revent: u32, context: &AfbCtxData) -> Result<(), AfbError> {

    // get verb user data context
    let ctx = context.get_mut::<AsyncTcpClientCtx>()?;

    // read is the only accepted operation
    if revent != AfbEvtFdPoll::IN.bits() {
        context.free::<AsyncTcpClientCtx>();
        return Ok(());
    }


    // move tcp socket data into exi stream buffer
    let mut lock = ctx.ctrl.stream.lock_stream();
    let state = ctx.ctrl.lock_state()?;

    let cnx = state.connection.as_ref().unwrap();

    let read_count = {
        let (stream_idx, stream_available) = ctx.ctrl.stream.get_index(&lock);

        let read_count = if stream_available == 0 {
            afb_log_msg!(
                Notice,
                None,
                "async_tcp_client {:?}, buffer full close session",
                cnx.get_source()
            );
            cnx.close()?;
            return Ok(());
        } else {
            let buffer = &mut lock.buffer[stream_idx..];
            cnx.get_data(buffer)?
        };

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            ctx.payload_len = ctx.ctrl.stream.header_check(&lock)?;
            ctx.data_len = 0;
        }
        read_count
    };

    // if data send in chunks let's complete exi buffer before processing it
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len == ctx.payload_len {
        // decode request and encode response
        ctx.ctrl.decode_payload(ctx.data_len)?;
    }

    Ok(())
}


pub struct AsyncSdpCtx {
    pub ctrl: &'static Controller,
    pub sdp_svc: SdpServer,
    pub sdp_scope: u32,
}

// async function receive SDP server ipv6 addr::port for iso15118 services
pub fn async_sdp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(Warning, None, "Unexpected SDP async event");
        return Ok(());
    }

    // if data_set already defined let ignore incoming SDP response
    let ctx = ctx.get_ref::<AsyncSdpCtx>()?;

    // get SDP/UDP packet
    let mut buffer = [0 as u8; mem::size_of::<SdpResponseBuffer>()];
    ctx.sdp_svc.read_buffer(&mut buffer)?;

    // lock connection state
    let mut state = ctx.ctrl.lock_state()?;
    if let Some(_) = state.connection {
        afb_log_msg!(
            Notice,
            None,
            "Ignoring SDP connection already defined",
        );
        return Ok(());
    }

    let response = SdpResponse::decode(&buffer)?;
    match response.check_header() {
        Ok(_) => {}
        Err(error) => {
            afb_log_msg!(
                Debug,
                None,
                "iso2-sdp-async: {}",
                error.get_info()
            );
            return Ok(());
        }
    }

    let transport= match response.get_transport() {
        SdpTransportProtocol::TCP => "tcp",
        _ => {
            afb_log_msg!(Critical, None, "UDP transport not supported");
            return Ok(());
        }
    };

    // extract port and server ip from response and build corresponding ip6 addr
    let svc_port = response.get_port();
    let svc_addr = response.get_addr6();
    let remote6 = net::Ipv6Addr::from(svc_addr);

    let security= match response.get_security() {
        SdpSecurityModel::TLS =>  "tls",
        SdpSecurityModel::NONE => "none",
    };

    afb_log_msg!(
                Notice,
                None,
                "iso2-sdp-async: {}({})://{:?}:{}",
                transport, security, svc_addr,  svc_port
            );

    let connection: Box<dyn NetConnection> = match response.get_security() {
        SdpSecurityModel::TLS => match &ctx.ctrl.tls_conf {
            None => {
                afb_log_msg!(Critical, None, "TLS request but not configured");
                return Ok(());
            }
            Some(config) => {
                let tcp_client = TcpClient::new(remote6, svc_port, ctx.sdp_scope)?;
                let tls_client = TlsConnection::new(config, tcp_client)?;
                Box::new(tls_client)
            }
        },
        SdpSecurityModel::NONE => {
            if let Some(_) = ctx.ctrl.tls_conf {
                afb_log_msg!(Warning, None, "TLS configured but not refused by server");
            }

            // connect TCL client to server
            let tcp_client = TcpClient::new(remote6, svc_port, ctx.sdp_scope)?;

            // register asynchronous tcp callback
            AfbEvtFd::new("iso2-tcp-client")
                .set_fd(tcp_client.get_sockfd()?)
                .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
                .set_autounref(true)
                .set_callback(async_tcp_client_cb)
                .set_context(AsyncTcpClientCtx {
                    ctrl: ctx.ctrl,
                    data_len: 0,
                    payload_len: 0,
                })
                .start()?;

            Box::new(tcp_client)
        }
    };


    // update TCP/TLS client connection
    state.connection= Some(connection);

    // unlock ctrl
    let (lock, cvar) = &*ctx.ctrl.initialized;
    let mut started = lock.lock().unwrap();
    *started = true;
    cvar.notify_one();

    Ok(())
}

// this callback starts from AfbSchedJob::new. If signal!=0 then callback overpass its watchdog timeout
fn jobpost_callback(
    _job: &AfbSchedJob,
    signal: i32,
    data: &AfbCtxData,
    _ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    // retrieve job post arguments
    let param = data.get_ref::<JobPostData>()?;

    if signal != 0 {
    // job post was cancelled
        param.afb_rqt.un_ref();
    } else {
        param.afb_rqt.reply(AFB_NO_DATA, -110); // timeout
    }

    Ok(())
}

pub struct Controller {
    pub initialized: Arc<(Mutex<bool>, Condvar)>,
    pub data_set: Mutex<ControllerState>,
    pub stream: ExiStream,
    pub session: SessionId,
    pub tls_conf: Option<&'static TlsConfig>,
    pub job_post: &'static AfbSchedJob,
}

pub struct ControllerConfig {
    pub tls_conf: Option<&'static TlsConfig>,
    pub session_id: &'static str,
}

impl Controller {
    pub fn new(config: ControllerConfig) -> Result<&'static Self, AfbError> {
        // create a fake session id
        let mut session_u8 = [0; 8];
        let len = hexa_to_byte(config.session_id, &mut session_u8)?;


        // reserve timeout job ctx
        let job_post = AfbSchedJob::new("iso2-timeout-job")
            .set_exec_watchdog(300) // limit exec time to 100ms;
            .set_callback(jobpost_callback)
            .finalize();

        let state=ControllerState{connection: None, pending: None};

        let ctrl = Box::leak(Box::new(Self {
            initialized: Arc::new((Mutex::new(false), Condvar::new())),
            tls_conf: config.tls_conf,
            stream: ExiStream::new(),
            session: SessionId::new(&session_u8, len as u16),
            data_set: Mutex::new(state),
            job_post,
        }));

        Ok(ctrl)
    }

    #[track_caller]
    pub fn lock_state(&self) -> Result<MutexGuard<'_, ControllerState>, AfbError> {
        Ok(self.data_set.lock().unwrap())
    }

    pub fn send_payload(
        &self,
        afb_rqt: &AfbRequest,
        msg_id: MessageTagId,
        api_params: JsoncObj,
        timeout: i64,
    ) -> Result<(), AfbError> {

        // ctrl is ready let's send messages
        let mut state = self.lock_state()?;

        // build exi payload from json
        let payload = body_from_json(msg_id.clone(), api_params)?;

        let mut stream = self.stream.lock_stream();
        Iso2MessageExi::encode_to_stream(&mut stream, &payload, &self.session)?;

        // if request expect a response let delay verb response
        let res_id = msg_id.match_res_id();
        if res_id != MessageTagId::Unsupported {
            // arm a watchdog before sending request
            let job_id = self
                .job_post
                .post(timeout, JobPostData { afb_rqt: afb_rqt.add_ref() })?;

            state.pending = Some(ControllerPending {
                msg_id: res_id,
                afb_rqt: afb_rqt.add_ref(),
                job_id,
            });
        } else {
            state.pending = None;
            afb_rqt.reply(AFB_NO_DATA, 0);
        };

        // send data
        let cnx= state.connection.as_ref().unwrap();
        cnx.put_data(stream.get_buffer())?;

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
                self.job_post.abort(pending.job_id)?;

                let response = body_to_json(payload)?;
                pending.afb_rqt.reply(response, 0);
            }
        };
        state.pending = None;

        Ok(())
    }
}
