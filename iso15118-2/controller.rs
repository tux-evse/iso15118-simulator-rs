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
use iso15118::prelude::{iso2::*, v2g::*, *};
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
    uid: &'static str,
    afb_rqt: AfbRequest,
}

pub struct ControllerState {
    pub connection: Option<Box<dyn NetConnection>>,
    pub pending: Option<ControllerPending>,
    pub protocol: v2g::ProtocolTagId,
}

struct AsyncTcpClientCtx {
    ctrl: &'static Controller,
    data_len: u32,
    payload_len: u32,
}

impl Drop for AsyncTcpClientCtx {
    fn drop(&mut self) {
        self.ctrl.reset().unwrap();
    }
}

// New TCP client connecting
fn async_tcp_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    // read is the only accepted operation
    if revent != AfbEvtFdPoll::IN.bits() {
        context.free::<AsyncTcpClientCtx>();
        return Ok(());
    }

    // get verb user data context
    let ctx = context.get_mut::<AsyncTcpClientCtx>()?;
    let state = ctx.ctrl.lock_state()?;
    let mut lock = ctx.ctrl.stream.lock_stream();

    // move tcp socket data into exi stream buffer
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
            let len = ctx.ctrl.stream.get_payload_len(&lock);
            if len < 0 {
                afb_log_msg!(
                    Warning,
                    None,
                    "async_tcp_client: packet ignored (invalid v2g header) size:{}",
                    read_count
                );
            } else {
                ctx.payload_len = len as u32;
            }
            ctx.data_len = 0;
        }
        read_count
    };

    // if data send in chunks let's complete exi buffer before processing it
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len >= ctx.payload_len + v2g::SDP_V2G_HEADER_LEN as u32 {
        // fix stream len for decoding
        ctx.ctrl.stream.finalize(&lock, ctx.payload_len)?;
        match ctx.ctrl.stream.get_payload_id(&lock) {
            // iso2 only use SAP payload-id
            PayloadMsgId::SAP => ctx.ctrl.iso_decode_payload(state, &mut lock)?,
            _ => {
                return afb_error!(
                    "async_tcp_client",
                    "Invalid message payload id:{:?}",
                    ctx.ctrl.stream.get_payload_id(&lock)
                )
            }
        }
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

    let response = SdpResponse::decode(&buffer)?;
    match response.check_header() {
        Ok(_) => {}
        Err(error) => {
            afb_log_msg!(Debug, None, "iso-sdp-async: {}", error.get_info());
            return Ok(());
        }
    }

    let transport = match response.get_transport() {
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

    let security = match response.get_security() {
        SdpSecurityModel::TLS => "tls",
        SdpSecurityModel::NONE => "none",
    };

    afb_log_msg!(
        Notice,
        None,
        "iso-sdp-async: {}({})://{:?}:{}",
        transport,
        security,
        svc_addr,
        svc_port
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
    state.connection = Some(connection);

    // unlock ctrl
    let (lock, cvar) = &*ctx.ctrl.initialized;
    let mut started = lock.lock().unwrap();
    *started = true;
    cvar.notify_one();

    Ok(())
}

// this callback starts from AfbSchedJob::new. If signal!=0 then callback overpass its watchdog timeout
fn job_timeout_cb(
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
        param.afb_rqt.reply(format!("timeout msg:{} (no response from EVSE)",param.uid), -100); // timeout
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
            .set_exec_watchdog(10000) // Fulup TBD limit exec time to 100ms not 10s;
            .set_callback(job_timeout_cb)
            .finalize();

        let state = ControllerState {
            protocol: v2g::ProtocolTagId::Unknown,
            connection: None,
            pending: None,
        };

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

    // wipe controller context (stream, lock, ...)
    pub fn reset(&self) -> Result<(), AfbError> {
        let mut state = self.lock_state()?;
        let lock = self.stream.lock_stream();
        lock.reset();
        state.connection = None;
        state.protocol= v2g::ProtocolTagId::Unknown;
        let (lock, _cvar) = &*self.initialized;
        let mut started = lock.lock().unwrap();
        *started = false;
        Ok(())
    }

    pub fn iso2_send_payload(
        &self,
        afb_rqt: &AfbRequest,
        ctx: &Iso2MsgReqCtx,
        api_params: JsoncObj,
    ) -> Result<(), AfbError> {
        // ctrl is ready let's send messages
        let mut state = self.lock_state()?;

        if let None = state.connection {
            return afb_error!("iso2_send_payload","SDP iso15118 require");
        }

        // build exi payload from json
        let payload = body_from_json(ctx.msg_id.clone(), api_params)?;

        let mut stream = self.stream.lock_stream();
        Iso2MessageExi::encode_to_stream(&mut stream, &payload, &self.session)?;

        // if request expect a response let delay verb response
        let res_id = ctx.msg_id.match_res_id();
        if res_id != MessageTagId::Unsupported {
            // arm a watchdog before sending request
            let job_id = self.job_post.post(
                ctx.timeout,
                JobPostData {
                    uid: ctx.uid,
                    afb_rqt: afb_rqt.add_ref(),
                },
            )?;

            state.pending = Some(ControllerPending {
                msg_id: res_id,
                afb_rqt: afb_rqt.add_ref(),
                job_id,
            });
        } else {
            state.pending = None;
            afb_rqt.reply("Warning: no response for this msg_id", 0);
            return Ok(());
        };

        // send data and wipe stream
        let cnx = state.connection.as_ref().unwrap();
        cnx.put_data(stream.get_buffer())?;
        stream.reset();
        Ok(())
    }

    pub fn v2g_send_payload(
        &self,
        afb_rqt: &AfbRequest,
        ctx: &Iso2MsgReqCtx,
        v2g_body: &V2gAppHandDoc,
    ) -> Result<(), AfbError> {
        // ctrl is ready let's send messages
        let mut state = self.lock_state()?;
        if let None = state.connection {
            return afb_error!("v2g_send_payload","SDP iso15118 require");
        }

        let mut stream = self.stream.lock_stream();
        SupportedAppProtocolExi::encode_to_stream(&mut stream, &v2g_body)?;

        // if request expect a response let delay verb response
        let res_id = ctx.msg_id.match_res_id();
        if res_id != MessageTagId::Unsupported {
            // arm a watchdog before sending request
            let job_id = self.job_post.post(
                ctx.timeout,
                JobPostData {
                    uid: ctx.uid,
                    afb_rqt: afb_rqt.add_ref(),
                },
            )?;

            state.pending = Some(ControllerPending {
                msg_id: res_id,
                afb_rqt: afb_rqt.add_ref(),
                job_id,
            });
        } else {
            state.pending = None;
            afb_rqt.reply(AFB_NO_DATA, 0);
        };

        // send data &wipe stream
        let cnx = state.connection.as_ref().unwrap();
        cnx.put_data(stream.get_buffer())?;
        stream.reset();

        Ok(())
    }

    pub fn iso_decode_payload(
        &self,
        mut state: MutexGuard<'_, ControllerState>,
        lock: &mut MutexGuard<RawStream>,
    ) -> Result<(), AfbError> {
        // if not waiting for a message let't ignore
        let msg_id = match &state.pending {
            None => {
                afb_log_msg!(
                    Notice,
                    None,
                    "Received {:?} message while pending=None",
                    state.protocol.clone()
                );
                return Ok(());
            }
            Some(pending) => pending.msg_id.clone(),
        };

        let response = match state.protocol.clone() {
            v2g::ProtocolTagId::Unknown => {
                let v2g_msg = SupportedAppProtocolExi::decode_from_stream(&lock)?;
                let app_protocol_res = match v2g_msg {
                    v2g::V2gMsgBody::Request(_) => {
                        return afb_error!(
                            "iso-app-protocol",
                            "expect 'AppHandSupportedAppProtocolRes' as initial request"
                        )
                    }
                    v2g::V2gMsgBody::Response(value) => value,
                };

                // retrieve chosen protocol by EVSE and use it until the end of the session
                let schema_id = app_protocol_res.get_schema();
                let protocol = SupportedAppProtocolConf::from_schema(
                    schema_id,
                    &V2G_PROTOCOLS_SUPPORTED_LIST,
                )?;
                state.protocol = protocol.get_schema();
                protocol.to_json()?
            }
            v2g::ProtocolTagId::Iso2 => {
                // extract message payload and tagid
                let message = Iso2Payload::decode_from_stream(&lock)?;
                let payload = message.get_payload();
                let tag_id = payload.get_tagid();
                if tag_id != msg_id {
                    return afb_error!(
                        "iso2-decode-payload",
                        "unexpected message got:{:?} waiting:{:?}",
                        tag_id.to_json(),
                        msg_id.clone().to_json()
                    );
                }
                body_to_json(payload)?.to_string()
            }
            _ => {
                return afb_error!(
                    "iso-decode-payload",
                    "unexpected iso protocol:{:?}",
                    &state.protocol
                )
            }
        };

        // respond & cleanup pending message & watchdog
        if let Some(pending) = &state.pending {
            pending.afb_rqt.reply(response, 0);
            self.job_post.abort(pending.job_id)?;
            state.pending = None;
        }
        Ok(())
    }
}
