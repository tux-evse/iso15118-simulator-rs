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

use afbv4::prelude::*;
use iso15118::prelude::*;
use iso15118_exi::prelude::*;
use iso15118_jsonc::prelude::*;

use nettls::prelude::*;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::{mem, net};

pub const SDP_INIT_TIMEOUT: u64 = 3000;
pub const SDP_INIT_TRY: u64 = 10;

pub struct IsoMsgReqCtx {
    pub ctrl: &'static EvccController,
    pub protocol: v2g::ProtocolTagId,
    pub msg_name: &'static str,
    pub msg_id: u32,
    pub timeout: i64,
    pub signed: bool,
}

pub struct EvccState {
    pub connection: Option<Box<dyn NetConnection>>,
    pub session: IsoSessionState,
}

struct AsyncTlsClientCtx {
    ctrl: &'static EvccController,
}
impl Drop for AsyncTlsClientCtx {
    fn drop(&mut self) {
        self.ctrl.reset().unwrap();
    }
}

fn async_tls_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    // get verb user data context
    let ctx = context.get_mut::<AsyncTlsClientCtx>()?;
    let mut state = ctx.ctrl.lock_state()?;
    let sock = match &state.connection {
        None => return afb_error!("async-tls-client", "no state connection"),
        Some(value) => value.as_ref(),
    };

    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(
            Notice,
            None,
            "async-tls-client: closing tls client:{}",
            sock.get_source()
        );
        context.free::<AsyncTlsClientCtx>();
        return Ok(());
    }

    ctx.ctrl.exi_message_in(&mut state)?;

    Ok(())
}

struct AsyncTcpClientCtx {
    ctrl: &'static EvccController,
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
    // get verb user data context
    let ctx = context.get_mut::<AsyncTcpClientCtx>()?;
    let mut state = ctx.ctrl.lock_state()?;
    let sock = match &state.connection {
        None => return afb_error!("async-tls-client", "no state connection"),
        Some(value) => value.as_ref(),
    };

    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(
            Notice,
            None,
            "async-tcp-client: closing tcp client:{}",
            sock.get_source()
        );
        context.free::<AsyncTcpClientCtx>();
        return Ok(());
    }

    ctx.ctrl.exi_message_in(&mut state)?;
    Ok(())
}

pub struct AsyncSdpCtx {
    pub ctrl: &'static EvccController,
    pub sdp_svc: SdpServer,
    pub sdp_scope: u32,
}

// async function receive SDP server ipv6 addr::port for iso15118 services
pub fn async_sdp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    use v2g::*;

    if revent != AfbEvtFdPoll::IN.bits() {
        afb_log_msg!(Warning, None, "Unexpected SDP async event");
        return Ok(());
    }

    // if session already defined let ignore incoming SDP response
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
        "v2g-sdp-async: {}[{}]://{:02x?}:{}",
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
                let tcp_client = TcpConnection::new(remote6, svc_port, ctx.sdp_scope)?;
                let tls_client = TlsConnection::new(config, tcp_client, TlsConnectionFlag::Client)?;

                AfbEvtFd::new("tls-client")
                    .set_fd(tls_client.get_sockfd()?)
                    .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
                    .set_autounref(true)
                    .set_callback(async_tls_client_cb)
                    .set_context(AsyncTlsClientCtx { ctrl: ctx.ctrl })
                    .start()?;
                Box::new(tls_client)
            }
        },
        SdpSecurityModel::NONE => {
            if let Some(_) = ctx.ctrl.tls_conf {
                afb_log_msg!(Warning, None, "TLS configured but not refused by server");
            }

            // connect TCP client to server
            let tcp_client = TcpConnection::new(remote6, svc_port, ctx.sdp_scope)?;

            // register asynchronous tcp callback
            AfbEvtFd::new("v2g-tcp-client")
                .set_fd(tcp_client.get_sockfd()?)
                .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
                .set_callback(async_tcp_client_cb)
                .set_context(AsyncTcpClientCtx { ctrl: ctx.ctrl })
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
    ctx.sdp_svc.close();
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
    let pending = data.get_ref::<IsoPendingState>()?;

    if signal != 0 {
        pending.afb_rqt.un_ref(); // job ended drop afb_rqt
    } else {
        pending.afb_rqt.reply(
            format!("timeout msg:{:?} (no response from EVSE)", pending.msg_id),
            -100,
        );
    }
    Ok(())
}

pub struct EvccController {
    pub initialized: Arc<(Mutex<bool>, Condvar)>,
    pub state: Mutex<EvccState>,
    pub network: IsoNetConfig,
    pub session_id: Vec<u8>,
    pub tls_conf: Option<&'static TlsConfig>,
    pub job_post: &'static AfbSchedJob,
}

pub struct ControllerConfig {
    pub tls_conf: Option<&'static TlsConfig>,
    pub pki_conf: Option<&'static PkiConfig>,
    pub session_id: &'static str,
}

impl EvccController {
    pub fn new(config: ControllerConfig) -> Result<&'static Self, AfbError> {
        // create a fake session id
        let mut session_u8 = [0; 8];
        let session = hexa_to_bytes(config.session_id, &mut session_u8)?;

        // reserve timeout job ctx
        let job_post = AfbSchedJob::new("iso2-timeout-job")
            .set_exec_watchdog(1) // one second max
            .set_callback(job_timeout_cb)
            .finalize();

        let state = EvccState {
            connection: None,
            session: IsoSessionState {
                pending: None,
                protocol: v2g::ProtocolTagId::Unknown,
                session_id: Vec::new(),
                challenge: Vec::new(),
                public_key: None,
            },
        };

        let ctrl = Box::leak(Box::new(Self {
            initialized: Arc::new((Mutex::new(false), Condvar::new())),
            network: IsoNetConfig {
                pki_conf: config.pki_conf,
                stream: ExiStream::new(),
            },
            tls_conf: config.tls_conf,
            session_id: session.to_vec(),
            state: Mutex::new(state),
            job_post,
        }));

        Ok(ctrl)
    }

    #[track_caller]
    pub fn lock_state(&self) -> Result<MutexGuard<'_, EvccState>, AfbError> {
        Ok(self.state.lock().unwrap())
    }

    pub fn v2g_send_payload(
        &self,
        afb_rqt: &AfbRequest,
        ctx: &IsoMsgReqCtx,
        v2g_body: &v2g::V2gAppHandDoc,
    ) -> Result<(), AfbError> {
        use v2g::*;

        // ctrl is ready let's send messages
        let mut state = self.lock_state()?;
        if let None = state.connection {
            return afb_error!("v2g_send_payload", "SDP iso15118 require");
        }

        // in simulation mode V2G does not expect any response
        let mut stream = self.network.stream.lock_stream();
        SupportedAppProtocolExi::encode_to_stream(&mut stream, &v2g_body)?;

        // send data &wipe stream
        let cnx = state.connection.as_ref().unwrap();
        cnx.put_data(stream.get_buffer())?;
        stream.reset();

        // wait for response
        let job_id = self.job_post.post(
            ctx.timeout, // default 1000s
            IsoPendingState {
                afb_rqt: afb_rqt.add_ref(),
                msg_id: IsoMsgResId::None,
                job_id: 0,
            },
        )?;

        // update state to pending
        state.session.pending = Some(IsoPendingState {
            msg_id: IsoMsgResId::None,
            afb_rqt: afb_rqt.add_ref(),
            job_id,
        });

        Ok(())
    }

    // wipe controller context (stream, lock, ...)
    pub fn reset(&self) -> Result<(), AfbError> {
        let mut state = self.lock_state()?;
        let mut lock = self.network.stream.lock_stream();
        lock.reset();
        state.connection = None;
        state.session.protocol = v2g::ProtocolTagId::Unknown;
        let (lock, _cvar) = &*self.initialized;
        let mut started = lock.lock().unwrap();
        *started = false;
        Ok(())
    }

    // process incoming iso_msg.res received after sending iso_msg.req
    pub fn exi_message_in(&self, state: &mut MutexGuard<EvccState>) -> Result<(), AfbError> {
        let sock = match &state.connection {
            None => return afb_error!("exi-message-in", "Hoop connection drop"),
            Some(value) => value.as_ref(),
        };

        // wait until we get a complete exi message from socket
        match self.network.rec_exi_message(sock)? {
            IsoStreamStatus::Complete => {}
            IsoStreamStatus::Incomplete => return Ok(()),
        }

        // try to decode message depending on session protocol
        let iso_body = self.network.decode_from_stream(&mut state.session)?;

        if !self
            .network
            .check_msg_id(&iso_body, &state.session.pending)?
        {
            afb_log_msg!(
                Notice,
                None,
                "Received {} message while pending=None",
                &state.session.protocol
            );
            return Ok(());
        }

        // parse to jsonc received message
        let jbody = match iso_body {
            IsoMsgBody::Sdp(schema) => {
                state.session.protocol= schema; // update schema to received schema
                schema.to_jsonc()?
            },
            IsoMsgBody::Din(body) => din_jsonc::body_to_jsonc(&body)?,
            IsoMsgBody::Iso2(body) => iso2_jsonc::body_to_jsonc(&body)?,
        };

        // if pending message waiting let's respond other wise ignore
        if let Some(pending) = &state.session.pending {
            pending.afb_rqt.reply(jbody, 0);
            self.job_post.abort(pending.job_id)?;
            state.session.pending = None;
        }

        Ok(())
    }

    // send command and if needed arm a job
    pub fn exi_message_out(
        &self,
        afb_rqt: &AfbRequest,
        ctx: &IsoMsgReqCtx,
        jbody: JsoncObj,
    ) -> Result<(), AfbError> {
        let mut state = self.lock_state()?;

        // check connection is defined without borrow
        let sock = match &state.connection {
            None => return afb_error!("exi-message-out", "Hoop connection drop"),
            Some(value) => value.as_ref(),
        };

        // send message
        let res_id = self
            .network
            .send_exi_message(sock, &state.session, ctx.msg_id, jbody)?;

        // if needed arm a timer
        if res_id != IsoMsgResId::None {
            // arm timeout watchdog
            let job_id = self.job_post.post(
                ctx.timeout,
                IsoPendingState {
                    afb_rqt: afb_rqt.add_ref(),
                    msg_id: res_id,
                    job_id: 0,
                },
            )?;

            // update state to pending
            state.session.pending = Some(IsoPendingState {
                msg_id: res_id,
                afb_rqt: afb_rqt.add_ref(),
                job_id,
            });
        } else {
            afb_rqt.reply(AFB_NO_DATA, 0);
        }
        Ok(())
    }
}
