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
use iso15118::prelude::{v2g::*, *};
use nettls::prelude::*;
use std::str;

use std::mem;

pub struct AsyncSdpCtx {
    pub sdp: SdpServer,
    pub tcp_port: u16,
    pub tls_port: u16,
    pub sdp_addr6: IfaceAddr6,
}

#[track_caller]
fn _buffer_to_str(buffer: &[u8]) -> Result<&str, AfbError> {
    let text = match std::str::from_utf8(buffer) {
        Ok(value) => value,
        Err(_) => return afb_error!("buffer-to_str", "fail UTF8 conversion"),
    };
    Ok(text)
}

pub fn async_sdp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncSdpCtx>()?;
    if revent == AfbEvtFdPoll::IN.bits() {
        // get SDP/UDP packet
        let mut buffer = [0 as u8; mem::size_of::<SdpRequestBuffer>()];
        ctx.sdp.read_buffer(&mut buffer)?;

        let request = SdpRequest::decode(&buffer)?;
        request.check_header()?;

        let transport = request.get_transport();
        let security = request.get_security();

        let port = match &security {
            SdpSecurityModel::TLS => ctx.tls_port,
            SdpSecurityModel::NONE => ctx.tcp_port,
        };

        match &transport {
            SdpTransportProtocol::TCP => {}
            SdpTransportProtocol::UDP => {
                return afb_error!("sdp-request-udp", "currently not supported")
            }
        }

        afb_log_msg!(
            Debug,
            None,
            "Respond sdp {:?}:{:?}:[{:?}]:{}",
            &transport,
            &security,
            &ctx.sdp_addr6.addr,
            port
        );
        let response =
            SdpResponse::new(ctx.sdp_addr6.get_addr().octets(), port, transport, security)
                .encode()?;
        ctx.sdp.send_buffer(&response)?;
    }
    Ok(())
}

struct AsyncTcpClientCtx {
    sock: TcpConnection,
    ctrl: ControllerEvse,
}

impl Drop for AsyncTcpClientCtx {
    fn drop(&mut self) {
        afb_log_msg!(
            Debug,
            None,
            "async-tcp-client: closing tcp:{}",
            self.sock.get_source()
        );
        self.ctrl.network.stream.drop();
    }
}

// New TCP client connecting
fn async_tcp_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = context.get_mut::<AsyncTcpClientCtx>()?;

    if revent != AfbEvtFdPoll::IN.bits() {
        context.free::<AsyncTcpClientCtx>();
        return Ok(());
    }

    ctx.ctrl.process_exi_message(&ctx.sock)
}

struct AsyncTlsClientCtx {
    sock: TlsConnection,
    ctrl: ControllerEvse,
}

impl Drop for AsyncTlsClientCtx {
    fn drop(&mut self) {
        afb_log_msg!(
            Debug,
            None,
            "async-tls-client: closing tcp:{}",
            self.sock.get_source()
        );
        self.ctrl.network.stream.drop();
    }
}

// New TLS client connecting
fn async_tls_client_cb(
    _evtfd: &AfbEvtFd,
    revent: u32,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = context.get_mut::<AsyncTlsClientCtx>()?;
    if revent != AfbEvtFdPoll::IN.bits() {
        context.free::<AsyncTlsClientCtx>();
        return Ok(());
    }

    ctx.ctrl.process_exi_message(&ctx.sock)
}

pub struct AsyncTcpCtx {
    pub apiv4: AfbApiV4,
    pub sock: TcpServer,
    pub responder: ResponderConfig,
    pub pki: Option<&'static PkiConfig>,
}
// New TCP client connecting
pub fn async_tcp_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncTcpCtx>()?;
    if revent == AfbEvtFdPoll::IN.bits() {
        let tcp_client = ctx.sock.accept_client()?;

        AfbEvtFd::new("tcp-client")
            .set_fd(tcp_client.get_sockfd()?)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(async_tcp_client_cb)
            .set_context(AsyncTcpClientCtx {
                sock: tcp_client,
                ctrl: ControllerEvse::new(ctx.pki, ctx.apiv4, ctx.responder),
            })
            .start()?;
    }
    Ok(())
}

pub struct AsyncTlsCtx {
    pub apiv4: AfbApiV4,
    pub sock: TcpServer,
    pub responder: ResponderConfig,
    pub tls_conf: &'static TlsConfig,
    pub pki_conf: Option<&'static PkiConfig>,
}
// New TLS sock
pub fn async_tls_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncTlsCtx>()?;
    if revent == AfbEvtFdPoll::IN.bits() {
        let tls_client = ctx.sock.accept_client()?;
        let source = tls_client.get_source();
        let sockfd = tls_client.get_sockfd()?;

        let tls_connection =
            TlsConnection::new(ctx.tls_conf, tls_client, TlsConnectionFlag::Server)?;

        afb_log_msg!(
            Notice,
            None,
            "New sock client:{} protocol:{}",
            source,
            tls_connection.get_version().to_string()
        );

        AfbEvtFd::new("tls-client")
            .set_fd(sockfd)
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(async_tls_client_cb)
            .set_context(AsyncTlsClientCtx {
                sock: tls_connection,
                ctrl: ControllerEvse::new(ctx.pki_conf, ctx.apiv4, ctx.responder),
            })
            .start()?;
    }
    Ok(())
}

fn scanifv6_callback(
    request: &AfbRequest,
    args: &AfbRqtData,
    _ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let iface = args.get::<String>(0)?;
    let addr = get_iface_addrs(&iface, 0xfe80)?;

    println!(
        "iface:{} addr6:{} scope6:{}",
        iface,
        addr.get_addr().to_string(),
        addr.get_scope()
    );
    request.reply(AFB_NO_DATA, 0);
    Ok(())
}
pub(crate) fn register_verbs(api: &mut AfbApi, _config: &BindingConfig) -> Result<(), AfbError> {
    let scanifv6 = AfbVerb::new("scan-iface")
        .set_callback(scanifv6_callback)
        .set_info("scan ipv6 interface return attached ipv6 addr")
        .finalize()?;

    api.add_verb(scanifv6);
    Ok(())
}
