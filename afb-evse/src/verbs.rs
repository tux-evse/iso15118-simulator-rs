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
use iso15118_jsonc::prelude::*;
use nettls::prelude::*;
use std::str;
//use typesv4::prelude::*;

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

fn process_exi_message(ctx: &mut AsyncShareClientCtx, sock: &dyn NetConnection) -> Result<(), AfbError> {
    // move tcp socket data into exi stream buffer
    let mut lock = ctx.stream.lock_stream();
    let read_count = {
        let (stream_idx, stream_available) = ctx.stream.get_index(&lock);
        let read_count = if stream_available == 0 {
            afb_log_msg!(
                Notice,
                None,
                "async_tls_client {:?}, buffer full close session",
                sock.get_source()
            );
            sock.close()?;
            return Ok(());
        } else {
            let buffer = &mut lock.buffer[stream_idx..];
            sock.get_data(buffer)?
        };

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            ctx.payload_len = ctx.stream.header_check(&lock, PayloadMsgId::SAP)?;
            ctx.data_len = 0;
        }

        // when facing a new exi check how much data should be read
        if stream_idx == 0 {
            let len = ctx.stream.get_payload_len(&lock);
            if len < 0 {
                afb_log_msg!(
                    Warning,
                    None,
                    "async_tls_client: packet ignored (invalid v2g header) size:{}",
                    read_count
                );
            } else {
                ctx.payload_len = len as u32;
            }
            ctx.data_len = 0;
        }
        read_count
    };

    // fix stream len for decoding
    ctx.data_len = ctx.data_len + read_count;
    if ctx.data_len == ctx.payload_len {
        // fix stream len for decoding
        ctx.stream.finalize(&lock, ctx.payload_len)?;

        // decode request and encode response
        let (tagid, jsonc) = match ctx.ctrl.decode_from_stream(&mut lock)? {
            IsoMsgBody::Din(body) => (body.get_tagid() as u32, din_jsonc::body_to_jsonc(&body)?),
            IsoMsgBody::Iso2(body) => (body.get_tagid() as u32, iso2_jsonc::body_to_jsonc(&body)?),
            IsoMsgBody::Sdp => return Ok(()),
        };

        // send request to responder and wait for jsonc reply to encode as response to iso15118
        let api_verb = format!("{}/{}", ctx.responder.prefix, jsonc.get::<&str>("verb")?);
        let response = AfbSubCall::call_sync(ctx.apiv4, ctx.responder.api, &api_verb, jsonc)?;

        // send response and wipe stream for next request
        ctx.ctrl
            .encode_to_stream(&mut lock, tagid, response.get(0)?)?;
        let response = ctx.stream.get_buffer(&lock);
        sock.put_data(response)?;
        ctx.stream.reset(&lock);
    }
    Ok(())
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
    client: AsyncShareClientCtx,
    sock: TcpClient,
}

impl Drop for AsyncTcpClientCtx {
    fn drop(&mut self) {
        afb_log_msg!(
            Debug,
            None,
            "async-tcp-client: closing tcp:{}",
            self.sock.get_source()
        );
        self.client.stream.drop();
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

    process_exi_message(&mut ctx.client, &ctx.sock)
}

struct AsyncShareClientCtx {
    apiv4: AfbApiV4,
    ctrl: Iso2Controller,
    stream: ExiStream,
    data_len: u32,
    payload_len: u32,
    responder: ResponderConfig,
}

struct AsyncTlsClientCtx {
    sock: TlsConnection,
    client: AsyncShareClientCtx,
}

impl Drop for AsyncTlsClientCtx {
    fn drop(&mut self) {
        afb_log_msg!(
            Debug,
            None,
            "async-tls-client: closing tcp:{}",
            self.sock.get_source()
        );
        self.client.stream.drop();
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

    process_exi_message(&mut ctx.client, &ctx.sock)
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
                client: AsyncShareClientCtx {
                    apiv4: ctx.apiv4,
                    data_len: 0,
                    payload_len: 0,
                    ctrl: Iso2Controller::new(ctx.pki),
                    stream: ExiStream::new(),
                    responder: ctx.responder,
                },
            })
            .start()?;
    }
    Ok(())
}

pub struct AsyncTlsCtx {
    pub apiv4: AfbApiV4,
    pub sock: TcpServer,
    pub config: &'static TlsConfig,
    pub responder: ResponderConfig,
    pub pki: Option<&'static PkiConfig>,
}
// New TLS sock
pub fn async_tls_cb(_evtfd: &AfbEvtFd, revent: u32, ctx: &AfbCtxData) -> Result<(), AfbError> {
    let ctx = ctx.get_ref::<AsyncTlsCtx>()?;
    if revent == AfbEvtFdPoll::IN.bits() {
        let tls_client = ctx.sock.accept_client()?;
        let source = tls_client.get_source();
        let sockfd = tls_client.get_sockfd()?;
        let tls_connection = TlsConnection::new(ctx.config, tls_client)?;
        tls_connection.client_handshake()?;

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
                client: AsyncShareClientCtx {
                    apiv4: ctx.apiv4,
                    data_len: 0,
                    payload_len: 0,
                    ctrl: Iso2Controller::new(ctx.pki),
                    stream: ExiStream::new(),
                    responder: ctx.responder,
                },
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
