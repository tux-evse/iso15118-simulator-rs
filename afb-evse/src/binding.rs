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
use nettls::prelude::*;

pub struct BindingConfig {}

#[derive(Clone, Copy)]
pub struct ResponderConfig {
    pub api: &'static str,
    pub prefix: &'static str,
}

struct ApiUserData {
    iface: &'static str,
    sdp_port: u16,
    tls_port: u16,
    tcp_port: u16,
    prefix: u16,
    tls_conf: Option<&'static TlsConfig>,
    responder_conf: ResponderConfig,
}
impl AfbApiControls for ApiUserData {
    // the API is created and ready. At this level user may subcall api(s) declare as dependencies
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(
            Notice,
            api,
            "iface:{} sdp:{} prefix:{:#0x}",
            self.iface,
            self.sdp_port,
            self.prefix
        );

        // get iface ipv6-addr matching prefix (local-link?)
        let sdp_addr6 = get_iface_addrs(&self.iface, self.prefix)?;

        // start TCP ws-server
        let tcp = TcpServer::new(api, "tcp-wserver", &sdp_addr6, self.tcp_port)?;
        AfbEvtFd::new(tcp.get_uid())
            .set_fd(tcp.get_sockfd())
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_callback(async_tcp_cb)
            .set_autounref(true)
            .set_context(AsyncTcpCtx {
                apiv4: api.get_apiv4(),
                sock: tcp,
                responder: self.responder_conf,
            })
            .start()?;

        if let Some(tls_conf) = self.tls_conf {
            // start TLS ws-server
            let tls = TcpServer::new(api, "tls-wserver", &sdp_addr6, self.tls_port)?;
            AfbEvtFd::new(tls.get_uid())
                .set_fd(tls.get_sockfd())
                .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
                .set_autounref(true)
                .set_callback(async_tls_cb)
                .set_context(AsyncTlsCtx {
                    apiv4: api.get_apiv4(),
                    sock: tls,
                    config: tls_conf,
                    responder: self.responder_conf,
                })
                .start()?;
        }

        // start SDP discovery service
        let sdp = SdpServer::new("sdp-server", self.iface, self.sdp_port)?;
        AfbEvtFd::new(sdp.get_uid())
            .set_fd(sdp.get_sockfd())
            .set_events(AfbEvtFdPoll::IN | AfbEvtFdPoll::RUP)
            .set_autounref(true)
            .set_callback(async_sdp_cb)
            .set_context(AsyncSdpCtx {
                sdp,
                sdp_addr6,
                tcp_port: self.tcp_port,
                tls_port: self.tls_port,
            })
            .start()?;
        Ok(())
    }

    // mandatory unsed declaration
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// Binding init callback started at binding load time before any API exist
// -----------------------------------------
pub fn binding_init(_rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    //afb_log_msg!(Info, rootv4, "config:{}", jconf);

    let uid = jconf.default("uid", "iso15118-16")?;
    let api = jconf.default("api", uid)?;
    let info = jconf.default("info", "")?;
    let iface = jconf.default("iface", "lo")?;
    let prefix = jconf.default("ip6_prefix", 0)?;
    let sdp_port = jconf.default("sdp_port", 15118)?;
    let tcp_port = jconf.default("tcp_port", 61341)?;

    let responder_conf = ResponderConfig {
        api: jconf.default("responder", "responder")?,
        prefix: jconf.default("scenario", "scenario-1")?,
    };

    let (tls_conf, tls_port) = match jconf.optional::<JsoncObj>("tls")? {
        None => (None, 0),
        Some(jtls) => {
            (
                Some(TlsConfig::from_jsonc(jtls.clone())?),
                jtls.default("port", 64109)?,
            )
        }
    };

    // create an register frontend api and register init session callback
    let api = AfbApi::new(api)
        .set_info(info)
        .set_callback(Box::new(ApiUserData {
            iface,
            prefix,
            sdp_port,
            tcp_port,
            tls_port,
            tls_conf,
            responder_conf,
        }));

    // create verbs
    let config = BindingConfig {};
    register_verbs(api, &config)?;

    // if acls set apply them
    if let Ok(value) = jconf.get::<&'static str>("permission") {
        api.set_permission(AfbPermission::new(value));
    };

    if let Ok(value) = jconf.get("verbosity") {
        api.set_verbosity(value);
    };

    Ok(api.finalize()?)
}

// register binding within libafb
AfbBindingRegister!(binding_init);
