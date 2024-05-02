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
use iso15118::prelude::v2g::*;
use nettls::prelude::*;

pub struct BindingConfig {
    pub timeout: i64,
    pub jverbs: JsoncObj,
    pub ip6_iface: &'static str,
    pub ip6_prefix: u16,
    pub sdp_port: u16,
    pub sdp_security: SdpSecurityModel,
}

// Binding init callback started at binding load time before any API exist
// -----------------------------------------
pub fn binding_init(rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    afb_log_msg!(Info, rootv4, "config:{}", jconf);

    let uid = jconf.default("uid", "iso15118-2")?;
    let api = jconf.default("api", "iso-2")?;
    let info = jconf.default("info", "iso15118-2 json API")?;

    let sdp_port = jconf.default("sdp_port", 15118)?;
    let ip6_prefix = jconf.default("ip6_prefix", 0xFE80)?;
    let ip6_iface = jconf.default("iface", "lo")?;
    let session_id = jconf.default("session", "[01,02,03,04,05,06]")?;
    let timeout = jconf.default("timeout", 1000)?;

    let tls_conf = if let Some(jtls) = jconf.optional::<JsoncObj>("tsl")? {
        let cert_chain = jtls.get("certs")?;
        let priv_key = jtls.get("key")?;
        let pin_key = jtls.optional("pin")?;
        let tls_psk = jtls.optional("pks")?;
        let tls_trust = jtls.optional("trust")?;
        let tls_verbosity = jtls.default("verbosity", 1)?;
        let tls_proto = jtls.optional("proto")?;
        let psk_log = jtls.optional("psk_log")?;

        Some(TlsConfig::new(
            cert_chain,
            priv_key,
            pin_key,
            tls_trust,
            tls_psk,
            psk_log,
            tls_verbosity,
            tls_proto,
        )?)
    } else {
        None
    };

    let jverbs = jconf.get::<JsoncObj>("verbs")?;
    if !jverbs.is_type(Jtype::Array) {
        return afb_error!(
            "iso2-binding-config",
            "verbs should be a valid array of iso messages"
        );
    }

    let sdp_security = match &tls_conf {
        None => SdpSecurityModel::NONE,
        Some(_) => SdpSecurityModel::TLS,
    };

    // Register ctrl
    let controller_config = ControllerConfig {
        tls_conf,
        session_id,
    };
    let ctrl = Controller::new(controller_config)?;

    // send SDP multicast packet

    let binding_config = BindingConfig {
        ip6_iface,
        ip6_prefix,
        sdp_port,
        sdp_security,
        timeout,
        jverbs,
    };
    // create an register frontend api and register init session callback
    let api = AfbApi::new(uid)
        .set_name(api)
        .set_info(info)
        ;

    // create verbs
    register_verbs(api, binding_config, ctrl)?;

    // if acls set apply them
    if let Some(value) = jconf.optional::<&str>("permission")? {
        api.set_permission(AfbPermission::new(value));
    };

    if let Some(value) = jconf.optional("verbosity")? {
        api.set_verbosity(value);
    };

    Ok(api.finalize()?)
}

// register binding within libafb
AfbBindingRegister!(binding_init);
