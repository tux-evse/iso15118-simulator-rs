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
use iso15118::prelude::{*,v2g::*};
use nettls::prelude::*;

pub struct BindingConfig {
    pub jverbs: JsoncObj,
    pub ip6_iface: &'static str,
    pub ip6_prefix: u16,
    pub sdp_port: u16,
    pub sdp_security: SdpSecurityModel,
    pub protocol: &'static str,
    pub watchdog: i64,
}

// Binding init callback started at binding load time before any API exist
// -----------------------------------------
pub fn binding_init(_rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    //afb_log_msg!(Debug, rootv4, "config:{}", jconf);

    let uid = jconf.default("uid", "iso15118")?;
    let api = jconf.default("api", uid)?;
    let info = jconf.default("info", "iso15118(2/Din) json API")?;

    let sdp_port = jconf.default("sdp_port", 15118)?;
    let ip6_prefix = jconf.default("ip6_prefix", 0)?;
    let ip6_iface = jconf.default("iface", "lo")?;

    let protocols = jconf.get::<JsoncObj>("protocols")?;
    if protocols.count()? < 1 {
        return afb_error!("iso15118-binding-config", "protocols array empty");
    }


    // create an register frontend api and register init session callback
    let api = AfbApi::new(uid).set_name(api).set_info(info);

    for idx in 0..protocols.count()? {
        let jproto = protocols.index::<JsoncObj>(idx)?;
        let uid = jproto.default("uid", "iso15118")?;
        let prefix = jproto.default("prefix", uid)?;
        let info = jproto.default("info", "iso15118(2/Din) json API")?;
        let protocol = jproto.default("protocol", prefix)?;

        let group = AfbGroup::new(uid)
            .set_info(info)
            .set_separator(":")
            .set_prefix(prefix)
            .set_info(info);

        let session_id = jproto.default("session", "[01,02,03,04,05,06]")?;
        let watchdog =  jproto.default("watchdog", 2500)?;

        let tls_conf = match jconf.optional::<JsoncObj>("tls")? {
            None => None,
            Some(jtls) => Some(TlsConfig::from_jsonc(jtls.clone())?),
        };

        let pki_conf = match jconf.optional::<JsoncObj>("pki")? {
            None => None,
            Some(jpki) => Some(PkiConfig::from_jsonc(jpki.clone())?),
        };

        let jverbs = jproto.get::<JsoncObj>("verbs")?;
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
            pki_conf,
            session_id,
        };
        let ctrl = EvccController::new(controller_config)?;

        // send SDP multicast packet

        let binding_config = BindingConfig {
            ip6_iface,
            ip6_prefix,
            sdp_port,
            sdp_security,
            jverbs,
            protocol,
            watchdog,
        };

        // create verbs
        register_verbs(group, binding_config, ctrl)?;

        // if acls set apply them
        if let Some(value) = jproto.optional::<&str>("permission")? {
            api.set_permission(AfbPermission::new(value));
        };

        if let Some(value) = jproto.optional("verbosity")? {
            api.set_verbosity(value)?;
        };

        // finalize api protocol group & add it to binding api
        api.add_group(group.finalize()?);
    }

    // if acls set apply them
    if let Some(value) = jconf.optional::<&str>("permission")? {
        api.set_permission(AfbPermission::new(value));
    };

    if let Some(value) = jconf.optional("verbosity")? {
        api.set_verbosity(value)?;
    };

    Ok(api.finalize()?)
}

// register binding within libafb
AfbBindingRegister!(binding_init);
