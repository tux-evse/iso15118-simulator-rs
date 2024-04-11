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

pub struct BindingConfig {
    pub timeout: i64,
    pub jverbs: JsoncObj,
}
struct ApiUserData {
    iface: &'static str,
    sdp_port: u16,
}

impl AfbApiControls for ApiUserData {
    // the API is created and ready. At this level user may subcall api(s) declare as dependencies
    fn start(&mut self, api: &AfbApi) -> Result<(), AfbError> {
        afb_log_msg!(Notice, api, "iface:{} sdp:{}", self.iface, self.sdp_port);

        //AfbSubCall::call_async(api, "simu", "ping", AFB_NO_DATA, Box::new(AsyncResponseCb {}))?;
        //AfbSubCall::call_sync(api, "simu", "ping", AFB_NO_DATA)?;
        //println! ("**** aftercall cb");
        Ok(())
    }
    // mandatory unsed declaration
    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

// Binding init callback started at binding load time before any API exist
// -----------------------------------------
pub fn binding_init(rootv4: AfbApiV4, jconf: JsoncObj) -> Result<&'static AfbApi, AfbError> {
    afb_log_msg!(Info, rootv4, "config:{}", jconf);

    let uid = jconf.default::<&'static str>("uid", "iso15118-2")?;
    let api = jconf.default::<&'static str>("api", "iso-2")?;
    let info = jconf.default::<&'static str>("info", "iso15118-2 json API")?;

    let sdp_port = jconf.default::<u32>("sdp_port", 15118)? as u16;
    let ip6_prefix = jconf.default::<u32>("ip6_prefix", 0)? as u16;
    let ip6_iface = jconf.default::<&'static str>("ip6_iface", "lo")?;
    let session_id = jconf.default::<&'static str>("ip6_iface", "01:02:03:04:05:06")?;
    let timeout = jconf.default::<i64>("timeout", 1000)?;

    let tls_conf = if let Some(jtls) = jconf.optional::<JsoncObj>("tsl")? {
        let cert_chain = jtls.get::<&str>("tls_certs")?;
        let priv_key = jtls.get::<&str>("tls_key")?;
        let pin_key = jtls.optional::<&str>("tls_pin")?;
        let tls_psk = jtls.optional::<&'static str>("tls_pks")?;
        let tls_trust = jtls.optional::<&'static str>("tls_trust")?;
        let tls_verbosity = jtls.default::<i32>("tls_verbosity", 1)?;
        let tls_proto = jtls.optional::<&'static str>("tls_proto")?;
        let psk_log = jtls.optional::<&'static str>("psk_log")?;

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

    let jverbs= jconf.get::<JsoncObj>("verbs")?;
    if ! jverbs.is_type(Jtype::Array) {
        return afb_error! ("iso2-binding-config", "verbs should be a valid array of iso messages")
    }

    // Register controller
    let controller_config = ControllerConfig {
        tls_conf,
        sdp_port,
        ip6_prefix,
        ip6_iface,
        session_id,
    };
    let controller = Controller::new(controller_config)?;


    // create an register frontend api and register init session callback
    let api = AfbApi::new(uid).set_name(api).set_info(info);

    // create verbs
    let binding_config = BindingConfig { timeout, jverbs };
    register_verbs(api, binding_config, controller)?;

    // if acls set apply them
    if let Ok(value) = jconf.get::<&'static str>("permission") {
        api.set_permission(AfbPermission::new(value));
    };

    if let Ok(value) = jconf.get::<i32>("verbosity") {
        api.set_verbosity(value);
    };

    Ok(api.finalize()?)
}

// register binding within libafb
AfbBindingRegister!(binding_init);
