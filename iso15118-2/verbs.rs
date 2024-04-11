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
use iso15118::prelude::iso2::*;

struct SessionSetupReqCtx {
    ctrl: &'static Controller,
    msg_id: MessageTagId,
    timeout: i64,
}

fn session_setup_req_cb(
    afb_rqt: &AfbRequest,
    args: &AfbRqtData,
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx= ctx.get_ref::<SessionSetupReqCtx>()?;
    let api_params = args.get::<JsoncObj>(0)?;

    ctx.ctrl.send_payload(
        afb_rqt,
        ctx.msg_id.clone(),
        api_params,
        ctx.timeout,
    )?;
    Ok(())
}

pub fn register_verbs(
    api: &mut AfbApi,
    config: BindingConfig,
    ctrl: &'static Controller,
) -> Result<(), AfbError> {
    for idx in 0..config.jverbs.count()? {
        let msg_name = config.jverbs.index::<&'static str>(idx)?;
        let msg_api = api_from_tagid(msg_name)?;

        let msg_verb = AfbVerb::new(msg_api.uid);
        msg_verb
            .set_name(msg_api.name)
            .set_info(msg_api.info)
            .set_callback(session_setup_req_cb)
            .set_context(SessionSetupReqCtx {
                timeout: config.timeout,
                ctrl,
                msg_id: msg_api.msg_id,
            });

        if let Some(sample)=msg_api.sample {
            msg_verb.set_sample(sample)?;
        };

        api.add_verb(msg_verb.finalize()?);
    }
    Ok(())
}
