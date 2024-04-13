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
use serde::{Deserialize, Serialize};

const DEFAULT_ISO_TIMEOUT: i32 = 1000; // call_sync ms default timeout

AfbDataConverter!(scenario_actions, ScenarioAction);
#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase", tag = "action")]
pub enum ScenarioAction {
    #[default]
    START,
    STOP,
    RESULT,
}

fn cmp_entry<'a>(value: &Jentry, expect: &'a Jentry) -> Option<&'a Jentry> {
    if value.key == expect.key {
        Some(expect)
    } else {
        None
    }
}

fn check_response(reply: &JsoncObj, expect: &JsoncObj) -> TransacStatus {
    // move from jsonc to a rust vector of json object
    let expect = expect.expand();
    let reply = reply.expand();

    for idx in 0..expect.len() {
        let expect_entry = &expect[idx];
        let reply_entry = match reply.iter().find_map(|s| cmp_entry(s, expect_entry)) {
            None => {
                return TransacStatus::Fail(AfbError::new(
                    "simu-check-response",
                    -99,
                    format!("fail to find key:{}", expect_entry.key),
                ))
            }
            Some(value) => value,
        };

        // if entry value embed a nested object let's recursively check content
        if reply_entry.obj.is_type(Jtype::Object) {
            let response = check_response(&reply_entry.obj, &expect_entry.obj);
            match check_response(&reply_entry.obj, &expect_entry.obj) {
                TransacStatus::Check => {}
                TransacStatus::Done => {}
                _ => return response,
            }
        }

        // check both reply & expected value match
        if let Err(error) = reply_entry.obj.clone().equal(expect_entry.obj.clone()) {
            return TransacStatus::Fail(AfbError::new(
                "simu-check-response",
                -99,
                format!(
                    "fail key:{} value:{}!={} {}",
                    expect_entry.key, expect_entry.obj, reply_entry.obj, error
                ),
            ));
        }
    }
    TransacStatus::Check
}

fn transac_req_cb(
    api: AfbApiV4,
    transac: &mut TransacEntry,
    target: &'static str,
    event: &AfbEvent,
) -> TransacStatus {

    let req_verb = match transac.request.optional::<String>("msg").unwrap() {
        Some(value) => value,
        None => format!("{}-req", transac.uid.replace("-", "_"))
    };

    let status = match AfbSubCall::call_sync(api, target, req_verb.as_str(), transac.request.clone()) {
        Err(error) => TransacStatus::Fail(error),
        Ok(response) => match transac.expect.clone() {
            None => TransacStatus::Done,
            Some(expect) => match response.get::<JsoncObj>(0) {
                Ok(jsonc) => check_response(&jsonc, &expect),
                Err(error) => TransacStatus::Fail(error),
            },
        },
    };

    let mut response = AfbParams::new();
    response.push(transac.uid).unwrap();
    response.push(format!("{:?}", status)).unwrap();
    event.push(response);
    status
}

pub struct ScenarioReqCtx {
    _uid: &'static str,
    target: &'static str,
    evt: &'static AfbEvent,
    job_id: i32,
    scenario: &'static Scenario,
}

fn scenario_action_cb(
    afb_rqt: &AfbRequest,
    args: &AfbRqtData,
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let ctx = ctx.get_mut::<ScenarioReqCtx>()?;
    let action = args.get::<&ScenarioAction>(0)?;

    match action {
        ScenarioAction::START => {
            AfbSubCall::call_sync(afb_rqt, ctx.target, "sdp", AFB_NO_DATA)?;
            ctx.evt.subscribe(afb_rqt)?;
            ctx.job_id = ctx.scenario.start(afb_rqt, ctx.evt)?;
            afb_rqt.reply(ctx.job_id, 0);
        }

        ScenarioAction::STOP => {
            ctx.evt.unsubscribe(afb_rqt)?;
            ctx.scenario.stop(ctx.job_id)?;
            ctx.job_id = 0;
            afb_rqt.reply(AFB_NO_DATA, 0);
        }

        ScenarioAction::RESULT => {
            ctx.scenario.get_result()?;
        }
    }

    Ok(())
}

pub fn register_verbs(api: &mut AfbApi, config: &BindingConfig) -> Result<(), AfbError> {
    scenario_actions::register()?;

    for idx in 0..config.scenarios.count()? {
        let jscenario = config.scenarios.index::<JsoncObj>(idx)?;
        let uid = jscenario.get::<&'static str>("uid")?;
        let name = jscenario.default::<&'static str>("name", uid)?;
        let info = jscenario.default::<&'static str>("info", "")?;
        let timeout = jscenario.default::<i32>("timeout", DEFAULT_ISO_TIMEOUT)?;
        let target = jscenario.get::<&'static str>("target")?;
        let transactions = jscenario.get::<JsoncObj>("transactions")?;
        if !transactions.is_type(Jtype::Array) {
            return afb_error!(
                "simu-scenario-config",
                "transactions should be a valid array of (uid,request,expect)"
            );
        }

        let scenario_event = AfbEvent::new(uid);
        let scenario_verb = AfbVerb::new(uid);
        let scenario = Scenario::new(uid, target, transactions, timeout, transac_req_cb)?;
        scenario_verb
            .set_name(name)
            .set_info(info)
            .set_action("['start','stop','result']")?
            .set_callback(scenario_action_cb)
            .set_context(ScenarioReqCtx {
                _uid: uid,
                target,
                job_id: 0,
                scenario,
                evt: scenario_event,
            });
        api.add_verb(scenario_verb.finalize()?);
        api.add_event(scenario_event);
    }
    Ok(())
}
