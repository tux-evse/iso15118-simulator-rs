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

use afbv4::prelude::*;
use std::sync::{Mutex, MutexGuard};

pub type TransacReqCb = fn(
    api: AfbApiV4,
    transac: &mut TransacEntry,
    target: &'static str,
) -> TransacStatus;

pub struct JobTransactionContext {
    event: &'static AfbEvent,
    target: &'static str,
    callback: TransacReqCb,
    running: bool,
}

pub struct JobTransactionParam<'a> {
    api: AfbApiV4,
    idx: usize,
    state: MutexGuard<'a, ScenarioState>,
}

fn job_transaction_cb(
    _job: &AfbSchedJob,
    signal: i32,
    jobctx: &AfbCtxData,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let param = jobctx.get_mut::<JobTransactionParam>()?;
    let ctx = context.get_mut::<JobTransactionContext>()?;

    let mut transac = &mut param.state.entries[param.idx];

    if signal != 0 {
        let error = AfbError::new(
            "job-transaction-cb",
            -62,
            format!("{}:{} timeout", ctx.target, transac.uid),
        );

        // send result as event
        let jreply = JsoncObj::new();
        jreply.add("uid", transac.uid)?;
        jreply.add("status", format!("{:?}", TransacStatus::Timeout).as_str())?;
        ctx.event.push(jreply);

        transac.status = TransacStatus::Fail(error);
        jobctx.free::<JobTransactionParam>();

        return afb_error!(
            "job-transaction-cb",
            "uid:{} transaction killed",
            transac.uid
        );
    }

    let response = if ctx.running {
        transac.status = TransacStatus::Pending;
        transac.status = (ctx.callback)(param.api, &mut transac, ctx.target);
        match &transac.status {
            TransacStatus::Done | TransacStatus::Check => {
                Ok(())
            }
            TransacStatus::Fail(_error) => {
                ctx.running = false;
                Ok(())
            }
            _ => afb_error!(
                "job_transaction_cb",
                "unexpected status for uid:{}",
                transac.uid
            ),
        }
    } else {
        transac.status = TransacStatus::Ignored;
        Ok(())
    };

    // send result as event
    let jreply = JsoncObj::new();
    jreply.add("uid", transac.uid)?;
    jreply.add("verb", transac.verb)?;
    jreply.add("status", format!("{:?}", transac.status).as_str())?;
    ctx.event.push(jreply);
    jobctx.free::<JobTransactionParam>();
    response
}

pub struct JobScenarioContext {
    target: &'static str,
    callback: TransacReqCb,
    timeout: i32,
    count: usize,
}

pub struct JobScenarioParam {
    api: AfbApiV4,
    scenario: &'static Scenario,
    event: &'static AfbEvent,
}

fn job_scenario_cb(
    _job: &AfbSchedJob,
    signal: i32,
    params: &AfbCtxData,
    context: &AfbCtxData,
) -> Result<(), AfbError> {
    let param = params.get_ref::<JobScenarioParam>()?;
    let ctx = context.get_ref::<JobScenarioContext>()?;

    // job was kill from API
    if signal != 0 {
        context.free::<JobScenarioContext>();
        return Ok(());
    }

    let job = AfbSchedJob::new("iso15118-transac")
        .set_exec_watchdog(ctx.timeout)
        .set_group(1)
        .set_callback(job_transaction_cb)
        .set_context(JobTransactionContext {
            target: ctx.target,
            event: param.event,
            callback: ctx.callback,
            running: true,
        })
        .set_exec_watchdog(ctx.timeout)
        .finalize();

    for idx in 0..ctx.count {
        job.post(
            0,
            JobTransactionParam {
                idx,
                state: param.scenario.lock_state()?,
                api: param.api,
            },
        )?;
    }

    job.terminate();
    Ok(())
}

#[derive(Debug)]
pub enum TransacStatus {
    Pending,
    Done,
    Check,
    Ignored,
    Idle,
    Timeout,
    Fail(AfbError),
}

pub struct TransacEntry {
    pub uid: &'static str,
    pub verb: &'static str,
    pub query: Option<JsoncObj>,
    pub expect: Option<JsoncObj>,
    pub status: TransacStatus,
}

pub struct ScenarioState {
    pub entries: Vec<TransacEntry>,
}

pub struct Scenario {
    uid: &'static str,
    job: &'static AfbSchedJob,
    count: usize,
    data_set: Mutex<ScenarioState>,
}

impl Scenario {
    pub fn new(
        uid: &'static str,
        target: &'static str,
        config: JsoncObj,
        timeout: i32,
        callback: TransacReqCb,
    ) -> Result<&'static Self, AfbError> {
        let mut data_set = ScenarioState {
            entries: Vec::new(),
        };

        for idx in 0..config.count()? {
            let transac = config.index::<JsoncObj>(idx)?;
            let uid = transac.get::<&str>("uid")?;
            let query = transac.optional::<JsoncObj>("query")?;
            let expect = transac.optional::<JsoncObj>("expect")?;
            let verb = match transac.optional::<&'static str>("verb")? {
                Some(value) => value,
                None => {
                    let name = format!("{}_req", uid.replace("-", "_"));
                    to_static_str(name)
                }
            };

            data_set.entries.push(TransacEntry {
                uid,
                verb,
                query,
                expect,
                status: TransacStatus::Idle,
            });
        }

        let job = AfbSchedJob::new("iso-15118-scenario")
            .set_callback(job_scenario_cb)
            .set_context(JobScenarioContext {
                target,
                timeout,
                callback,
                count: data_set.entries.len(),
            });

        let this = Self {
            uid,
            job,
            count: config.count()?,
            data_set: Mutex::new(data_set),
        };

        Ok(Box::leak(Box::new(this)))
    }

    #[track_caller]
    pub fn lock_state(&self) -> Result<MutexGuard<'_, ScenarioState>, AfbError> {
        let guard = self.data_set.lock().unwrap();
        Ok(guard)
    }

    pub fn start(
        &'static self,
        afb_rqt: &AfbRequest,
        event: &'static AfbEvent,
    ) -> Result<i32, AfbError> {
        let api = afb_rqt.get_apiv4();
        let job_id = self.job.post(
            1,
            JobScenarioParam {
                scenario: self,
                event,
                api,
            },
        )?;

        Ok(job_id)
    }

    pub fn stop(&self, job_id: i32) -> Result<JsoncObj, AfbError> {
        self.job.abort(job_id)?;
        self.get_result()
    }

    pub fn get_result(&self) -> Result<JsoncObj, AfbError> {
        let state = self.lock_state()?;
        let result= JsoncObj::array();
        result.insert(format!("1..{} # {}", self.count, self.uid).as_str())?;
        for idx in 0..self.count {
            let transac = &state.entries[idx];
            let status= match &transac.status {
                TransacStatus::Done =>  format!("ok {} - {}  # Response uncheck", idx, transac.uid),
                TransacStatus::Check => format!("ok {} - {}  # Response checked", idx, transac.uid),
                TransacStatus::Fail(error) => format!("fx {} - {}  # {}", idx, transac.uid, error),
                _ => format!("fx {} - {}  # {:?}", idx, transac.uid, transac.status),
            };
            result.insert(status.as_str())?;
        }
        Ok(result)
    }
}
