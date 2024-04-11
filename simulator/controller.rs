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
    event: &AfbEvent,
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
    params: &AfbCtxData,
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let param = params.get_mut::<JobTransactionParam>()?;
    let context = ctx.get_mut::<JobTransactionContext>()?;

    let mut transac = &mut param.state.entries[param.idx];
    if signal != 0 {
        // callsync fail in timeout
        let error = AfbError::new(
            "job-transaction-cb",
            -62,
            format!("{}:{} timeout", context.target, transac.uid),
        );
        transac.status = TransacStatus::Fail(error);
        return afb_error!(
            "job-transaction-cb",
            "uid:{} transaction killed",
            transac.uid
        );
    }

    if context.running {
        transac.status= TransacStatus::Pending;
        transac.status= (context.callback)(param.api, &mut transac, context.target, context.event);
        match  &transac.status {
            TransacStatus::Done | TransacStatus::Check => {
                Ok(())
            },
            TransacStatus::Fail(_error) => {
                context.running = false;
                Ok(())
            }
            _ => afb_error!(
                "job_transaction_cb",
                "unexpected status for uid:{}",
                transac.uid
            ),
        }
    } else {
       transac.status= TransacStatus::Ignored;
       Ok(())
    }
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
    ctx: &AfbCtxData,
) -> Result<(), AfbError> {
    let param = params.get_ref::<JobScenarioParam>()?;
    let context = ctx.get_ref::<JobScenarioContext>()?;

    // job was kill from API
    if signal != 0 {
        return Ok(());
    }

    let job = AfbSchedJob::new("iso15118-transac")
        .set_exec_watchdog(context.timeout)
        .set_group(1)
        .set_callback(job_transaction_cb)
        .set_context(JobTransactionContext {
            target: context.target,
            event: param.event,
            callback: context.callback,
            running: true,
        })
        .set_exec_watchdog(context.timeout)
        .finalize();

    for idx in 0..context.count {
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
    Fail(AfbError),
}

pub struct TransacEntry {
    pub uid: &'static str,
    pub request: JsoncObj,
    pub expect: Option<JsoncObj>,
    pub status: TransacStatus,
}

pub struct ScenarioState {
    pub entries: Vec<TransacEntry>,
}

pub struct Scenario {
    _uid: &'static str,
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
            let request = transac.get::<JsoncObj>("request")?;
            let expect = transac.optional::<JsoncObj>("expect")?;

            data_set.entries.push(TransacEntry {
                uid,
                request,
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
            _uid: uid,
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

    pub fn start(&'static self, afb_rqt: &AfbRequest, event: &'static AfbEvent) -> Result<i32, AfbError> {
        let api = afb_rqt.get_apiv4();
        let job_id = self.job.post(
            0,
            JobScenarioParam {
                scenario: self,
                event,
                api,
            },
        )?;

        Ok(job_id)
    }

    pub fn stop(&self, job_id: i32) -> Result<(), AfbError> {
        self.job.abort(job_id)?;
        self.get_result()?;
        Ok(())
    }

    pub fn get_result(&self) -> Result<(), AfbError> {
        let state = self.lock_state()?;
        for idx in 0..self.count {
            let transac = &state.entries[idx];
            println!(" --[{}] uid:{}, {:?}", idx, transac.uid, transac.status);
        }
        Ok(())
    }
}
