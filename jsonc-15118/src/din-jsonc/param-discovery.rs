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
use iso15118::prelude::din_exi::*;

impl IsoToJson for SaleTariffEntry {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("price_level", self.get_price_level())?;

        if let Some(value) = self.get_relative_time() {
            jsonc.add("rtime", value.to_jsonc()?)?;
        }

        if let Some(value) = self.get_time() {
            jsonc.add("time", value.to_jsonc()?)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let price = jsonc.get("price_level")?;
        let mut payload = SaleTariffEntry::new(price);

        if let Some(value) = jsonc.optional("rtime")? {
            payload.set_relative_time(RelativeTimeInterval::from_jsonc(value)?.as_ref());
        }

        if let Some(value) = jsonc.optional("time")? {
            payload.set_time(TimeInterval::from_jsonc(value)?.as_ref());
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for SalesTariff {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("id", self.get_id()?)?;
        jsonc.add("tariff_id", self.get_tariff_id())?;
        jsonc.add("price_level", self.get_price_level())?;

        if let Some(value) = self.get_description() {
            jsonc.add("schedule_id", value)?;
        }

        let entries = self.get_entries();
        if entries.len() > 0 {
            let jentries = JsoncObj::array();
            for entry in entries {
                jentries.append(entry.to_jsonc()?)?;
            }
            jsonc.add("tariff_entries", jentries)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let tariff_id = jsonc.get("tariff_id")?;
        let price_level = jsonc.get("price_level")?;
        let mut payload = SalesTariff::new(id, tariff_id, price_level)?;

        if let Some(value) = jsonc.optional("schedule_id")? {
            payload.set_description(value)?;
        }

        if let Some(values) = jsonc.optional::<JsoncObj>("tariff_entries")? {
            for idx in 0..values.count()? {
                payload.add_entry(SaleTariffEntry::from_jsonc(values.index(idx)?)?.as_ref())?;
            }
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for RelativeTimeInterval {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("start", self.get_start())?;
        if let Some(value) = self.get_duration() {
            jsonc.add("duration", value)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let start = jsonc.get("start")?;
        let duration = jsonc.optional("duration")?;
        let mut payload = RelativeTimeInterval::new(start);
        if let Some(value) = duration {
            payload.set_duration(value);
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for TimeInterval {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("unused", self.get_unused())?;
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let payload = TimeInterval::new(jsonc.get("unused")?);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PMaxScheduleEntry {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("value", self.get_pmax())?;

        if let Some(value) = self.get_relative_time_interval() {
            jsonc.add("relative_time_interval", value.to_jsonc()?)?;
        }

        if let Some(value) = self.get_time_interval() {
            jsonc.add("time_interval", value)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let pmax = jsonc.get("value")?;
        let mut payload = PMaxScheduleEntry::new(pmax);

        if let Some(value) = jsonc.optional("time_interval")? {
            payload.set_time_interval(value);
        }

        if let Some(value) = jsonc.optional("relative_time_interval")? {
            let time = RelativeTimeInterval::from_jsonc(value)?;
            payload.set_relative_time_interval(time.as_ref());
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for PMaxSchedule {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id())?;

        let entries = self.get_entries();
        if entries.len() > 0 {
            let jentries = JsoncObj::array();
            for entry in entries {
                jentries.append(entry.to_jsonc()?)?;
            }
            jsonc.add("entries", jentries)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let mut payload = PMaxSchedule::new(id);

        if let Some(entries) = jsonc.optional::<JsoncObj>("entries")? {
            for idx in 0..entries.count()? {
                payload.add_entry(PMaxScheduleEntry::from_jsonc(entries.index(idx)?)?.as_ref())?;
            }
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for SasScheduleTuple {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id())?;
        jsonc.add("pmax", self.get_pmax_schedule().to_jsonc()?)?;

        if let Some(value) = self.get_tariff() {
            jsonc.add("tariff", value.to_jsonc()?)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let pmax = jsonc.get("pmax")?;
        let mut payload = SasScheduleTuple::new(id, PMaxSchedule::from_jsonc(pmax)?.as_ref());

        if let Some(value) = jsonc.optional("tariff")? {
            payload.set_tariff(SalesTariff::from_jsonc(value)?.as_ref());
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for ParamDiscoveryRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("transfer_mode", self.get_transfert_energy_mode().to_label())?;

        if let Some(param) = self.get_ac_charge_param() {
            jsonc.add("ac_evparam", param.to_jsonc()?)?;
        }

        if let Some(param) = self.get_dc_charge_param() {
            jsonc.add("dc_evparam", param.to_jsonc()?)?;
        }

        if let Some(param) = self.get_ev_charge_param() {
            jsonc.add("evparam", param.to_jsonc()?)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let transfer_mode = EvRequestTransfertMode::from_label(jsonc.get("transfer_mode")?)?;
        let mut payload = ParamDiscoveryRequest::new(transfer_mode);

        if let Some(value) = jsonc.optional("ac_evparam")? {
            payload.set_ac_charge_param(AcEvChargeParam::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("dc_evparam")? {
            payload.set_dc_charge_param(DcEvChargeParam::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("evparam")? {
            payload.set_ev_charge_param(EvChargeParam::from_jsonc(value)?.as_ref())?;
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for ParamDiscoveryResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;

        if let Some(value) = self.get_schedules() {
            jsonc.add("schedules", value)?; // unused
        }
        if let Some(value) = self.get_evse_charge_param() {
            jsonc.add("charge_param", value)?;
        }

        let tuples = self.get_schedule_tuples();
        if tuples.len() > 0 {
            let jtuples = JsoncObj::array();
            for tuple in tuples {
                jtuples.append(tuple.to_jsonc()?)?;
            }
            jsonc.add("tuples", jtuples)?;
        }

        if let Some(charge) = self.get_evse_dc_charge_param() {
            jsonc.add("evse_dc_charge_param", charge.to_jsonc()?)?;
        }

        if let Some(charge) = self.get_evse_ac_charge_param() {
            jsonc.add("evse_ac_charge_param", charge.to_jsonc()?)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;

        let mut payload = ParamDiscoveryResponse::new(rcode);

        if let Some(value) = jsonc.optional("schedules")? {
            payload.set_schedules(value);
        }

        if let Some(value) = jsonc.optional("evse_charge_param")? {
            payload.set_evse_charge_param(value); // unused
        }

        if let Some(values) = jsonc.optional::<JsoncObj>("tuples")? {
            for idx in 0..values.count()? {
                payload.add_schedule_tuple(
                    SasScheduleTuple::from_jsonc(values.index(idx)?)?.as_ref(),
                )?;
            }
        }

        if let Some(value) = jsonc.optional("evse_ac_charge_param")? {
            payload.set_evse_ac_charge_param(AcEvseChargeParam::from_jsonc(value)?.as_ref());
        }

        if let Some(value) = jsonc.optional("evse_dc_charge_param")? {
            payload.set_evse_dc_charge_param(DcEvseChargeParam::from_jsonc(value)?.as_ref());
        }

        Ok(Box::new(payload))
    }
}
