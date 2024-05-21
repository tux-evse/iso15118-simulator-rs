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
use iso15118::prelude::iso2_exi::*;

impl IsoToJson for SaleTariffEntry {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        if let Some(value) = self.get_start() {
            jsonc.add("start", value)?;
        }

        if let Some(value) = self.get_duration() {
            jsonc.add("duration", value)?;
        }

        if let Some(value) = self.get_price_level() {
            jsonc.add("price", value)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let mut payload = SaleTariffEntry::new();

        if let Some(value) = jsonc.optional("start")? {
            payload.set_start(value);
        }

        if let Some(value) = jsonc.optional("duration")? {
            payload.set_duration(value);
        }

        if let Some(value) = jsonc.optional("price")? {
            payload.set_price_level(value);
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for SalesTariff {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("tariff_id", self.get_tariff_id())?;

        if let Some(value) = self.get_id() {
            jsonc.add("id", value)?;
        }
        if let Some(value) = self.get_description() {
            jsonc.add("description", value)?;
        }
        if let Some(value) = self.get_tariff_level() {
            jsonc.add("tariff_level", value as u32)?;
        }

        let entries = self.get_entries();
        if entries.len() > 0 {
            let jentries = JsoncObj::array();
            for entry in entries {
                jentries.insert(entry.to_jsonc()?)?;
            }
            jsonc.add("tariff_entries", jentries)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let tariff_id = jsonc.get("tariff_id")?;
        let mut payload = SalesTariff::new(tariff_id);

        if let Some(value) = jsonc.optional("id")? {
            payload.set_id(value)?;
        }

        if let Some(value) = jsonc.optional("description")? {
            payload.set_description(value)?;
        }

        if let Some(value) = jsonc.optional("tariff_level")? {
            payload.set_tariff_level(value);
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
        let start= jsonc.get("start")?;
        let duration= jsonc.optional("duration")?;
        let mut payload= RelativeTimeInterval:: new(start);
        if let Some(value) = duration {
            payload.set_duration(value);
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PMaxScheduleEntry {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("pmax", self.get_pmax().to_jsonc()?)?;

        if let Some(value) = self.get_relative_time_interval() {
            jsonc.add("time_interval", value.to_jsonc()?)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let pmax = PhysicalValue::from_jsonc(jsonc.get("pmax")?)?;
        let time_interval = jsonc.optional("time_interval")?;
        let mut payload = PMaxScheduleEntry::new(pmax.as_ref());
        if let Some(value) = time_interval {
            let time= RelativeTimeInterval::from_jsonc(value)?;
            payload.set_relative_time_interval (time.as_ref());
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for SasScheduleTuple {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("description", self.get_description())?;

        let pmaxs = self.get_pmaxs();
        if pmaxs.len() > 0 {
            let jpmaxs = JsoncObj::array();
            for idx in 0..pmaxs.len() {
                jpmaxs.insert(pmaxs[idx].to_jsonc()?)?;
            }
            jsonc.add("pmax", jpmaxs)?;
        }

        if let Some(value) = self.get_tariff() {
            jsonc.add("tariff", value.to_jsonc()?)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let description = jsonc.get("description")?;
        let mut payload = SasScheduleTuple::new(description);

        if let Some(values) = jsonc.optional::<JsoncObj>("pmaxs")? {
            for idx in 0..values.count()? {
                payload.add_pmax(PMaxScheduleEntry::from_jsonc(values.index(idx)?)?.as_ref())?;
            }
        }
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

        if let Some(value) = self.get_max_schedule_tuple() {
            jsonc.add("max_shed_tuple", value)?;
        }

        if let Some(param) = self.get_ac_charge_param() {
            jsonc.add("ac_param", param.to_jsonc()?)?;
        }

        if let Some(param) = self.get_dc_charge_param() {
            jsonc.add("dc_param", param.to_jsonc()?)?;
        }

        if let Some(param) = self.get_ev_charge_param() {
            jsonc.add("ev_param", param.to_jsonc()?)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let transfer_mode = EngyTransfertMode::from_label(jsonc.get("transfer_mode")?)?;
        let mut payload = ParamDiscoveryRequest::new(transfer_mode);

        if let Some(value) = jsonc.optional("max_shed_tuple")? {
            payload.set_max_schedule_tuple(value);
        }

        if let Some(value) = jsonc.optional("ac_param")? {
            payload.set_ac_charge_param(AcEvChargeParam::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("dc_param")? {
            payload.set_dc_charge_param(DcEvChargeParam::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("ev_param")? {
            payload.set_ev_charge_param(EvChargeParam::from_jsonc(value)?.as_ref())?;
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for ParamDiscoveryResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("processing", self.get_processing().to_label())?;

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
                jtuples.insert(tuple.to_jsonc()?)?;
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
        let processing = EvseProcessing::from_label(jsonc.get("processing")?)?;

        let mut payload = ParamDiscoveryResponse::new(rcode, processing);

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
