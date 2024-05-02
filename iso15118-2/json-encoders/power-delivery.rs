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

impl IsoToJson for ChargingProfileEntry {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("start", self.get_start())?;
        jsonc.add("power_max", self.get_power_max().to_jsonc()?)?;
        if let Some(value) = self.get_phases_max() {
            jsonc.add("phases_max", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let start = jsonc.get::<u32>("start")?;
        let power_max = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("power_max")?)?;
        let phase_max = jsonc.optional::<i8>("phases_max")?;
        Ok(Box::new(ChargingProfileEntry::new(
            start, *power_max, phase_max,
        )))
    }
}

impl IsoToJson for DcEvPowerDeliveryParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("charge_complete", self.get_charge_complete())?;
        if let Some(value) = self.get_bulk_complete() {
            jsonc.add("bulk_complete", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status = DcEvStatusType::from_jsonc(jsonc.get::<JsoncObj>("status")?)?;
        let charge_complete = jsonc.get::<bool>("charge_complete")?;
        let bulk_complete = jsonc.optional::<bool>("charge_complete")?;
        Ok(Box::new(DcEvPowerDeliveryParam::new(
            *status,
            charge_complete,
            bulk_complete,
        )))
    }
}

impl IsoToJson for PowerDeliveryRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("charge_progress", self.get_progress().to_label())?;
        jsonc.add("schedule_id", self.get_schedule_id())?;

        let profiles = self.get_charging_profiles();
        if profiles.len() > 0 {
            let jprofiles = JsoncObj::array();
            for idx in 0..profiles.len() {
                let profile = &profiles[idx];
                jprofiles.insert(profile.to_jsonc()?)?;
            }
            jsonc.add("charging_profiles", jprofiles)?;
        }

        if let Some(value) = self.get_dc_delivery_params() {
            jsonc.add("dc_delivery_params", value.to_jsonc()?)?;
        }

        if let Some(value) = self.get_ev_delivery_params() {
            jsonc.add("ev_delivery_params", value)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let charge_progress = ChargeProgress::from_label(jsonc.get("charge_progress")?)?;
        let schedule_id = jsonc.get("schedule_id")?;
        let mut payload = PowerDeliveryRequest::new(charge_progress, schedule_id);

        if let Some(jvalues) = jsonc.optional::<JsoncObj>("charging_profiles")? {
            for idx in 0..jvalues.count()? {
                payload.add_charging_profile(
                    ChargingProfileEntry::from_jsonc(jvalues.index(idx)?)?.as_ref(),
                )?;
            }
        }

        if let Some(value) = jsonc.optional("dc_delivery_params")? {
            payload.set_dc_delivery_params(DcEvPowerDeliveryParam::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("ev_delivery_params")? {
            payload.set_ev_delivery_params(value);
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for PowerDeliveryResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("rcode", self.get_rcode().to_label())?;

        if let Some(value) = self.get_ac_evse_status() {
            jsonc.add("ac_evse_status", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_dc_evse_status() {
            jsonc.add("dc_evse_status", value.to_jsonc()?)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get::<&str>("rcode")?)?;
        let mut payload = PowerDeliveryResponse::new(rcode);

        if let Some(value) = jsonc.optional("ac_evse_status")? {
            payload.set_ac_evse_status(AcEvseStatusType::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("dc_evse_status")? {
            payload.set_dc_evse_status(DcEvseStatusType::from_jsonc(value)?.as_ref())?;
        }

        Ok(Box::new(payload))
    }
}
