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

use crate::prelude::IsoToJson;
use afbv4::prelude::*;
use iso15118::prelude::iso2_exi::*;

impl IsoToJson for ChargingStatusRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        // does not take any param
        let jsonc = JsoncObj::new();
        Ok(jsonc)
    }
    fn from_jsonc(_jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        // does not take any param
        let payload = ChargingStatusRequest::new();
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ChargingStatusResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("evse_id", self.get_evse_id()?)?;
        jsonc.add("tuple_id", self.get_tuple_id() as u32)?;
        jsonc.add("status", &self.get_ac_evse_status().to_jsonc()?)?;

        if let Some(value) = self.get_max_current() {
            jsonc.add("max_current", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_meter_info() {
            jsonc.add("meter_info", value.to_jsonc()?)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let evse_id = jsonc.get("evse_id")?;
        let tuple_id = jsonc.get("tuple_id")?;
        let status = AcEvseStatusType::from_jsonc(jsonc.get("status")?)?;
        let mut payload = ChargingStatusResponse::new(rcode, evse_id, tuple_id, &status)?;

        if let Some(value) = jsonc.optional("max_current")? {
            payload.set_max_current(PhysicalValue::from_jsonc(value)?.as_ref());
        }

        if let Some(value) = jsonc.optional("meter_info")? {
            payload.set_meter_info(MeterInfo::from_jsonc(value)?.as_ref());
        }
        Ok(Box::new(payload))
    }
}
