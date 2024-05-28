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

impl IsoToJson for PreChargeRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("target_voltage", self.get_target_voltage().to_jsonc()?)?;
        jsonc.add("target_current", self.get_target_current().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status = DcEvStatusType::from_jsonc(jsonc.get("status")?)?;
        let voltage = PhysicalValue::from_jsonc(jsonc.get("target_voltage")?)?;
        let current = PhysicalValue::from_jsonc(jsonc.get("target_current")?)?;
        let payload = PreChargeRequest::new(status.as_ref(), voltage.as_ref(), current.as_ref())?;
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PreChargeResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("voltage", self.get_voltage().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let status = DcEvseStatusType::from_jsonc(jsonc.get("status")?)?;
        let voltage = PhysicalValue::from_jsonc(jsonc.get("voltage")?)?;
        let payload = PreChargeResponse::new(rcode, status.as_ref(), voltage.as_ref())?;
        Ok(Box::new(payload))
    }
}
