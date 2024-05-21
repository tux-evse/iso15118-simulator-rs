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

impl IsoToJson for CableCheckRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status= DcEvStatusType::from_jsonc(jsonc.get("status")?)?;
        let payload= CableCheckRequest::new(&status);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for CableCheckResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("processing", self.get_processing().to_label())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let processing= EvseProcessing::from_label(jsonc.get("processing")?)?;
        let status= DcEvseStatusType::from_jsonc(jsonc.get("status")?)?;
        let payload= CableCheckResponse::new(rcode, &status, processing);
        Ok(Box::new(payload))
    }
}
