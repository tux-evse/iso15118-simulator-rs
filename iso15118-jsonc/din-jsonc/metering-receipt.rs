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

impl IsoToJson for MeteringReceiptRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("session", bytes_to_hexa(self.get_session_id()).as_str())?;
        jsonc.add("info", self.get_info().to_jsonc()?)?;
        if let Some(value) = self.get_id() {
            jsonc.add("id", value)?;
        }
        if let Some(value) = self.get_tuple_id() {
            jsonc.add("tuple", value as u32)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let mut buffer= [0x00; 6];
        let session_id = hexa_to_bytes(jsonc.get("session")?, &mut buffer)?;
        let meter_info = MeterInfo::from_jsonc(jsonc.get("info")?)?;
        let mut payload= MeteringReceiptRequest::new(session_id, &meter_info)?;

        if let Some(value) = jsonc.optional("id")? {
           payload.set_id(value)?;
        }

        if let Some(value) = jsonc.optional("tuple")? {
           payload.set_tupple_id(value);
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for MeteringReceiptResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("ac_status", self.get_ac_evse_status().to_jsonc()?)?;
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let ac_status= AcEvseStatusType::from_jsonc(jsonc.get("ac_status")?)?;

        let payload= MeteringReceiptResponse::new(rcode, ac_status.as_ref());
        Ok(Box::new(payload))
    }
}
