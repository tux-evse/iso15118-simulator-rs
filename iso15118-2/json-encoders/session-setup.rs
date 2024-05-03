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
use iso15118::prelude::iso2::*;

impl IsoToJson for SessionSetupRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        let id = self.get_id();
        let data = bytes_to_hexa(id);
        jsonc.add("id", data.as_str())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let session_id = jsonc.get("id")?;
        let mut session_u8 = [0x0; 6 * 3];
        let session = hexa_to_bytes(session_id, &mut session_u8)?;
        let payload = SessionSetupRequest::new(session)?;
        Ok(Box::new(payload))
    }
}

impl IsoToJson for SessionSetupResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        let id = self.get_id()?;
        jsonc.add("id", id)?;
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("stamp", self.get_time_stamp())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let payload = SessionSetupResponse::new(id, rcode)?;
        Ok(Box::new(payload))
    }
}
