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

impl IsoToJson for ContractAuthenticationRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        if let Some(id) = self.get_id()? {
            jsonc.add("id",id)?;
        }
        if let Some(challenge) = self.get_challenge()? {
            jsonc.add("challenge",challenge)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let mut payload= ContractAuthenticationRequest::new();
        if let Some(id) = jsonc.optional("id")? {
            payload.set_id(id)?;
        }
        if let Some(challenge) = jsonc.optional("challenge")? {
            payload.set_id(challenge)?;
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ContractAuthenticationResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("processing", self.get_processing().to_label())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let processing= EvseProcessing::from_label(jsonc.get("processing")?)?;
        let payload= ContractAuthenticationResponse::new(rcode, processing);
        Ok(Box::new(payload))
    }
}
