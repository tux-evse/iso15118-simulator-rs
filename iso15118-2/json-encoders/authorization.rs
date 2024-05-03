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
use base64::{engine::general_purpose, Engine as _};


impl IsoToJson for AuthorizationRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        if let Some(id) = self.get_id() {
            jsonc.add("id", id)?;
        }
        if let Some(challenge) = self.get_challenge() {
            let mut encode = String::new();
            general_purpose::STANDARD.encode_string(challenge, &mut encode);
            jsonc.add("challenge", &encode)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let mut payload= AuthorizationRequest::new();

        if let Some(value) = jsonc.optional("id")? {
           payload.set_id(value)?;
        }

        if let Some(base64) = jsonc.optional::<&str>("challenge")? {
           let challenge=  match general_purpose::STANDARD.decode(base64) {
             Ok(decode) => decode,
             Err(_) => return afb_error!("authorization-req-from_jsonc", "fail to decode base64 challenge")
           };
           payload.set_challenge(&challenge)?;
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for AuthorizationResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("processing", self.get_processing().to_label())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let processing= EvseProcessing::from_label(jsonc.get("processing")?)?;
        let payload= AuthorizationResponse::new(rcode, processing);
        Ok(Box::new(payload))
    }
}
