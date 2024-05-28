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
use std::str;
use base64::{engine::general_purpose, Engine as _};


impl IsoToJson for PaymentDetailsRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("emaid",self.get_contract_id()?)?;
        jsonc.add("chain", self.get_contract_chain().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let contract= CertificateChainType::from_jsonc(jsonc.get("chain")?)?;
        let emaid= jsonc.get("emaid")?;
        let payload= PaymentDetailsRequest::new(emaid, contract.as_ref())?;
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PaymentDetailsResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let mut base64 = String::new();
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        general_purpose::STANDARD.encode_string(self.get_challenge()?.as_bytes(), &mut base64);
        jsonc.add("challenge", &base64)?;
        jsonc.add("timestamp", self.get_time_stamp())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let decoded=  match general_purpose::STANDARD.decode(jsonc.get::<&str>("challenge")?) {
            Ok(value) => value,
            Err(_) => return afb_error!("payment-detail-res-from-jsonc", "fail to decode base64 challenge")
        };

        let challenge= match str::from_utf8(&decoded) {
                    Ok(value) => value,
                    Err(_) => return afb_error!("payment-detail-res-from-jsonc", "fail to decode base64 challenge"),
        };

        let payload= PaymentDetailsResponse::new(rcode, challenge)?;
        Ok(Box::new(payload))
    }
}
