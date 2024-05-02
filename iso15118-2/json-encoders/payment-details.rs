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
use base64::{engine::general_purpose, Engine as _};


impl IsoToJson for PaymentDetailsRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("contract",self.get_contract().to_jsonc()?)?;
        jsonc.add("emaid", self.get_emaid()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let contract= CertificateChainType::from_jsonc(jsonc.get("contract")?)?;
        let emaid= jsonc.get("emaid")?;
        let payload= PaymentDetailsRequest::new(emaid, contract.as_ref())?;
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PaymentDetailsResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        let mut encode = String::new();
        general_purpose::STANDARD.encode_string(self.get_challenge(), &mut encode);
        jsonc.add("challenge", &encode)?;
        jsonc.add("timestamp", self.get_time_stamp())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get::<&str>("rcode")?)?;
        let challenge=  match general_purpose::STANDARD.decode(jsonc.get::<&str>("challenge")?) {
            Ok(decode) => decode,
            Err(_) => return afb_error!("payment-detail-res-from-jsonc", "fail to decode base64 challenge")
        };

        let payload= PaymentDetailsResponse::new(rcode, &challenge)?;
        Ok(Box::new(payload))
    }
}
