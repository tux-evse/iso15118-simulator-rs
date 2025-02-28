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

impl IsoToJson for PaymentDetailsRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("emaid", self.get_emaid()?)?;
        jsonc.add("chain", self.get_contract_chain().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let contract = CertificateChainType::from_jsonc(jsonc.get("chain")?)?;
        let emaid = jsonc.get("emaid")?;
        let payload = PaymentDetailsRequest::new(emaid, contract.as_ref())?;
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PaymentDetailsResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("challenge", self.get_challenge())?;
        jsonc.add("timestamp", self.get_time_stamp())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let challenge = jsonc.get::<&str>("challenge")?;

        let payload = PaymentDetailsResponse::new(rcode, challenge.as_bytes())?;
        Ok(Box::new(payload))
    }
}
