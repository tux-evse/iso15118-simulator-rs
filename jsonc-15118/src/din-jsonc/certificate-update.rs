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

impl IsoToJson for CertificateUpdateRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        if let Some(value) = self.get_id() {
            jsonc.add("id", value)?;
        }
        jsonc.add("emaid", self.get_contract_id()?)?;
        jsonc.add("public_key", self.get_public_key())?;
        jsonc.add("root_certs", self.get_root_certs().to_jsonc()?)?;

        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let contract_id = jsonc.get("emaid")?;
        let public_key = jsonc.get::<&str>("public_key")?;
        let root_certs = CertificateRootList::from_jsonc(jsonc.get("root_certs")?)?;

        let mut payload =
            CertificateUpdateRequest::new(contract_id, root_certs.as_ref(), public_key.as_bytes())?;
        if let Some(value) = jsonc.optional("id")? {
            payload.set_id(value)?;
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for CertificateUpdateResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("id", self.get_id()?)?;
        jsonc.add("emaid", self.get_contract_id()?)?;
        jsonc.add("contract_chain", self.get_contract_chain().to_jsonc()?)?;
        jsonc.add("public_key", self.get_public_key())?;
        jsonc.add("contract_signature", self.get_signature())?;
        jsonc.add("rcount", self.get_rcount())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let id = jsonc.get("id")?;
        let rcount = jsonc.get("rcount")?;
        let contract_id = jsonc.get("emaid")?;
        let contract_chain = CertificateChainType::from_jsonc(jsonc.get("contract")?)?;

        let public_key = jsonc.get::<&str>("public_key")?;
        let contract_signature =jsonc.get::<&str>("contract_signature")?;

        let payload = CertificateUpdateResponse::new(
            rcode,
            id,
            contract_id,
            contract_chain.as_ref(),
            contract_signature.as_bytes(),
            public_key.as_bytes(),
            rcount,
        )?;
        Ok(Box::new(payload))
    }
}
