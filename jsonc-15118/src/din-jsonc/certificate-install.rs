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

impl IsoToJson for CertificateInstallRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("provisioning", self.get_provisioning())?;
        jsonc.add("root_certs", self.get_certs_list().to_jsonc()?)?;

        if let Some(value) = self.get_id()? {
            jsonc.add("provisioning", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let provisioning = jsonc.get::<&str>("provisioning")?;
        let cert_list = CertificateRootList::from_jsonc(jsonc.get("root_certs")?)?;
        let mut payload = CertificateInstallRequest::new(provisioning.as_bytes(), &cert_list)?;

        if let Some(value) = jsonc.optional("id")? {
            payload.set_id(value)?;
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for CertificateInstallResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("id", self.get_id()?)?;
        jsonc.add("emaid", self.get_contract_id()?)?;
        jsonc.add("contract_chain", self.get_contract_chain().to_jsonc()?)?;

        jsonc.add("public_key", self.get_public_key())?;
        jsonc.add("contract_signature", self.get_contract_signature())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let id_ref = jsonc.get("id")?;
        let contract_id = jsonc.get("emaid")?;
        let contract_chain = CertificateChainType::from_jsonc(jsonc.get("contract_chain")?)?;

        let public_key = jsonc.get::<&str>("public_key")?;
        let contract_signature = jsonc.get::<&str>("contract_signature")?;

        let payload = CertificateInstallResponse::new(
            rcode,
            id_ref,
            contract_id,
            &contract_chain,
            contract_signature.as_bytes(),
            public_key.as_bytes(),
        )?;
        Ok(Box::new(payload))
    }
}
