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
use base64::{engine::general_purpose, Engine as _};
use iso15118::prelude::din_exi::*;

impl IsoToJson for CertificateInstallRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        let mut base64 = String::new();
        general_purpose::STANDARD.encode_string(self.get_provisioning(), &mut base64);
        jsonc.add("provisioning", &base64)?;
        jsonc.add("root_certs", self.get_certs_list().to_jsonc()?)?;

        if let Some(value) = self.get_id()? {
            jsonc.add("provisioning", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let base64 = jsonc.get::<&str>("provisioning")?;
        let provisioning = match general_purpose::STANDARD.decode(base64) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "certificate-install-req-from-jsonc",
                    "fail to decode base64 provisioning"
                )
            }
        };
        let cert_list = CertificateRootList::from_jsonc(jsonc.get("root_certs")?)?;
        let mut payload = CertificateInstallRequest::new(&provisioning, &cert_list)?;

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

        let mut base64 = String::new();
        general_purpose::STANDARD.encode_string(self.get_public_key(), &mut base64);
        jsonc.add("public_key", &base64)?;

        let mut base64 = String::new();
        general_purpose::STANDARD.encode_string(self.get_contract_signature(), &mut base64);
        jsonc.add("contract_signature", &base64)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let id_ref = jsonc.get("id")?;
        let contract_id = jsonc.get("emaid")?;
        let contract_chain = CertificateChainType::from_jsonc(jsonc.get("contract_chain")?)?;

        let base64 = jsonc.get::<&str>("public_key")?;
        let public_key = match general_purpose::STANDARD.decode(base64) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "certificate-install-req-from-jsonc",
                    "fail to decode base64 public_key"
                )
            }
        };

        let base64 = jsonc.get::<&str>("contract_signature")?;
        let contract_signature = match general_purpose::STANDARD.decode(base64) {
            Ok(value) => value,
            Err(_) => {
                return afb_error!(
                    "certificate-install-req-to-jsonc",
                    "fail to decode base64 public_key"
                )
            }
        };

        let payload = CertificateInstallResponse::new(
            rcode,
            id_ref,
            contract_id,
            &contract_chain,
            &contract_signature,
            &public_key,
        )?;
        Ok(Box::new(payload))
    }
}
