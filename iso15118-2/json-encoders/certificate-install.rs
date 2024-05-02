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
use base64::{engine::general_purpose, Engine as _};
use iso15118::prelude::iso2::*;

impl IsoToJson for CertificateInstallRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("id", self.get_id()?)?;
        let mut encode = String::new();
        general_purpose::STANDARD.encode_string(self.get_provisioning(), &mut encode);
        jsonc.add("provisioning", &encode)?;
        jsonc.add("certs", self.get_certs_list().to_jsonc()?)?;

        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
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
        let cert_list = CertificateRootList::from_jsonc(jsonc.get::<JsoncObj>("certs")?)?;
        let payload = CertificateInstallRequest::new(id, &provisioning, &cert_list)?;
        Ok(Box::new(payload))
    }
}

impl IsoToJson for CertificateInstallResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("contract", self.get_contract_chain().to_jsonc()?)?;
        jsonc.add("provisioning", self.get_provisioning_chain().to_jsonc()?)?;
        jsonc.add("private_key", self.get_private_key().to_jsonc()?)?;
        jsonc.add("public_key", self.get_public_key().to_jsonc()?)?;
        jsonc.add("emaid", self.get_emaid().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let provisioning = CertificateChainType::from_jsonc(jsonc.get("provisioning")?)?;
        let contract = CertificateChainType::from_jsonc(jsonc.get("contract")?)?;
        let private = PrivateKeyType::from_jsonc(jsonc.get("private_key")?)?;
        let public = DhPublicKeyType::from_jsonc(jsonc.get("public_key")?)?;
        let emaid = EmaidType::from_jsonc(jsonc.get("emaid")?)?;
        let payload = CertificateInstallResponse::new(
            rcode,
            contract.as_ref(),
            provisioning.as_ref(),
            private.as_ref(),
            public.as_ref(),
            emaid.as_ref(),
        );
        Ok(Box::new(payload))
    }
}
