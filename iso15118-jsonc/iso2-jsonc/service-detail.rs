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

impl IsoToJson for ServiceDetailRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id() as u32)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let payload = ServiceDetailRequest::new(id);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceDetailResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("id", self.get_id())?;
        let psets = self.get_psets();
        if psets.len() > 0 {
            let jpsets = JsoncObj::array();
            for pset in psets {
                jpsets.insert(pset.to_jsonc()?)?;
            }
            jsonc.add("psets", jpsets)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let mut payload = ServiceDetailResponse::new(id, rcode);

        if let Some(jvalue) = jsonc.optional::<JsoncObj>("psets")? {
            for idx in 0..jvalue.count()? {
                let pset = ParamSet::from_jsonc(jvalue.index(idx)?)?;
                payload.add_pset(pset.as_ref())?;
            }
        }
        Ok(Box::new(payload))
    }
}
