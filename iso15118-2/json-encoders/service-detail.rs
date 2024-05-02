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

impl IsoToJson for ServiceDetailRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id() as u32)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<u16>("id")?;
        let payload = ServiceDetailRequest::new(id);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceDetailResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        let jsonc = JsoncObj::new();
        let jpsets = JsoncObj::array();
        for pset in self.get_psets() {
            let jpset = JsoncObj::new();
            jpset.add("id", pset.get_id() as i32)?;
            let jprms = JsoncObj::array();
            for prm in pset.get_params()? {
                let jprm = JsoncObj::new();
                jprm.add("name", prm.get_name())?;
                jprm.add("value", prm.get_value().to_jsonc()?)?;
                jprms.insert(jprm)?;
            }
        }
        jsonc.add("params", jpsets)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<u16>("id")?;
        let rcode = ResponseCode::from_label(jsonc.get::<&str>("rcode")?)?;
        let mut payload = ServiceDetailResponse::new(id, rcode);

        if let Some(jvalue) = jsonc.optional::<JsoncObj>("psets")? {
            for idx in 0..jvalue.count()? {
                let pset = ParamSet::from_jsonc(jvalue.index(idx)?)?;
                payload.add_pset(&*pset)?;
            }
        }
        Ok(Box::new(payload))
    }
}
