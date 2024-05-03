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

impl IsoToJson for PaymentServiceOpt {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("service_id", self.get_service_id())?;
        if let Some(value) = self.get_param_id() {
            jsonc.add("param_id",value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let service_id= jsonc.get("service_id")?;
        let param_id= jsonc.optional("param_id")?;
        let payload= PaymentServiceOpt::new(service_id, param_id);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PaymentSelectionRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("option", self.get_option().to_label())?;
        let services = self.get_services();
        if services.len() > 0 {
            let jservices = JsoncObj::array();
            for service in services {
                jservices.insert(service.to_jsonc()?)?;
            }
            jsonc.add("services", jservices)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let option= PaymentOption::from_label(jsonc.get("option")?)?;
        let mut payload = PaymentSelectionRequest::new(option);
        if let Some(values) = jsonc.optional::<JsoncObj>("services")?{
            for idx in 0 .. values.count()? {
                let value= values.index(idx)?;
                payload.add_service(PaymentServiceOpt::from_jsonc(value)?.as_ref())?;
            }
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for PaymentSelectionResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get::<&str>("rcode")?)?;
        let payload= PaymentSelectionResponse::new(rcode);
        Ok(Box::new(payload))
    }
}
