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

impl IsoToJson for ServiceTag {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id())?;
        jsonc.add("category", self.get_category().to_label())?;
        if let Some(value) = self.get_name() {
            jsonc.add("name", value)?;
        }
        if let Some(value) = self.get_scope() {
            jsonc.add("scope", value)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let category = ServiceCategory::from_label(jsonc.get("category")?)?;
        let mut payload = ServiceTag::new(id, category);
        if let Some(value) = jsonc.optional("name")? {
            payload.set_name(value)?;
        }
        if let Some(value) = jsonc.optional("scope")? {
            payload.set_scope(value)?;
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceCharging {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("tag", self.get_tag().to_jsonc()?)?;
        jsonc.add("transfer", self.get_transfer().to_label())?;
        jsonc.add("isfree", self.get_isfree())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let tag = ServiceTag::from_jsonc(jsonc.get("tag")?)?;
        let transfer= EvRequestTransfertMode::from_label(jsonc.get("transfer")?)?;
        let isfree = jsonc.get("isfree")?;
        let payload = ServiceCharging::new(tag.as_ref(), transfer, isfree);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceOther {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("tag", self.get_tag().to_jsonc()?)?;
        jsonc.add("isfree", self.get_isfree())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let tag = ServiceTag::from_jsonc(jsonc.get("tag")?)?;
        let isfree = jsonc.get("isfree")?;
        let payload = ServiceOther::new(&tag, isfree);
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceDiscoveryRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        if let Some(value) = self.get_scope() {
            jsonc.add("scope", value)?;
        }

        if let Some(value) = self.get_category() {
            jsonc.add("category", value.to_label())?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let mut payload = ServiceDiscoveryRequest::new();
        if let Some(value) = jsonc.optional::<&str>("scope")? {
            payload.set_scope(value)?;
        }
        if let Some(value) = jsonc.optional::<&str>("category")? {
            payload.set_category(ServiceCategory::from_label(value)?);
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceDiscoveryResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("charging", self.get_charging().to_jsonc()?)?;

        let payments = self.get_payments();
        if payments.len() > 0 {
            let jpay = JsoncObj::array();
            for payment in payments {
                jpay.insert(payment.clone().to_label())?;
            }
            jsonc.add("payments", jpay)?;
        }

        if let Some(value) = self.get_service() {
            jsonc.add("service", value.to_jsonc()?)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let charging= ServiceCharging::from_jsonc(jsonc.get("charging")?)?;
        let mut payload = ServiceDiscoveryResponse::new(rcode, &charging);

        if let Some(values) = jsonc.optional::<JsoncObj>("payments")? {
            for idx in 0..values.count()? {
                payload.add_payment(PaymentOption::from_label(values.index(idx)?)?)?;
            }
        }


        if let Some(value) = jsonc.optional("service")? {
            payload.set_service(ServiceOther::from_jsonc(value)?.as_ref());
        }

        Ok(Box::new(payload))
    }
}
