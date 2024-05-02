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

impl IsoToJson for ServiceCharging {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("isfree", self.get_isfree())?;
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
        let isfree = jsonc.get("isfree")?;
        let mut payload = ServiceCharging::new(id, isfree);
        if let Some(value) = jsonc.optional("name")? {
            payload.set_name(value)?;
        }
        if let Some(value) = jsonc.optional("scope")? {
            payload.set_scope(value)?;
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for ServiceOther {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id())?;
        jsonc.add("isfree", self.get_isfree())?;
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
        let isfree = jsonc.get("isfree")?;
        let category = ServiceCategory::from_label(jsonc.get("categoty")?)?;
        let mut payload = ServiceOther::new(id, category, isfree);
        if let Some(value) = jsonc.optional("name")? {
            payload.set_name(value)?;
        }
        if let Some(value) = jsonc.optional("scope")? {
            payload.set_scope(value)?;
        }
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
        let transfers = self.get_transfers()?;
        let payments = self.get_payments();
        let services = self.get_services()?;

        jsonc.add("rcode", self.get_rcode().to_label())?;

        if let Some(value) = self.get_charging() {
            jsonc.add("charging", value.to_jsonc()?)?;
        }

        if transfers.len() > 0 {
            let jtrans = JsoncObj::array();
            for idx in 0..transfers.len() {
                jtrans.insert(transfers[idx].clone().to_label())?;
            }
            jsonc.add("transfers", jtrans)?;
        }

        if payments.len() > 0 {
            let jpay = JsoncObj::array();
            for payment in payments {
                jpay.insert(payment.clone().to_label())?;
            }
            jsonc.add("payments", jpay)?;
        }

        if services.len() > 0 {
            let jserv = JsoncObj::array();
            for service in services {
                jserv.insert(service.to_jsonc()?)?;
            }
            jsonc.add("services", jserv)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let mut payload = ServiceDiscoveryResponse::new(rcode);

        if let Some(value) = jsonc.optional("charging")? {
            payload.set_charging(ServiceCharging::from_jsonc(value)?.as_ref());
        }

        if let Some(values) = jsonc.optional::<JsoncObj>("transfers")? {
            for idx in 0..values.count()? {
                payload.add_transfer(EngyTransfertMode::from_label(values.index(idx)?)?)?;
            }
        }

        if let Some(values) = jsonc.optional::<JsoncObj>("payments")? {
                for idx in 0 .. values.count()? {
                    payload.add_payment(PaymentOption::from_label(values.index(idx)?)?)?;
                }
        }

        if let Some(values) = jsonc.optional::<JsoncObj>("services")? {
                for idx in 0 .. values.count()? {
                    payload.add_service(ServiceOther::from_jsonc(values.index(idx)?)?.as_ref())?;
                }
        }

        Ok(Box::new(payload))
    }
}
