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

use super::prelude::*;
use afbv4::prelude::*;
use iso15118::prelude::iso2::*;

impl IsoToJson for CurrentDemandRequest {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("voltage_target", self.get_voltage_target().to_jsonc()?)?;
        jsonc.add("current_target", self.get_current_target().to_jsonc()?)?;
        jsonc.add("charging_complete", self.get_charging_complete())?;

        if let Some(value) = self.get_voltage_limit() {
            jsonc.add("voltage_limit", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_current_limit() {
            jsonc.add("current_limit", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_power_limit() {
            jsonc.add("power_limit", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_time_to_full_sock() {
            jsonc.add("time_to_full_sock", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_time_to_bulk_sock() {
            jsonc.add("time_to_bulk_sock", value.to_jsonc()?)?;
        }

        if let Some(value) = self.get_bulk_complete() {
            jsonc.add("bulk_complete", value)?;
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let dc_status = DcEvStatusType::from_jsonc(jsonc.get("status")?)?;
        let current_target = PhysicalValue::from_jsonc(jsonc.get("current_target")?)?;
        let voltage_target = PhysicalValue::from_jsonc(jsonc.get("voltage_target")?)?;
        let charging_complete = jsonc.get("charging_complete")?;
        let mut payload = CurrentDemandRequest::new(
            dc_status.as_ref(),
            current_target.as_ref(),
            voltage_target.as_ref(),
            charging_complete,
        );

        if let Some(value) = jsonc.optional("voltage_limit")? {
            payload.set_voltage_limit(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("current_limit")? {
            payload.set_current_limit(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("power_limit")? {
            payload.set_power_limit(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }
        if let Some(value) = jsonc.optional("bulk_complete")? {
            payload.set_bulk_complete(value);
        }

        if let Some(value) = jsonc.optional("time_to_bulk_sock")? {
            payload.set_time_to_bulk_sock(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }

        Ok(Box::new(payload))
    }
}

impl IsoToJson for CurrentDemandResponse {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("rcode", self.get_rcode().to_label())?;
        jsonc.add("id", self.get_id()?)?;
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("voltage", self.get_voltage().to_jsonc()?)?;
        jsonc.add("current", self.get_current().to_jsonc()?)?;
        jsonc.add("current_limit_reach", self.get_current_limit_reach())?;
        jsonc.add("voltage_limit_reach", self.get_voltage_limit_reach())?;
        jsonc.add("power_limit_reach", self.get_power_limit_reach())?;
        jsonc.add("tuple_id", self.get_tuple_id() as u32)?;

        if let Some(value) = self.get_voltage_limit() {
            jsonc.add("voltage_limit", value.to_jsonc()?)?;
        }

        if let Some(value) = self.get_current_limit() {
            jsonc.add("current_limit", value.to_jsonc()?)?;
        }

        if let Some(value) = self.get_power_limit() {
            jsonc.add("power_limit", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_receipt_require() {
            jsonc.add("receipt_require", value)?;
        }

        if let Some(value) = self.get_meter_info() {
            jsonc.add("meter_info", value.to_jsonc()?)?;
        }

        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let evse_id = jsonc.get("id")?;
        let rcode = ResponseCode::from_label(jsonc.get("rcode")?)?;
        let dc_status = DcEvseStatusType::from_jsonc(jsonc.get("status")?)?;
        let current = PhysicalValue::from_jsonc(jsonc.get("current")?)?;
        let voltage = PhysicalValue::from_jsonc(jsonc.get("voltage")?)?;
        let current_limit = jsonc.get("current_limit_reach")?;
        let voltage_limit = jsonc.get("voltage_limit_reach")?;
        let power_limit = jsonc.get("power_limit_reach")?;
        let schd_tuple_id = jsonc.get("tuple_id")?;

        let mut payload = CurrentDemandResponse::new(
            rcode,
            evse_id,
            dc_status.as_ref(),
            current.as_ref(),
            current_limit,
            voltage.as_ref(),
            voltage_limit,
            power_limit,
            schd_tuple_id,
        )?;

        if let Some(value) = jsonc.optional("voltage_limit")? {
            payload.set_voltage_limit(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("current_limit")? {
            payload.set_current_limit(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("power_limit")? {
            payload.set_power_limit(PhysicalValue::from_jsonc(value)?.as_ref())?;
        }

        if let Some(value) = jsonc.optional("receipt_require")? {
            payload.set_receipt_require(value);
        }

        if let Some(value) = jsonc.optional("meter_info")? {
            payload.set_meter_info(MeterInfoType::from_jsonc(value)?.as_ref());
        }

        Ok(Box::new(payload))
    }
}
