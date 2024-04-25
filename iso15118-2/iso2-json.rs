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

use afbv4::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use iso15118::prelude::{iso2::*, v2g::SupportedAppProtocolConf, *};

pub trait IsoToJson {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError>;
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError>;
}

impl IsoToJson for SupportedAppProtocolConf {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("name", self.get_name())?;
        jsonc.add("schema", self.get_schema().to_label())?;
        jsonc.add("major", self.get_major())?;
        jsonc.add("minor", self.get_minor())?;
        Ok(jsonc)
    }
    fn from_jsonc(_jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        return afb_error!("supported-app-protocol-conf", "from_jsonc not implemented");
    }
}

impl IsoToJson for ChargingProfileEntry {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("start", self.get_start())?;
        jsonc.add("power_max", self.get_power_max().to_jsonc()?)?;
        if let Some(value) = self.get_phases_max() {
            jsonc.add("phases_max", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let start = jsonc.get::<u32>("start")?;
        let power_max = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("power_max")?)?;
        let phase_max = jsonc.optional::<i8>("phases_max")?;
        Ok(Box::new(ChargingProfileEntry::new(
            start, *power_max, phase_max,
        )))
    }
}

impl IsoToJson for DcEvPowerDeliveryParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("charge_complete", self.get_charge_complete())?;
        if let Some(value) = self.get_bulk_complete() {
            jsonc.add("bulk_complete", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status = DcEvStatusType::from_jsonc(jsonc.get::<JsoncObj>("status")?)?;
        let charge_complete = jsonc.get::<bool>("charge_complete")?;
        let bulk_complete = jsonc.optional::<bool>("charge_complete")?;
        Ok(Box::new(DcEvPowerDeliveryParam::new(
            *status,
            charge_complete,
            bulk_complete,
        )))
    }
}

impl IsoToJson for EmaidType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id()?)?;
        jsonc.add("data", self.get_data()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<&str>("id")?;
        let data = jsonc.get::<&str>("data")?;
        Ok(Box::new(EmaidType::new(id, &data)?))
    }
}

impl IsoToJson for PrivateKeyType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id()?)?;
        let mut encode = String::new();
        general_purpose::STANDARD.encode_string(self.get_data(), &mut encode);
        jsonc.add("data", &encode)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<&str>("id")?;
        let base64 = jsonc.get::<&str>("data")?;
        let data = match general_purpose::STANDARD.decode(base64) {
            Ok(value) => value,
            Err(_error) => {
                return afb_error!("private-key-from-jsonc", "fail to decode base64 data",)
            }
        };
        Ok(Box::new(PrivateKeyType::new(id, &data)?))
    }
}

impl IsoToJson for CertificateData {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("issuer", self.get_issuer())?;
        jsonc.add("serial", self.get_serial())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let issuer = jsonc.get::<&str>("issuer")?;
        let serial = jsonc.get::<i32>("serial")?;
        Ok(Box::new(CertificateData::new(issuer, serial)))
    }
}

impl IsoToJson for DhPublicKeyType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id()?)?;
        let mut encode = String::new();
        general_purpose::STANDARD.encode_string(self.get_data(), &mut encode);
        jsonc.add("data", &encode)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<&str>("id")?;
        let base64 = jsonc.get::<&str>("data")?;
        let data = match general_purpose::STANDARD.decode(base64) {
            Ok(value) => value,
            Err(_error) => {
                return afb_error!("dh-private-key-from-jsonc", "fail to decode base64 data",)
            }
        };
        Ok(Box::new(DhPublicKeyType::new(id, &data)?))
    }
}

impl IsoToJson for CertificateRootList {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();

        let certs = self.get_certs()?;
        if certs.len() == 0 {
            return afb_error!("certificate-root-to-jsonc", "(hoops) empty chain list");
        }

        let jcerts = JsoncObj::array();
        jsonc.add("certs", jcerts)?;
        for cert in certs {
            jsonc.insert(cert.to_jsonc()?)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        if !jsonc.is_type(Jtype::Array) || jsonc.count()? == 0 {
            return afb_error!(
                "certificate-root-from-jsonc",
                "(hoops) chain should be an array of root cert"
            );
        }

        let jcert = jsonc.index::<JsoncObj>(0)?;
        let mut root_list = CertificateRootList::new(&*CertificateData::from_jsonc(jcert)?)?;

        for idx in 1..jsonc.count()? {
            let jcert = jsonc.index::<JsoncObj>(idx)?;
            root_list.add_cert(&*CertificateData::from_jsonc(jcert)?)?;
        }
        Ok(Box::new(root_list))
    }
}

impl IsoToJson for CertificateChainType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        if let Some(value) = self.get_id() {
            jsonc.add("id", value)?;
        }
        let mut encode = String::new();
        general_purpose::STANDARD.encode_string(self.get_cert(), &mut encode);
        jsonc.add("cert", &encode)?;

        let subcerts = self.get_subcerts();
        if subcerts.len() > 0 {
            let jsubcerts = JsoncObj::array();
            for subcert in subcerts {
                let mut encode = String::new();
                general_purpose::STANDARD.encode_string(subcert, &mut encode);
                jsubcerts.insert(&encode)?;
            }
            jsonc.add("sub_certs", jsubcerts)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<&str>("id")?;
        let base64 = jsonc.get::<&str>("cert")?;
        let data = match general_purpose::STANDARD.decode(base64) {
            Ok(decoded) => decoded,
            Err(error) => return afb_error!("mater-info-from_jsonc", error.to_string()),
        };
        let mut cert_chain = CertificateChainType::new(id, &data)?;

        if let Some(jsub_certs) = jsonc.optional::<JsoncObj>("sub_certs")? {
            for idx in 0..jsub_certs.count()? {
                let data = jsub_certs.index::<&str>(idx)?;
                match general_purpose::STANDARD.decode(data) {
                    Ok(value) => {
                        cert_chain.add_subcert(&value)?;
                    }
                    Err(_error) => {
                        return afb_error!(
                            "certificate-chain-from-jsonc",
                            "fail to decode subcert idx:{}",
                            idx
                        )
                    }
                }
            }
        }
        Ok(Box::new(cert_chain))
    }
}

impl IsoToJson for MeterInfoType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id()?)?;

        if let Some(value) = self.get_reading() {
            jsonc.add("reading", value as i64)?;
        }
        if let Some(value) = self.get_status() {
            jsonc.add("status", value as i32)?;
        }
        if let Some(value) = self.get_tmeter() {
            jsonc.add("tmeter", value)?;
        }

        if let Some(value) = self.get_sig() {
            let mut encode = String::new();
            general_purpose::STANDARD.encode_string(value, &mut encode);
            jsonc.add("sig", &encode)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get::<&str>("id")?;
        let mut meter_info = MeterInfoType::new(id)?;

        if let Some(value) = jsonc.optional::<u64>("reading")? {
            meter_info.set_reading(value);
        }

        if let Some(value) = jsonc.optional::<i16>("status")? {
            meter_info.set_status(value);
        }

        if let Some(value) = jsonc.optional::<i64>("tmeter")? {
            meter_info.set_tmeter(value);
        }

        if let Some(base64) = jsonc.optional::<&str>("sig")? {
            match general_purpose::STANDARD.decode(base64) {
                Ok(decoded) => {
                    meter_info.set_sig(&decoded)?;
                }
                Err(error) => return afb_error!("mater-info-from_jsonc", error.to_string()),
            }
        }

        Ok(Box::new(meter_info))
    }
}

impl IsoToJson for DcEvStatusType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("ready", self.get_ready())?;
        jsonc.add("error", self.get_error().to_label())?;
        jsonc.add("evresssoc", self.get_evresssoc() as i32)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let ready = jsonc.get::<bool>("ready")?;
        let error = DcEvErrorCode::from_label(jsonc.get::<&str>("error")?)?;
        let evresssoc = jsonc.get::<i8>("evresssoc")?;
        Ok(Box::new(DcEvStatusType::new(ready, error, evresssoc)))
    }
}

impl IsoToJson for EvseStatusType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("notification", self.get_notification().to_label())?;
        jsonc.add("delay", self.get_delay() as u32)?;
        jsonc.add("ac_status", self.get_ac_status().to_jsonc()?)?;
        jsonc.add("dc_status", self.get_dc_status().to_jsonc()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let notification = EvseNotification::from_label(jsonc.get::<&str>("notification")?)?;
        let delay = jsonc.get::<u16>("delay")?;
        let ac_status = AcEvseStatusType::from_jsonc(jsonc.get::<JsoncObj>("ac_status")?)?;
        let dc_status = DcEvseStatusType::from_jsonc(jsonc.get::<JsoncObj>("dc_status")?)?;
        Ok(Box::new(EvseStatusType::new(
            notification,
            delay,
            &ac_status,
            &dc_status,
        )))
    }
}

impl IsoToJson for AcEvseStatusType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("notification", self.get_notification().to_label())?;
        jsonc.add("delay", self.get_delay() as u32)?;
        jsonc.add("rcd", self.get_rcd())?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let notification = EvseNotification::from_label(jsonc.get::<&str>("notification")?)?;
        let delay = jsonc.get::<u16>("delay")?;
        let rcd = jsonc.get::<bool>("rcd")?;
        Ok(Box::new(AcEvseStatusType::new(notification, delay, rcd)))
    }
}

impl IsoToJson for DcEvseStatusType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("error", self.get_error().to_label())?;
        jsonc.add("notification", self.get_notification().to_label())?;
        jsonc.add("delay", self.get_delay() as u32)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let error = DcEvseErrorCode::from_label(jsonc.get::<&str>("error")?)?;
        let notification = EvseNotification::from_label(jsonc.get::<&str>("error")?)?;
        let delay = jsonc.get::<u16>("delay")?;
        let status = DcEvseStatusType::new(error, notification, delay);
        Ok(Box::new(status))
    }
}

impl IsoToJson for DcEvseChargeParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("max_voltage", self.get_max_voltage().to_jsonc()?)?;
        jsonc.add("min_voltage", self.get_min_voltage().to_jsonc()?)?;
        jsonc.add("max_current", self.get_max_current().to_jsonc()?)?;
        jsonc.add("min_voltage", self.get_min_current().to_jsonc()?)?;
        jsonc.add("max_power", self.get_max_power().to_jsonc()?)?;
        jsonc.add("current_ripple", self.get_peak_current_ripple().to_jsonc()?)?;

        if let Some(value) = self.get_regul_tolerance() {
            jsonc.add("regul_tolerance", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_energy_to_deliver() {
            jsonc.add("energy_to_deliver", value.to_jsonc()?)?;
        }

        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status = DcEvseStatusType::from_jsonc(jsonc.get::<JsoncObj>("status")?)?;
        let max_voltage = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("max_voltage")?)?;
        let min_voltage = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("min_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("max_current")?)?;
        let min_current = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("min_current")?)?;
        let max_power = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("max_power")?)?;
        let current_ripple = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("current_ripple")?)?;
        let param = DcEvseChargeParam::new(
            &*status,
            &*max_voltage,
            &*min_voltage,
            &*max_current,
            &*min_current,
            &*max_power,
            &*current_ripple,
        )?;
        Ok(Box::new(param))
    }
}

impl IsoToJson for DcEvChargeParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("max_voltage", self.get_max_voltage().to_jsonc()?)?;
        jsonc.add("max_current", self.get_max_current().to_jsonc()?)?;

        if let Some(value) = self.get_max_power() {
            jsonc.add("max_power", value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_energy_capacity() {
            jsonc.add("energy_capacity", &value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_energy_request() {
            jsonc.add("energy_request", &value.to_jsonc()?)?;
        }
        if let Some(value) = self.get_departure_time() {
            jsonc.add("departure_time", value)?;
        }
        if let Some(value) = self.get_bulk_soc() {
            jsonc.add("bulk_soc", value)?;
        }
        if let Some(value) = self.get_full_soc() {
            jsonc.add("full_soc", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status = DcEvStatusType::from_jsonc(jsonc.get::<JsoncObj>("ea_mount")?)?;
        let max_voltage = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("max_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("min_voltage")?)?;
        let mut param = DcEvChargeParam::new(&*status, &*max_voltage, &*max_current)?;

        if let Ok(jvalue) = jsonc.get::<JsoncObj>("max_power") {
            param.set_max_power(&*PhysicalValue::from_jsonc(jvalue)?);
        }
        if let Ok(jvalue) = jsonc.get::<JsoncObj>("energy_capacity") {
            param.set_energy_capacity(&*PhysicalValue::from_jsonc(jvalue)?);
        }
        if let Ok(value) = jsonc.get::<u32>("departure_time") {
            param.set_departure_time(value);
        }
        if let Ok(value) = jsonc.get::<i8>("bulk_soc") {
            param.set_bulk_soc(value);
        }
        if let Ok(value) = jsonc.get::<i8>("full_soc") {
            param.set_full_soc(value as i8);
        }
        Ok(Box::new(param))
    }
}

impl IsoToJson for AcEvChargeParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("ea_mount", self.get_ea_mount().to_jsonc()?)?;
        jsonc.add("max_voltage", self.get_max_voltage().to_jsonc()?)?;
        jsonc.add("max_current", self.get_max_current().to_jsonc()?)?;
        jsonc.add("min_current", self.get_min_current().to_jsonc()?)?;
        if let Some(value) = self.get_departure_time() {
            jsonc.add("departure_time", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let ea_mount = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("ea_mount")?)?;
        let max_voltage = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("max_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("min_voltage")?)?;
        let min_current = PhysicalValue::from_jsonc(jsonc.get::<JsoncObj>("min_current")?)?;
        let mut param = AcEvChargeParam::new(&ea_mount, &max_voltage, &max_current, &min_current)?;
        if let Ok(value) = jsonc.get::<u32>("departure_time") {
            param.set_departure_time(value);
        }
        Ok(Box::new(param))
    }
}

impl IsoToJson for PhysicalValue {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("value", self.get_value() as i32)?;
        jsonc.add("multiplier", self.get_multiplier() as i32)?;
        jsonc.add("unit", self.get_unit().to_label())?;
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let unit = PhysicalUnit::from_label(jsonc.get::<&str>("unit")?)?;
        let multiplier = jsonc.default::<i8>("multiplier", 1)?;
        let value = jsonc.get::<i16>("value")?;
        Ok(Box::new(PhysicalValue::new(value, multiplier, unit)))
    }
}

impl IsoToJson for ParamValue {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        match self {
            ParamValue::Bool(value) => {
                jsonc.add("type", "bool")?;
                jsonc.add("value", value.clone())?;
            }
            ParamValue::Int8(value) => {
                jsonc.add("type", "i8")?;
                jsonc.add("value", value.clone() as i32)?;
            }
            ParamValue::Int16(value) => {
                jsonc.add("type", "i16")?;
                jsonc.add("value", value.clone() as i32)?;
            }
            ParamValue::Int32(value) => {
                jsonc.add("type", "i32")?;
                jsonc.add("value", value.clone())?;
            }
            ParamValue::Text(value) => {
                jsonc.add("type", "string")?;
                jsonc.add("value", value)?;
            }
            ParamValue::PhyValue(value) => {
                jsonc.add("type", "physical")?;
                jsonc.add("value", value.to_jsonc()?)?;
            }
        }
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let this = match jsonc.get::<&str>("type")? {
            "bool" => {
                let value = jsonc.get::<bool>("value")?;
                ParamValue::Bool(value)
            }

            "i8" => {
                let value = jsonc.get::<i8>("value")?;
                ParamValue::Int8(value)
            }

            "i16" => {
                let value = jsonc.get::<i16>("value")?;
                ParamValue::Int16(value)
            }

            "i32" => {
                let value = jsonc.get::<i32>("value")?;
                ParamValue::Int32(value)
            }

            "physical" => {
                let value = jsonc.get::<JsoncObj>("value")?;
                ParamValue::PhyValue(*PhysicalValue::from_jsonc(value)?)
            }

            _ => {
                return afb_error!(
                    "param-value-from-json",
                    "invalid value type:{}",
                    jsonc.get::<&str>("type")?
                )
            }
        };
        Ok(Box::new(this))
    }
}

pub fn body_to_jsonc(body: &Iso2MessageBody) -> Result<JsoncObj, AfbError> {
    let jsonc = JsoncObj::new();
    jsonc.add("tagid", body.get_tagid().to_label())?;

    match body {
        Iso2MessageBody::SessionSetupReq(payload) => {
            let id = payload.get_id();
            let data = dump_hexa(id);
            jsonc.add("id", data.as_str())?;
        }
        Iso2MessageBody::SessionSetupRes(payload) => {
            let id = payload.get_id()?;
            jsonc.add("id", id)?;
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("stamp", payload.get_time_stamp())?;
        }

        Iso2MessageBody::ServiceDiscoveryReq(payload) => {
            if let Some(value) = payload.get_scope() {
                jsonc.add("scope", value)?;
            }

            if let Some(value) = payload.get_category() {
                jsonc.add("category", value.to_label())?;
            }
        }
        Iso2MessageBody::ServiceDiscoveryRes(payload) => {
            let charging = payload.get_charging()?;
            let transfers = payload.get_transfers()?;
            let payments = payload.get_payments();
            let services = payload.get_services()?;

            jsonc.add("rcode", payload.get_rcode().to_label())?;
            let jcharg = JsoncObj::new();
            jcharg.add("name", charging.get_name().as_str())?;
            jcharg.add("scope", charging.get_scope().as_str())?;
            jcharg.add("isfree", charging.get_isfree())?;
            jsonc.add("charging", jcharg)?;

            let jtrans = JsoncObj::array();
            for idx in 0..transfers.len() {
                jtrans.insert(transfers[idx].clone().to_label())?;
            }
            jsonc.add("transfers", jtrans)?;

            let jpay = JsoncObj::array();
            for idx in 0..payments.len() {
                jpay.insert(payments[idx].clone().to_label())?;
            }
            jsonc.add("transfers", jpay)?;

            let jserv = JsoncObj::array();
            for idx in 0..services.len() {
                let service = &services[idx];
                let jserv = JsoncObj::new();
                jserv.add("id", service.get_id() as u32)?;
                jserv.add("name", service.get_name().as_str())?;
                jserv.add("name", service.get_scope().as_str())?;
                jserv.add("isfree", service.get_isfree())?;
                jserv.add("category", service.get_category().to_label())?;
            }
            jsonc.add("services", jserv)?;
        }
        Iso2MessageBody::ServiceDetailReq(payload) => {
            jsonc.add("id", payload.get_id() as u32)?;
        }

        Iso2MessageBody::ServiceDetailRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            let jpsets = JsoncObj::array();
            for pset in payload.get_psets() {
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
        }

        Iso2MessageBody::AuthorizationReq(payload) => {
            if let Some(id) = payload.get_id() {
                jsonc.add("id", id)?;
            }
            if let Some(challenge) = payload.get_challenge() {
                let mut encode = String::new();
                general_purpose::STANDARD.encode_string(challenge, &mut encode);
                jsonc.add("challenge", &encode)?;
            }
        }

        Iso2MessageBody::AuthorizationRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("processing", payload.get_processing().to_label())?;
        }

        Iso2MessageBody::CableCheckReq(payload) => {
            let jstatus = JsoncObj::new();
            let status = payload.get_status();
            jstatus.add("ready", status.get_ready())?;
            jstatus.add("error", status.get_error().to_label())?;
            jstatus.add("evresssoc", status.get_evresssoc() as u32)?;
            jsonc.add("status", jstatus)?;
        }

        Iso2MessageBody::CableCheckRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;

            let jstatus = JsoncObj::new();
            let status = payload.get_status();
            jstatus.add("error", status.get_error().to_label())?;
            jstatus.add("notification", status.get_notification().to_label())?;
            jstatus.add("delay", status.get_delay() as u32)?;
            jsonc.add("status", jstatus)?;
            jsonc.add("processing", payload.get_processing().to_label())?;
        }

        Iso2MessageBody::CertificateInstallReq(payload) => {
            jsonc.add("id", payload.get_id()?)?;
            let mut encode = String::new();
            general_purpose::STANDARD.encode_string(payload.get_provisioning(), &mut encode);
            jsonc.add("provisioning", &encode)?;
            let jscerts = JsoncObj::array();
            for cert in payload.get_certs_list().get_certs()? {
                let jcert = JsoncObj::new();
                jcert.add("issuer", cert.get_issuer())?;
                jcert.add("serial", cert.get_serial())?;
                jscerts.insert(jcert)?;
            }
            jsonc.add("certs", jscerts)?;
        }

        Iso2MessageBody::CertificateInstallRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("contract", payload.get_contract_chain().to_jsonc()?)?;
            jsonc.add("provisioning", payload.get_provisioning_chain().to_jsonc()?)?;
            jsonc.add("private", payload.get_private_key().to_jsonc()?)?;
            jsonc.add("dh_private", payload.get_public_key().to_jsonc()?)?;
            jsonc.add("emaid", payload.get_emaid().to_jsonc()?)?;
        }

        Iso2MessageBody::CertificateUpdateReq(payload) => {
            jsonc.add("id", payload.get_id()?)?;
            jsonc.add("emaid", payload.get_emaid()?)?;
            jsonc.add("contract", payload.get_contract_chain().to_jsonc()?)?;
            jsonc.add("root_certs", payload.get_root_certs().to_jsonc()?)?;
        }

        Iso2MessageBody::CertificateUpdateRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("contract", payload.get_contract_chain().to_jsonc()?)?;
            jsonc.add("provisioning", payload.get_provisioning_chain().to_jsonc()?)?;
            jsonc.add("private", payload.get_private_key().to_jsonc()?)?;
            jsonc.add("dh_private", payload.get_public_key().to_jsonc()?)?;
            jsonc.add("emaid", payload.get_emaid().to_jsonc()?)?;
        }
        Iso2MessageBody::ParamDiscoveryReq(payload) => {
            if let Some(value) = payload.get_max_schedule_tuple() {
                jsonc.add("max_shed_tuple", value as u32)?;
            }

            if let Some(param) = payload.get_ac_charge_param() {
                jsonc.add("ac_param", param.to_jsonc()?)?;
            }
        }
        Iso2MessageBody::ParamDiscoveryRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("processing", payload.get_processing().to_label())?;
            if let Some(value) = payload.get_schedules() {
                jsonc.add("schedules", value)?;
            }
            if let Some(value) = payload.get_charge_param() {
                jsonc.add("charge_param", value)?;
            }

            let tuples = payload.get_schedule_tuples();
            if tuples.len() > 0 {
                let jtuples = JsoncObj::array();
                for tuple in tuples {
                    let jtuple = JsoncObj::new();
                    jtuple.add("description", tuple.get_description() as u32)?;
                    let pmaxs = tuple.get_pmaxs();
                    if pmaxs.len() > 0 {
                        let jpmaxs = JsoncObj::array();
                        jtuple.add("pmaxs", jpmaxs)?;
                        for pmax in pmaxs {
                            let jpmax = JsoncObj::new();
                            jpmax.add("value", pmax.get_value().to_jsonc()?)?;
                            jpmax.add("start", pmax.get_start())?;
                            jpmax.add("duration", pmax.get_duration())?;
                        }
                    }

                    if let Some(tariff) = tuple.get_tariff() {
                        let jtariff = JsoncObj::new();
                        if let Some(value) = tariff.get_id() {
                            jtariff.add("id", value)?;
                        }
                        if let Some(value) = tariff.get_description() {
                            jtariff.add("description", value)?;
                        }
                        if let Some(value) = tariff.get_price_level() {
                            jtariff.add("price_level", value as u32)?;
                        }

                        let entries = tariff.get_entries();
                        if entries.len() > 0 {
                            let jentries = JsoncObj::new();
                            for entry in entries {
                                let jentry = JsoncObj::new();
                                if let Some(value) = entry.get_start() {
                                    jentry.add("start", value)?;
                                }
                                if let Some(value) = entry.get_duration() {
                                    jentry.add("duration", value)?;
                                }
                                if let Some(value) = entry.get_price() {
                                    jentry.add("price", value as u32)?;
                                }
                                jentries.insert(jentry)?;
                            }
                            jtariff.add("entries", jentries)?;
                        }
                    }
                }
                jsonc.add("tuples", jtuples)?;
            }

            if let Some(charge) = payload.get_evse_dc_charge_param() {
                jsonc.add("dc_charge_param", charge.to_jsonc()?)?;
            }
        }

        Iso2MessageBody::ChargingStatusReq(_payload) => {
            // does not take any param
        }

        Iso2MessageBody::ChargingStatusRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("id", payload.get_id()?)?;
            jsonc.add("tuple", payload.get_tuple_id() as u32)?;
            jsonc.add("status", &payload.get_ac_evse_status().to_jsonc()?)?;

            if let Some(value) = payload.get_meter_info() {
                jsonc.add("meter", value.to_jsonc()?)?;
            }
        }

        Iso2MessageBody::CurrentDemandReq(payload) => {
            jsonc.add("status", payload.get_status().to_jsonc()?)?;
            jsonc.add("voltage_target", payload.get_voltage_target().to_jsonc()?)?;
            jsonc.add("current_target", payload.get_current_target().to_jsonc()?)?;
            jsonc.add("charging_complete", payload.get_charging_complete())?;

            if let Some(value) = payload.get_voltage_limit() {
                jsonc.add("voltage_limit", value.to_jsonc()?)?;
            }
            if let Some(value) = payload.get_current_limit() {
                jsonc.add("current_limit", value.to_jsonc()?)?;
            }
            if let Some(value) = payload.get_power_limit() {
                jsonc.add("power_limit", value.to_jsonc()?)?;
            }
            if let Some(value) = payload.get_time_to_full_sock() {
                jsonc.add("time_to_full_sock", value.to_jsonc()?)?;
            }
            if let Some(value) = payload.get_time_to_bulk_sock() {
                jsonc.add("time_to_bulk_sock", value.to_jsonc()?)?;
            }

            if let Some(value) = payload.get_bulk_complete() {
                jsonc.add("bulk_complete", value)?;
            }
        }

        Iso2MessageBody::CurrentDemandRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("id", payload.get_id()?)?;
            jsonc.add("status", payload.get_status().to_jsonc()?)?;
            jsonc.add("voltage", payload.get_voltage().to_jsonc()?)?;
            jsonc.add("current", payload.get_current().to_jsonc()?)?;
            jsonc.add("current_limit_reach", payload.get_current_limit_reach())?;
            jsonc.add("voltage_limit_reach", payload.get_voltage_limit_reach())?;
            jsonc.add("power_limit_reach", payload.get_power_limit_reach())?;
            jsonc.add("tuple_id", payload.get_tuple_id() as u32)?;

            if let Some(value) = payload.get_voltage_limit() {
                jsonc.add("voltage_limit", value.to_jsonc()?)?;
            }

            if let Some(value) = payload.get_current_limit() {
                jsonc.add("current_limit", value.to_jsonc()?)?;
            }

            if let Some(value) = payload.get_power_limit() {
                jsonc.add("power_limit", value.to_jsonc()?)?;
            }
            if let Some(value) = payload.get_receipt_require() {
                jsonc.add("receipt_require", value)?;
            }
        }

        Iso2MessageBody::MeteringReceiptReq(payload) => {
            jsonc.add(
                "session_id",
                bytes_to_hexa(payload.get_session_id()).as_str(),
            )?;
            jsonc.add("info", payload.get_info().to_jsonc()?)?;
            if let Some(value) = payload.get_id() {
                jsonc.add("id", value)?;
            }
            if let Some(value) = payload.get_tuple_id() {
                jsonc.add("tuple_id", value as u32)?;
            }
        }

        Iso2MessageBody::MeteringReceiptRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;

            if let Some(value) = payload.get_ac_evse_status() {
                jsonc.add("ac_status", value.to_jsonc()?)?;
            }

            if let Some(value) = payload.get_dc_evse_status() {
                jsonc.add("dc_status", value.to_jsonc()?)?;
            }

            if let Some(value) = payload.get_evse_status() {
                jsonc.add("evse_status", value.to_jsonc()?)?;
            }
        }

        Iso2MessageBody::PaymentDetailsReq(payload) => {
            jsonc.add("emaid", payload.get_emaid()?)?;
            jsonc.add("contract", payload.get_contract_chain().to_jsonc()?)?;
        }

        Iso2MessageBody::PaymentDetailsRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("challenge", &bytes_to_hexa(payload.get_challenge()))?;
            jsonc.add("timestamp", payload.get_time_stamp())?;
        }

        Iso2MessageBody::PaymentSelectionReq(payload) => {
            jsonc.add("option", payload.get_option().to_label())?;
            let services = payload.get_services();
            if services.len() > 0 {
                let jservices = JsoncObj::new();
                jsonc.add("services", jservices)?;
                for idx in 0..services.len() {
                    let opts = &services[idx];
                    let jopts = JsoncObj::new();
                    jopts.add("service_id", opts.get_service_id())?;
                    if let Some(value) = opts.get_param_id() {
                        jopts.add("param_id", value)?;
                    }
                }
            }
        }
        Iso2MessageBody::PaymentSelectionRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
        }

        Iso2MessageBody::PowerDeliveryReq(payload) => {
            jsonc.add("charge_progress", payload.get_progress().to_label())?;
            jsonc.add("schedule_id", payload.get_schedule_id())?;
            let profiles = payload.get_charging_profiles();
            if profiles.len() > 0 {
                let jprofiles = JsoncObj::array();
                for idx in 0..profiles.len() {
                    let profile = &profiles[idx];
                    jprofiles.insert(profile.to_jsonc()?)?;
                }
                jsonc.add("charging_profile", jprofiles)?;
            }

            if let Some(value) = payload.get_dc_delivery_params() {
                jsonc.add("dc_delivery_params", value.to_jsonc()?)?;
            }

            if let Some(value) = payload.get_ev_delivery_params() {
                jsonc.add("ev_delivery_params", value)?;
            }
        }

        Iso2MessageBody::PowerDeliveryRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            if let Some(value) = payload.get_ac_evse_status() {
                jsonc.add("ac_evse_status", value.to_jsonc()?)?;
            }
            if let Some(value) = payload.get_dc_evse_status() {
                jsonc.add("dc_evse_status", value.to_jsonc()?)?;
            }
        }

        Iso2MessageBody::PreChargeReq(payload) => {
            jsonc.add("status", payload.get_status().to_jsonc()?)?;
            jsonc.add("target_voltage", payload.get_target_voltage().to_jsonc()?)?;
        }

        Iso2MessageBody::PreChargeRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("status", payload.get_status().to_jsonc()?)?;
            jsonc.add("voltage", payload.get_voltage().to_jsonc()?)?;
        }

        Iso2MessageBody::SessionStopReq(payload) => {
            jsonc.add("action", payload.get_action().to_label())?;
        }

        Iso2MessageBody::SessionStopRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
        }

        Iso2MessageBody::WeldingDetectionReq(payload) => {
            jsonc.add("status", payload.get_status().to_jsonc()?)?;
        }

        Iso2MessageBody::WeldingDetectionRes(payload) => {
            jsonc.add("rcode", payload.get_rcode().to_label())?;
            jsonc.add("status", payload.get_status().to_jsonc()?)?;
            jsonc.add("voltage", payload.get_voltage().to_jsonc()?)?;
        }

        Iso2MessageBody::Unsupported => {
            return afb_error!(
                "body-to_jsonc",
                "(hoops) Tagid:{} unsupported",
                body.get_tagid()
            )
        }
        _ => {}
    }
    Ok(jsonc)
}

pub fn body_from_jsonc(tagid: MessageTagId, jsonc: JsoncObj) -> Result<Iso2BodyType, AfbError> {
    let payload = match tagid {
        MessageTagId::SessionSetupReq => {
            let session_id = jsonc.get::<&str>("id")?;
            let mut session_u8 = [0x0; 6 * 3];
            let len = hexa_to_bytes(session_id, &mut session_u8)?;

            SessionSetupRequest::new(&session_u8[0..len])?.encode()
        }
        MessageTagId::SessionSetupRes => {
            let id = jsonc.get::<&str>("id")?;
            let rcode = ResponseCode::from_label(jsonc.get::<&str>("rcode")?)?;
            SessionSetupResponse::new(id, rcode)?.encode()
        }
        MessageTagId::ServiceDiscoveryReq => {
            let mut payload = ServiceDiscoveryRequest::new();
            if let Some(value) = jsonc.optional::<&str>("scope")? {
                payload.set_scope(value)?;
            }
            if let Some(value) = jsonc.optional::<&str>("category")? {
                payload.set_category(ServiceCategory::from_label(value)?);
            }
            payload.encode()
        }
        // MessageTagId::ServiceDiscoveryRes => MessageTagId::ServiceDiscoveryRes,
        MessageTagId::ServiceDetailReq => {
            let id = jsonc.get::<u32>("id")? as u16;
            ServiceDetailRequest::new(id).encode()
        }

        // MessageTagId::ServiceDetailRes => MessageTagId::ServiceDetailRes,
        // MessageTagId::AuthorizationReq => MessageTagId::AuthorizationReq,
        // MessageTagId::AuthorizationRes => MessageTagId::AuthorizationRes,
        // MessageTagId::BodyElement => MessageTagId::BodyElement,
        // MessageTagId::CableCheckReq => MessageTagId::CableCheckReq,
        // MessageTagId::CableCheckRes => MessageTagId::CableCheckRes,
        // MessageTagId::CertificateInstallReq => MessageTagId::CertificateInstallReq,
        // MessageTagId::CertificateInstallRes => MessageTagId::CertificateInstallRes,
        // MessageTagId::CertificateUpdateReq => MessageTagId::CertificateUpdateReq,
        // MessageTagId::CertificateUpdateRes => MessageTagId::CertificateUpdateRes,
        // MessageTagId::ParamDiscoveryReq => MessageTagId::ParamDiscoveryReq,
        // MessageTagId::ParamDiscoveryRes => MessageTagId::ParamDiscoveryRes,
        // MessageTagId::ChargingStatusReq => MessageTagId::ChargingStatusReq,
        // MessageTagId::ChargingStatusRes => MessageTagId::ChargingStatusRes,
        // MessageTagId::CurrentDemandReq => MessageTagId::CurrentDemandReq,
        // MessageTagId::CurrentDemandRes => MessageTagId::CurrentDemandRes,
        // MessageTagId::MeteringReceiptReq => MessageTagId::MeteringReceiptReq,
        // MessageTagId::MeteringReceiptRes => MessageTagId::MeteringReceiptRes,
        // MessageTagId::PaymentDetailsReq => MessageTagId::PaymentDetailsReq,
        // MessageTagId::PaymentDetailsRes => MessageTagId::PaymentDetailsRes,
        // MessageTagId::PaymentSelectionReq => MessageTagId::PaymentSelectionReq,
        // MessageTagId::PaymentSelectionRes => MessageTagId::PaymentSelectionRes,
        // MessageTagId::PowerDeliveryReq => MessageTagId::PowerDeliveryReq,
        // MessageTagId::PowerDeliveryRes => MessageTagId::PowerDeliveryRes,
        // MessageTagId::PreChargeReq => MessageTagId::PreChargeReq,
        // MessageTagId::PreChargeRes => MessageTagId::PreChargeRes,
        // MessageTagId::SessionStopReq => MessageTagId::SessionStopReq,
        // MessageTagId::SessionStopRes => MessageTagId::SessionStopRes,
        // MessageTagId::WeldingDetectionReq => MessageTagId::WeldingDetectionReq,
        // MessageTagId::WeldingDetectionRes => MessageTagId::WeldingDetectionRes,
        // MessageTagId::Unsupported => MessageTagId::Unsupported
        _ => return afb_error!("hoops", "TBD Fulup"),
    };
    Ok(payload)
}

pub struct ApiMsgInfo {
    pub uid: &'static str,
    pub name: &'static str,
    pub info: &'static str,
    pub msg_id: MessageTagId,
    pub sample: Option<&'static str>,
}

pub fn api_from_tagid(msg_api: &'static str) -> Result<ApiMsgInfo, AfbError> {
    let msg_json = format!("\"{}\"", msg_api);
    let msg_uid = msg_api.to_string().replace("_", "-");
    let msg_id = MessageTagId::from_label(msg_json.as_str())?;

    let api_info = match msg_id {
        MessageTagId::SessionSetupReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "Session setup request",
            sample: Some("{'id':'01:02:03:04:05:06'}"),
        },
        MessageTagId::SessionSetupRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "Session setup response",
            sample: Some("{'id':'tux-evse', 'rcode':'new_session'}"),
        },
        MessageTagId::ServiceDiscoveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "Service discovery request",
            sample: Some("{'scope':'tux-scope', 'category':'ev_charger'}"),
        },
        // MessageTagId::ServiceDiscoveryRes => MessageTagId::ServiceDiscoveryRes,
        MessageTagId::ServiceDetailReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "Service Detail request",
            sample: Some("{'id':1234}"),
        },
        // MessageTagId::ServiceDetailRes => MessageTagId::ServiceDetailRes,
        // MessageTagId::AuthorizationReq => MessageTagId::AuthorizationReq,
        // MessageTagId::AuthorizationRes => MessageTagId::AuthorizationRes,
        // MessageTagId::BodyElement => MessageTagId::BodyElement,
        // MessageTagId::CableCheckReq => MessageTagId::CableCheckReq,
        // MessageTagId::CableCheckRes => MessageTagId::CableCheckRes,
        // MessageTagId::CertificateInstallReq => MessageTagId::CertificateInstallReq,
        // MessageTagId::CertificateInstallRes => MessageTagId::CertificateInstallRes,
        // MessageTagId::CertificateUpdateReq => MessageTagId::CertificateUpdateReq,
        // MessageTagId::CertificateUpdateRes => MessageTagId::CertificateUpdateRes,
        // MessageTagId::ParamDiscoveryReq => MessageTagId::ParamDiscoveryReq,
        // MessageTagId::ParamDiscoveryRes => MessageTagId::ParamDiscoveryRes,
        // MessageTagId::ChargingStatusReq => MessageTagId::ChargingStatusReq,
        // MessageTagId::ChargingStatusRes => MessageTagId::ChargingStatusRes,
        // MessageTagId::CurrentDemandReq => MessageTagId::CurrentDemandReq,
        // MessageTagId::CurrentDemandRes => MessageTagId::CurrentDemandRes,
        // MessageTagId::MeteringReceiptReq => MessageTagId::MeteringReceiptReq,
        // MessageTagId::MeteringReceiptRes => MessageTagId::MeteringReceiptRes,
        // MessageTagId::PaymentDetailsReq => MessageTagId::PaymentDetailsReq,
        // MessageTagId::PaymentDetailsRes => MessageTagId::PaymentDetailsRes,
        // MessageTagId::PaymentSelectionReq => MessageTagId::PaymentSelectionReq,
        // MessageTagId::PaymentSelectionRes => MessageTagId::PaymentSelectionRes,
        // MessageTagId::PowerDeliveryReq => MessageTagId::PowerDeliveryReq,
        // MessageTagId::PowerDeliveryRes => MessageTagId::PowerDeliveryRes,
        // MessageTagId::PreChargeReq => MessageTagId::PreChargeReq,
        // MessageTagId::PreChargeRes => MessageTagId::PreChargeRes,
        // MessageTagId::SessionStopReq => MessageTagId::SessionStopReq,
        // MessageTagId::SessionStopRes => MessageTagId::SessionStopRes,
        // MessageTagId::WeldingDetectionReq => MessageTagId::WeldingDetectionReq,
        // MessageTagId::WeldingDetectionRes => MessageTagId::WeldingDetectionRes,
        // MessageTagId::Unsupported => MessageTagId::Unsupported
        _ => return afb_error!("hoops", "TBD Fulup"),
    };
    Ok(api_info)
}
