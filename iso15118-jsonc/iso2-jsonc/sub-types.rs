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

use afbv4::prelude::*;
use crate::prelude::*;
use base64::{engine::general_purpose, Engine as _};
use iso15118::prelude::{iso2_exi::*, v2g::SupportedAppProtocolConf};

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

impl IsoToJson for EmaidType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id()?)?;
        jsonc.add("data", self.get_data()?)?;
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let data = jsonc.get("data")?;
        Ok(Box::new(EmaidType::new(id, data)?))
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
        let id = jsonc.get("id")?;
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

impl IsoToJson for IssuerSerialType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("issuer", self.get_issuer()?)?;
        jsonc.add("serial", self.get_serial())?;
        Ok(jsonc)
    }

    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let issuer = jsonc.get("issuer")?;
        let serial = jsonc.get("serial")?;
        Ok(Box::new(IssuerSerialType::new(issuer, serial)?))
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
        let id = jsonc.get("id")?;
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
        let certs = self.get_certs()?;
        if certs.len() == 0 {
            return afb_error!("certificate-root-to-jsonc", "(hoops) empty chain list");
        }

        let jsonc = JsoncObj::array();
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
        let mut root_list = CertificateRootList::new(IssuerSerialType::from_jsonc(jcert)?.as_ref())?;

        for idx in 1..jsonc.count()? {
            root_list
                .add_cert(IssuerSerialType::from_jsonc(jsonc.index::<JsoncObj>(idx)?)?.as_ref())?;
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
        let base64 = jsonc.get::<&str>("cert")?;
        let data = match general_purpose::STANDARD.decode(base64) {
            Ok(decoded) => decoded,
            Err(error) => return afb_error!("mater-info-from_jsonc", error.to_string()),
        };
        let mut cert_chain = CertificateChainType::new(&data)?;

        if let Some(value) = jsonc.optional::<&str>("id")? {
            cert_chain.set_id(value)?;
        }

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
        let id = jsonc.get("id")?;
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
        let ready = jsonc.get("ready")?;
        let error = DcEvErrorCode::from_label(jsonc.get("error")?)?;
        let evresssoc = jsonc.get("evresssoc")?;
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
        let notification = EvseNotification::from_label(jsonc.get("notification")?)?;
        let delay = jsonc.get("delay")?;
        let ac_status = AcEvseStatusType::from_jsonc(jsonc.get("ac_status")?)?;
        let dc_status = DcEvseStatusType::from_jsonc(jsonc.get("dc_status")?)?;
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
        let notification = EvseNotification::from_label(jsonc.get("notification")?)?;
        let delay = jsonc.get("delay")?;
        let rcd = jsonc.get("rcd")?;
        Ok(Box::new(AcEvseStatusType::new(notification, delay, rcd)))
    }
}

impl IsoToJson for DcEvseStatusType {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("error", self.get_error().to_label())?;
        jsonc.add("notification", self.get_notification().to_label())?;
        jsonc.add("delay", self.get_delay())?;

        if let Some(value) = self.get_isolation_status() {
            jsonc.add("isolation_status", value.to_label())?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let error = DcEvseErrorCode::from_label(jsonc.get("error")?)?;
        let notification = EvseNotification::from_label(jsonc.get("notification")?)?;
        let delay = jsonc.get("delay")?;
        let mut payload = DcEvseStatusType::new(error, notification, delay);

        if let Some(value) = jsonc.optional("isolation_status")? {
            payload.set_isolation_status(IsolationStatus::from_label(value)?);
        }
        Ok(Box::new(payload))
    }
}

impl IsoToJson for DcEvseChargeParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("max_voltage", self.get_max_voltage().to_jsonc()?)?;
        jsonc.add("min_voltage", self.get_min_voltage().to_jsonc()?)?;
        jsonc.add("max_current", self.get_max_current().to_jsonc()?)?;
        jsonc.add("min_current", self.get_min_current().to_jsonc()?)?;
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
        let status = DcEvseStatusType::from_jsonc(jsonc.get("status")?)?;
        let max_voltage = PhysicalValue::from_jsonc(jsonc.get("max_voltage")?)?;
        let min_voltage = PhysicalValue::from_jsonc(jsonc.get("min_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get("max_current")?)?;
        let min_current = PhysicalValue::from_jsonc(jsonc.get("min_current")?)?;
        let max_power = PhysicalValue::from_jsonc(jsonc.get("max_power")?)?;
        let current_ripple = PhysicalValue::from_jsonc(jsonc.get("current_ripple")?)?;
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

impl IsoToJson for AcEvseChargeParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("status", self.get_status().to_jsonc()?)?;
        jsonc.add("nom_voltage", self.get_nominate_voltage().to_jsonc()?)?;
        jsonc.add("max_current", self.get_max_current().to_jsonc()?)?;

        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let status = AcEvseStatusType::from_jsonc(jsonc.get("status")?)?;
        let nom_voltage = PhysicalValue::from_jsonc(jsonc.get("max_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get("max_current")?)?;
        let param =
            AcEvseChargeParam::new(status.as_ref(), nom_voltage.as_ref(), max_current.as_ref());
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
        let status = DcEvStatusType::from_jsonc(jsonc.get("status")?)?;
        let max_voltage = PhysicalValue::from_jsonc(jsonc.get("max_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get("max_current")?)?;
        let mut param = DcEvChargeParam::new(status.as_ref(), max_voltage.as_ref(), max_current.as_ref())?;

        if let Ok(jvalue) = jsonc.get("max_power") {
            param.set_max_power(PhysicalValue::from_jsonc(jvalue)?.as_ref())?;
        }
        if let Ok(jvalue) = jsonc.get("energy_capacity") {
            param.set_energy_capacity(PhysicalValue::from_jsonc(jvalue)?.as_ref())?;
        }
        if let Ok(value) = jsonc.get("departure_time") {
            param.set_departure_time(value);
        }
        if let Ok(value) = jsonc.get("bulk_soc") {
            param.set_bulk_soc(value);
        }
        if let Ok(value) = jsonc.get("full_soc") {
            param.set_full_soc(value);
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
        let ea_mount = PhysicalValue::from_jsonc(jsonc.get("ea_mount")?)?;
        let max_voltage = PhysicalValue::from_jsonc(jsonc.get("max_voltage")?)?;
        let max_current = PhysicalValue::from_jsonc(jsonc.get("max_current")?)?;
        let min_current = PhysicalValue::from_jsonc(jsonc.get("min_current")?)?;
        let mut param = AcEvChargeParam::new(&ea_mount, &max_voltage, &max_current, &min_current)?;
        if let Ok(value) = jsonc.get("departure_time") {
            param.set_departure_time(value);
        }
        Ok(Box::new(param))
    }
}

impl IsoToJson for EvChargeParam {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("ac_param", self.get_ac_param().to_jsonc()?)?;
        jsonc.add("dc_param", self.get_dc_param().to_jsonc()?)?;
        if let Some(value) = self.get_departure_time() {
            jsonc.add("departure_time", value)?;
        }
        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {

        let ac_param = AcEvChargeParam::from_jsonc(jsonc.get("ac_param")?)?;
        let dc_param = DcEvChargeParam::from_jsonc(jsonc.get("dc_param")?)?;
        let mut param = EvChargeParam::new(&ac_param, &dc_param);
        if let Ok(value) = jsonc.get("departure_time") {
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
        let unit = PhysicalUnit::from_label(jsonc.get("unit")?)?;
        let multiplier = jsonc.default::<i8>("multiplier", 1)?;
        let value = jsonc.get::<i16>("value")?;
        Ok(Box::new(PhysicalValue::new(value, multiplier, unit)))
    }
}

impl IsoToJson for ParamSet {
    fn to_jsonc(&self) -> Result<JsoncObj, AfbError> {
        let jsonc = JsoncObj::new();
        jsonc.add("id", self.get_id())?;
        let prms = self.get_params()?;
        if prms.len() > 0 {
            let jprms = JsoncObj::array();
            for idx in 0..prms.len() {
                let prm = &prms[idx];
                let jprm = JsoncObj::new();
                jprm.add("name", prm.get_name()?)?;
                jprm.add("value", prm.get_value()?.to_jsonc()?)?;
                jprms.insert(jprm)?;
            }
            jsonc.add("prms", jprms)?;
        }

        Ok(jsonc)
    }
    fn from_jsonc(jsonc: JsoncObj) -> Result<Box<Self>, AfbError> {
        let id = jsonc.get("id")?;
        let mut this = ParamSet::new(id);
        if let Some(jvalue) = jsonc.optional::<JsoncObj>("prms")? {
            for idx in 0..jvalue.count()? {
                let jprm = jvalue.index::<JsoncObj>(idx)?;
                let name = jprm.get("name")?;
                let value = jprm.get("value")?;
                let prm = ParamTuple::new(name, ParamValue::from_jsonc(value)?.as_ref())?;
                this.add_param(&prm)?;
            }
        }
        Ok(Box::new(this))
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
        let this = match jsonc.get("type")? {
            "bool" => {
                let value = jsonc.get("value")?;
                ParamValue::Bool(value)
            }

            "i8" => {
                let value = jsonc.get("value")?;
                ParamValue::Int8(value)
            }

            "i16" => {
                let value = jsonc.get("value")?;
                ParamValue::Int16(value)
            }

            "i32" => {
                let value = jsonc.get("value")?;
                ParamValue::Int32(value)
            }

            "physical" => {
                let value = jsonc.get("value")?;
                ParamValue::PhyValue(*PhysicalValue::from_jsonc(value)?)
            }

            "string" => {
                let value = jsonc.get("value")?;
                ParamValue::Text(value)
            }

            _ => {
                return afb_error!(
                    "param-value-from-json",
                    "invalid value type:{} value:{}",
                    jsonc.get::<JsoncObj>("type")?,
                    jsonc.get::<JsoncObj>("value")?
                )
            }
        };
        Ok(Box::new(this))
    }
}
