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
use iso15118::prelude::{iso2::*, *};

fn str_to_json(value: &str) -> String {
    format!("\"{}\"", value)
}

fn json_to_str(value: &String) -> &str {
    &value[1..value.len() - 1]
}

pub fn body_to_json(body: &Iso2MessageBody) -> Result<JsoncObj, AfbError> {
    let jsonc = JsoncObj::new();
    let tag_id = body.get_tagid().to_json()?;
    jsonc.add("tagid", tag_id.as_str())?;

    match body {
        Iso2MessageBody::SessionSetupReq(payload) => {
            let id = payload.get_id();
            let data = dump_hexa(id);
            jsonc.add("id", data.as_str())?;
        }
        Iso2MessageBody::SessionSetupRes(payload) => {
            let id = payload.get_id()?;
            let rcode = payload.get_rcode().to_json()?;
            jsonc.add("id", id)?;
            jsonc.add("rcode", rcode.as_str())?;
            jsonc.add("stamp", payload.get_time_stamp())?;
        }

        Iso2MessageBody::ServiceDiscoveryReq(payload) => {
            if let Some(value) = payload.get_scope() {
                jsonc.add("scope", value)?;
            }

            if let Some(value) = payload.get_category() {
                let json = value.to_json()?;
                jsonc.add("category", json_to_str(&json))?;
            }
        }
        Iso2MessageBody::ServiceDiscoveryRes(payload) => {
            let rcode = payload.get_rcode().to_json()?;
            let charging = payload.get_charging()?;
            let transfers = payload.get_transfers()?;
            let payments = payload.get_payments();
            let services = payload.get_services()?;

            jsonc.add("rcode",  json_to_str(&rcode))?;

            let jcharg= JsoncObj::new();
            jcharg.add("name", charging.get_name().as_str())?;
            jcharg.add("scope", charging.get_scope().as_str())?;
            jcharg.add("isfree", charging.get_isfree())?;
            jsonc.add("charging", jcharg)?;

            let jtrans= JsoncObj::array();
            for idx in 0 .. transfers.len() {
                let transfer= transfers[idx].clone().to_json()?;
                jtrans.insert( json_to_str(&transfer))?;
            }
            jsonc.add("transfers", jtrans)?;

            let jpay= JsoncObj::array();
            for idx in 0 .. payments.len() {
                let payment= payments[idx].clone().to_json()?;
                jpay.insert( json_to_str(&payment))?;
            }
            jsonc.add("transfers", jpay)?;

            let jserv= JsoncObj::array();
            for idx in 0 .. services.len() {
                let service= &services[idx];
                let jserv= JsoncObj::new();
                jserv.add("id",service.get_id() as u32)?;
                jserv.add("name",service.get_name().as_str())?;
                jserv.add("name",service.get_scope().as_str())?;
                jserv.add("isfree",service.get_isfree())?;
                let jcat = service.get_category().to_json()?;
                jserv.add("category",json_to_str(&jcat))?;
            }
            jsonc.add("services", jserv)?;
        }
        // Iso2MessageBody::ServiceDetailReq(_) => MessageTagId::ServiceDetailReq,
        // Iso2MessageBody::ServiceDetailRes(_) => MessageTagId::ServiceDetailRes,
        // Iso2MessageBody::AuthorizationReq(_) => MessageTagId::AuthorizationReq,
        // Iso2MessageBody::AuthorizationRes(_) => MessageTagId::AuthorizationRes,
        // Iso2MessageBody::BodyElement(_) => MessageTagId::BodyElement,
        // Iso2MessageBody::CableCheckReq(_) => MessageTagId::CableCheckReq,
        // Iso2MessageBody::CableCheckRes(_) => MessageTagId::CableCheckRes,
        // Iso2MessageBody::CertificateInstallReq(_) => MessageTagId::CertificateInstallReq,
        // Iso2MessageBody::CertificateInstallRes(_) => MessageTagId::CertificateInstallRes,
        // Iso2MessageBody::CertificateUpdateReq(_) => MessageTagId::CertificateUpdateReq,
        // Iso2MessageBody::CertificateUpdateRes(_) => MessageTagId::CertificateUpdateRes,
        // Iso2MessageBody::ParamDiscoveryReq(_) => MessageTagId::ParamDiscoveryReq,
        // Iso2MessageBody::ParamDiscoveryRes(_) => MessageTagId::ParamDiscoveryRes,
        // Iso2MessageBody::ChargingStatusReq(_) => MessageTagId::ChargingStatusReq,
        // Iso2MessageBody::ChargingStatusRes(_) => MessageTagId::ChargingStatusRes,
        // Iso2MessageBody::CurrentDemandReq(_) => MessageTagId::CurrentDemandReq,
        // Iso2MessageBody::CurrentDemandRes(_) => MessageTagId::CurrentDemandRes,
        // Iso2MessageBody::MeteringReceiptReq(_) => MessageTagId::MeteringReceiptReq,
        // Iso2MessageBody::MeteringReceiptRes(_) => MessageTagId::MeteringReceiptRes,
        // Iso2MessageBody::PaymentDetailsReq(_) => MessageTagId::PaymentDetailsReq,
        // Iso2MessageBody::PaymentDetailsRes(_) => MessageTagId::PaymentDetailsRes,
        // Iso2MessageBody::PaymentSelectionReq(_) => MessageTagId::PaymentSelectionReq,
        // Iso2MessageBody::PaymentSelectionRes(_) => MessageTagId::PaymentSelectionRes,
        // Iso2MessageBody::PowerDeliveryReq(_) => MessageTagId::PowerDeliveryReq,
        // Iso2MessageBody::PowerDeliveryRes(_) => MessageTagId::PowerDeliveryRes,
        // Iso2MessageBody::PreChargeReq(_) => MessageTagId::PreChargeReq,
        // Iso2MessageBody::PreChargeRes(_) => MessageTagId::PreChargeRes,
        // Iso2MessageBody::SessionStopReq(_) => MessageTagId::SessionStopReq,
        // Iso2MessageBody::SessionStopRes(_) => MessageTagId::SessionStopRes,
        // Iso2MessageBody::WeldingDetectionReq(_) => MessageTagId::WeldingDetectionReq,
        // Iso2MessageBody::WeldingDetectionRes(_) => MessageTagId::WeldingDetectionRes,
        // Iso2MessageBody::Unsupported => MessageTagId::Unsupported
        _ => {}
    }
    Ok(jsonc)
}

pub fn body_from_json(tagid: MessageTagId, jsonc: JsoncObj) -> Result<Iso2BodyType, AfbError> {
    println! ("*** body_from_json tagid:{:?} jsonc:{}", tagid, jsonc);
    let payload = match tagid {
        MessageTagId::SessionSetupReq => {
            let session_id = jsonc.get::<&str>("id")?;
            let mut session_u8 = [0x0; 6 * 3];
            let len = hexa_to_byte(session_id, &mut session_u8)?;

            SessionSetupRequest::new(&session_u8[0..len])?.encode()
        }
        MessageTagId::SessionSetupRes => {
            let id = jsonc.get::<&str>("id")?;
            let rcode = str_to_json(jsonc.get::<&str>("rcode")?);
            SessionSetupResponse::new(id, ResponseCode::from_json(rcode.as_str())?)?.encode()
        }
        MessageTagId::ServiceDiscoveryReq => {
            let scope = jsonc.get::<&str>("scope")?;
            let category = str_to_json(jsonc.get::<&str>("category")?);

            ServiceDiscoveryRequest::new()
                .set_scope(scope)?
                .set_category(ServiceCategory::from_json(category.as_str())?)
                .encode()
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
    let msg_id = MessageTagId::from_json(msg_json.as_str())?;

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
