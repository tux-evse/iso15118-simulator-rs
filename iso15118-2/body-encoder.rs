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
use crate::prelude::*;
use iso15118::prelude::{iso2::*, *};

pub fn body_to_jsonc(body: &Iso2MessageBody) -> Result<JsoncObj, AfbError> {
    let jsonc = match body {
        Iso2MessageBody::SessionSetupReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::SessionSetupRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::ServiceDiscoveryReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::ServiceDiscoveryRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::ServiceDetailReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::ServiceDetailRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::AuthorizationReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::AuthorizationRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::CableCheckReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::CableCheckRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::CertificateInstallReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::CertificateInstallRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::CertificateUpdateReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::CertificateUpdateRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::ParamDiscoveryReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::ParamDiscoveryRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::ChargingStatusReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::ChargingStatusRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::CurrentDemandReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::CurrentDemandRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::MeteringReceiptReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::MeteringReceiptRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::PaymentDetailsReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::PaymentDetailsRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::PaymentSelectionReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::PaymentSelectionRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::PowerDeliveryReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::PowerDeliveryRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::PreChargeReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::PreChargeRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::SessionStopReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::SessionStopRes(payload) => payload.to_jsonc(),
        Iso2MessageBody::WeldingDetectionReq(payload) => payload.to_jsonc(),
        Iso2MessageBody::WeldingDetectionRes(payload) => payload.to_jsonc(),
        _ => {
            return afb_error!(
                "body-to-jsonc",
                "(hoops) Tagid:{} unsupported",
                body.get_tagid()
            )
        }
    }?;
    jsonc.add("tagid", body.get_tagid().to_label())?;
    Ok(jsonc)
}

pub fn body_from_jsonc(tagid: MessageTagId, jsonc: JsoncObj) -> Result<Iso2BodyType, AfbError> {
    let payload = match tagid {
        MessageTagId::SessionSetupReq => SessionSetupRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::SessionSetupRes => SessionSetupResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::ServiceDiscoveryReq => ServiceDiscoveryRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::ServiceDetailReq => ServiceDetailRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::ServiceDetailRes => ServiceDetailResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::AuthorizationReq => AuthorizationRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::AuthorizationRes => AuthorizationResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::CableCheckReq => CableCheckRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::CableCheckRes => CableCheckResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::CertificateInstallReq => CertificateInstallRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::CertificateInstallRes => CertificateInstallResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::CertificateUpdateReq => CertificateUpdateRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::CertificateUpdateRes => CertificateUpdateResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::ParamDiscoveryReq => ParamDiscoveryRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::ParamDiscoveryRes => ParamDiscoveryResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::ChargingStatusReq => ChargingStatusRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::ChargingStatusRes => ChargingStatusResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::CurrentDemandReq => CurrentDemandRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::CurrentDemandRes => CurrentDemandResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::MeteringReceiptReq => MeteringReceiptRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::MeteringReceiptRes => MeteringReceiptResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::PaymentDetailsReq => PaymentDetailsRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::PaymentDetailsRes => PaymentDetailsResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::PaymentSelectionReq => PaymentSelectionRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::PaymentSelectionRes => PaymentSelectionResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::PowerDeliveryReq => PowerDeliveryRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::PowerDeliveryRes => PowerDeliveryResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::PreChargeReq => PreChargeRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::PreChargeRes => PreChargeResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::SessionStopReq => SessionStopRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::SessionStopRes => SessionStopResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::WeldingDetectionReq => WeldingDetectionRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::WeldingDetectionRes => WeldingDetectionResponse::from_jsonc(jsonc)?.encode(),

        _ => return afb_error!("body-from-jsonc", "(hoops) not implemented"),
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
        MessageTagId::ServiceDiscoveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "Service Detail response",
            sample: Some("{'id':1234}"),
        },
        MessageTagId::ServiceDetailReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "Service Detail request",
            sample: Some("{'id':1234}"),
        },
        MessageTagId::ServiceDetailRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::AuthorizationReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::AuthorizationRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::BodyElement => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CableCheckReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CableCheckRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CertificateInstallReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CertificateInstallRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CertificateUpdateReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CertificateUpdateRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::ParamDiscoveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::ParamDiscoveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::ChargingStatusReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::ChargingStatusRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CurrentDemandReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::CurrentDemandRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::MeteringReceiptReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::MeteringReceiptRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PaymentDetailsReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PaymentDetailsRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PaymentSelectionReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PaymentSelectionRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PowerDeliveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PowerDeliveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PreChargeReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::PreChargeRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::SessionStopReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::SessionStopRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::WeldingDetectionReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },
        MessageTagId::WeldingDetectionRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "xxx",
            sample: None,
        },

        _ => return afb_error!("hoops", "Unknown message"),
    };
    Ok(api_info)
}
