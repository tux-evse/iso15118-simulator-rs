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
    let msg_uid = msg_api.to_string().replace("_", "-");
    let msg_id = MessageTagId::from_label(msg_api)?;

    let api_info = match msg_id {
        MessageTagId::SessionSetupReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.2.2 [V2G2-188][V2G2-189][V2G2-879]",
            sample: Some("{'id':'[01,02,03,04,05,06]'}"),
        },
        MessageTagId::SessionSetupRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.2.2 [V2G2-190][V2G2-191]",
            sample: Some("{'id':'tux-evse', 'rcode':'new_session'}"),
        },
        MessageTagId::ServiceDiscoveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.3.2 [V2G2-193][V2G2-194]",
            sample: Some("{'scope':'tux-scope', 'category':'ev_charger'}"),
        },
        MessageTagId::ServiceDiscoveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.3.3 [V2G2-195][V2G2-196]",
            sample: Some("{'id':1234}"),
        },
        MessageTagId::ServiceDetailReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.4.1 [V2G2-197][V2G2-198]",
            sample: Some("{'id':1234}"),
        },
        MessageTagId::ServiceDetailRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.4.2 [V2G2-199][V2G2-200]",
            sample: None,
        },
        MessageTagId::AuthorizationReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.7.1 [V2G2-210]..[V2G2-698]",
            sample: None,
        },
        MessageTagId::AuthorizationRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.7.2 [V2G2-212]..[V2G2-901]",
            sample: None,
        },
        MessageTagId::CableCheckReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.2.2 [V2G2-249][V2G2-250]",
            sample: None,
        },
        MessageTagId::CableCheckRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.2.3 [V2G2-251][V2G2-252]",
            sample: None,
        },
        MessageTagId::CertificateInstallReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.11.2 [V2G2-235][V2G2-236][V2G2-893][V2G2-894]",
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
            info: "§8.4.3.10.2 [V2G2-228]..[V2G2-889]",
            sample: None,
        },
        MessageTagId::CertificateUpdateRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.10.3 [V2G2-230]..[V2G2-892]",
            sample: None,
        },
        MessageTagId::ParamDiscoveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.8.2 [V2G2-214]..[V2G2-785]",
            sample: None,
        },
        MessageTagId::ParamDiscoveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "8.4.3.8.3 [V2G2-218]..[V2G2-220]",
            sample: None,
        },
        MessageTagId::ChargingStatusReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.4.2.2 [V2G2-242]",
            sample: None,
        },
        MessageTagId::ChargingStatusRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.4.2.3 [V2G2-243][V2G2-244]",
            sample: None,
        },
        MessageTagId::CurrentDemandReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.4.2 [V2G2-257][V2G2-258]",
            sample: None,
        },
        MessageTagId::CurrentDemandRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.4.3 [V2G2-259][V2G2-260]",
            sample: None,
        },
        MessageTagId::MeteringReceiptReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.13.2 [V2G2-245]..[V2G2-904]",
            sample: None,
        },
        MessageTagId::MeteringReceiptRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.13.3 [V2G2-247][V2G2-248]",
            sample: None,
        },
        MessageTagId::PaymentDetailsReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.6.2 [V2G2-205][V2G2-206]",
            sample: None,
        },
        MessageTagId::PaymentDetailsRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.6.3 [V2G2-208]..[V2G2-899]",
            sample: None,
        },
        MessageTagId::PaymentSelectionReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.5.2 [V2G2-201][V2G2-202]",
            sample: None,
        },
        MessageTagId::PaymentSelectionRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.5.3 [V2G2-203][V2G2-204]",
            sample: None,
        },
        MessageTagId::PowerDeliveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.9.2 [V2G2-221][V2G2-222]",
            sample: None,
        },
        MessageTagId::PowerDeliveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.9.3 [V2G2-223]..[V2G2-226]",
            sample: None,
        },
        MessageTagId::PreChargeReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.3.2 [V2G2-253][V2G2-254]",
            sample: None,
        },
        MessageTagId::PreChargeRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.3.3 [V2G2-255][V2G2-256]",
            sample: None,
        },
        MessageTagId::SessionStopReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.12.2 [V2G2-239][V2G2-738]",
            sample: None,
        },
        MessageTagId::SessionStopRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.3.12.3 [V2G2-240][V2G2-241]",
            sample: None,
        },
        MessageTagId::WeldingDetectionReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.5.2 [V2G2-261]",
            sample: None,
        },
        MessageTagId::WeldingDetectionRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id,
            name: msg_api,
            info: "§8.4.5.5.3 [V2G2-263][V2G2-264]",
            sample: None,
        },

        _ => return afb_error!("hoops", "Unknown message"),
    };
    Ok(api_info)
}
