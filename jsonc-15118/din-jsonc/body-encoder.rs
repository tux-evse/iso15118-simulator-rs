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

pub fn body_to_jsonc(body: &MessageBody) -> Result<JsoncObj, AfbError> {
    let jsonc = match body {
        MessageBody::SessionSetupReq(payload) => payload.to_jsonc(),
        MessageBody::SessionSetupRes(payload) => payload.to_jsonc(),
        MessageBody::ServiceDiscoveryReq(payload) => payload.to_jsonc(),
        MessageBody::ServiceDiscoveryRes(payload) => payload.to_jsonc(),
        MessageBody::ServiceDetailReq(payload) => payload.to_jsonc(),
        MessageBody::ServiceDetailRes(payload) => payload.to_jsonc(),
        MessageBody::ContractAuthenticationReq(payload) => payload.to_jsonc(),
        MessageBody::ContractAuthenticationRes(payload) => payload.to_jsonc(),
        MessageBody::CableCheckReq(payload) => payload.to_jsonc(),
        MessageBody::CableCheckRes(payload) => payload.to_jsonc(),
        MessageBody::CertificateInstallReq(payload) => payload.to_jsonc(),
        MessageBody::CertificateInstallRes(payload) => payload.to_jsonc(),
        MessageBody::CertificateUpdateReq(payload) => payload.to_jsonc(),
        MessageBody::CertificateUpdateRes(payload) => payload.to_jsonc(),
        MessageBody::ParamDiscoveryReq(payload) => payload.to_jsonc(),
        MessageBody::ParamDiscoveryRes(payload) => payload.to_jsonc(),
        MessageBody::ChargingStatusReq(payload) => payload.to_jsonc(),
        MessageBody::ChargingStatusRes(payload) => payload.to_jsonc(),
        MessageBody::CurrentDemandReq(payload) => payload.to_jsonc(),
        MessageBody::CurrentDemandRes(payload) => payload.to_jsonc(),
        MessageBody::MeteringReceiptReq(payload) => payload.to_jsonc(),
        MessageBody::MeteringReceiptRes(payload) => payload.to_jsonc(),
        MessageBody::PaymentDetailsReq(payload) => payload.to_jsonc(),
        MessageBody::PaymentDetailsRes(payload) => payload.to_jsonc(),
        MessageBody::PaymentSelectionReq(payload) => payload.to_jsonc(),
        MessageBody::PaymentSelectionRes(payload) => payload.to_jsonc(),
        MessageBody::PowerDeliveryReq(payload) => payload.to_jsonc(),
        MessageBody::PowerDeliveryRes(payload) => payload.to_jsonc(),
        MessageBody::PreChargeReq(payload) => payload.to_jsonc(),
        MessageBody::PreChargeRes(payload) => payload.to_jsonc(),
        MessageBody::SessionStopReq(payload) => payload.to_jsonc(),
        MessageBody::SessionStopRes(payload) => payload.to_jsonc(),
        MessageBody::WeldingDetectionReq(payload) => payload.to_jsonc(),
        MessageBody::WeldingDetectionRes(payload) => payload.to_jsonc(),
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

pub fn body_from_jsonc(tagid: MessageTagId, jsonc: JsoncObj) -> Result<DinBodyType, AfbError> {
    let payload = match tagid {
        MessageTagId::SessionSetupReq => SessionSetupRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::SessionSetupRes => SessionSetupResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::ServiceDiscoveryReq => ServiceDiscoveryRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::ServiceDetailReq => ServiceDetailRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::ServiceDetailRes => ServiceDetailResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::ContractAuthenticationReq => {
            ContractAuthenticationRequest::from_jsonc(jsonc)?.encode()
        }
        MessageTagId::ContractAuthenticationRes => {
            ContractAuthenticationResponse::from_jsonc(jsonc)?.encode()
        }
        MessageTagId::CableCheckReq => CableCheckRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::CableCheckRes => CableCheckResponse::from_jsonc(jsonc)?.encode(),
        MessageTagId::CertificateInstallReq => {
            CertificateInstallRequest::from_jsonc(jsonc)?.encode()
        }
        MessageTagId::CertificateInstallRes => {
            CertificateInstallResponse::from_jsonc(jsonc)?.encode()
        }
        MessageTagId::CertificateUpdateReq => CertificateUpdateRequest::from_jsonc(jsonc)?.encode(),
        MessageTagId::CertificateUpdateRes => {
            CertificateUpdateResponse::from_jsonc(jsonc)?.encode()
        }
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

pub fn api_from_tagid(msg_api: &'static str) -> Result<ApiMsgInfo, AfbError> {
    let msg_uid = msg_api.to_string().replace("_", "-");
    let msg_id = MessageTagId::from_label(msg_api)?;

    let api_info = match msg_id {
        MessageTagId::SessionSetupReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.2.2 [V2G2-188][V2G2-189][V2G2-879]",
            sample: Some("{'id':'[01,02,03,04,05,06]'}"),
        },
        MessageTagId::SessionSetupRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.2.2 [V2G2-190][V2G2-191]",
            sample: Some("{'id':'tux-evse-001','rcode':'ok'}"),
        },
        MessageTagId::ServiceDiscoveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.3.2 [V2G2-193][V2G2-194]",
            sample: Some("{'scope':'sample-scope','category':'ev_charger'}"),
        },
        MessageTagId::ServiceDiscoveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.3.3 [V2G2-195][V2G2-196]",
            sample: Some("{'rcode':'ok','charging':{'id':1,'isfree':false,'name':'Tux-Evse'},'transfers':['ac_single_phase','dc_basic'],'payments':['contract','external'],'services':[{'id':56,'isfree':true,'category':'internet','name':'LTE','scope':'Network'},{'id':29,'isfree':true,'category':'other','name':'OTA','scope':'Update'}]}"),
        },
        MessageTagId::ServiceDetailReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.4.1 [V2G2-197][V2G2-198]",
            sample: Some("{'id':1234}"),
        },
        MessageTagId::ServiceDetailRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.4.2 [V2G2-199][V2G2-200]",
            sample: Some("{'rcode':'ok','id':56,'psets':[{'id':1,'prms':[{'name':'prm_1','set':{'type':'i16','value':123}},{'name':'prm_2','set':{'type':'string','value':'snoopy'}},{'name':'prm_3','set':{'type':'physical','value':{'value':240,'multiplier':1,'unit':'volt'}}}]},{'id':2,'prms':[{'name':'prm_1','set':{'type':'i16','value':1234}},{'name':'prm_2','set':{'type':'string','value':'Mme Kermichu'}},{'name':'prm_3','set':{'type':'physical','value':{'value':10,'multiplier':1,'unit':'ampere'}}}]}]}"),
        },
        MessageTagId::ContractAuthenticationReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.7.1 [V2G2-210]..[V2G2-698]",
            sample: Some("{'id':'tux-evse','challenge':'AQIDBA=='}"),
        },
        MessageTagId::ContractAuthenticationRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.7.2 [V2G2-212]..[V2G2-901]",
            sample: Some("'rcode':'new_session','processing':'finished'}"),
        },
        MessageTagId::CableCheckReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.5.2.2 [V2G2-249][V2G2-250]",
            sample:  Some("{'status':{'ready':true,'error':'no_error','evresssoc':16}}")
        },
        MessageTagId::CableCheckRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.5.2.3 [V2G2-251][V2G2-252]",
            sample: Some("{'rcode':'new_session','status':{'error':'ready','notification':'re_negotiation','delay':160},'processing':'ongoing'}"),
        },
        MessageTagId::CertificateInstallReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.11.2 [V2G2-235][V2G2-236][V2G2-893][V2G2-894]",
            sample: Some("{'id':'tux-evse','provisioning':'AQIDBAUG','certs':[{'issuer':'IoT.bzh','serial':1234},{'issuer':'Redpesk.bzh','serial':5678}]}"),
        },
        MessageTagId::CertificateInstallRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.11.3",
            sample: Some("{'rcode':'new_session','contract':{'id':'Contract-TuxEvSE','cert':'oaKjpKWm','sub_certs':['sbKztLW2','wcLDxMXG']},'provisioning':{'id':'Cert-TuxEvSE','cert':'AQIDBAUG','sub_certs':['ERITFBUW','ISIjJCUm']},'private_key':{'id':'Private_TuxEvSe','data':'0dLT1NXW'},'public_key':{'id':'public_TuxEvSe','data':'4eLj5OXm'},'emaid':{'id':'emaid_TuxEvSE','data':'my emaid testing string'}}"),
        },
        MessageTagId::CertificateUpdateReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.10.2 [V2G2-228]..[V2G2-889]",
            sample: Some("{'id':'tux-evse','emaid':'tux-emaid','contract':{'id':'Contract-TuxEvSE','cert':'oaKjpKWm','sub_certs':['sbKztLW2','wcLDxMXG']},'root_certs':[{'issuer':'IoT.bzh','serial':1234},{'issuer':'Redpesk.bzh','serial':5678}]}"),
        },
        MessageTagId::CertificateUpdateRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.10.3 [V2G2-230]..[V2G2-892]",
            sample: Some("{'rcode':'new_session','contract':{'id':'Contract-TuxEvSE','cert':'oaKjpKWm','sub_certs':['sbKztLW2','wcLDxMXG']},'provisioning':{'id':'Cert-TuxEvSE','cert':'AQIDBAUG','sub_certs':['ERITFBUW','ISIjJCUm']},'private_key':{'id':'Private_TuxEvSe','data':'0dLT1NXW'},'public_key':{'id':'public_TuxEvSe','data':'4eLj5OXm'},'emaid':{'id':'emaid_TuxEvSE','data':'my emaid testing string'}}"),
        },
        MessageTagId::ParamDiscoveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.8.2 [V2G2-214]..[V2G2-785]",
            sample: Some("{'transfer_mode':'ac_single_phase','max_shed_tuple':16,'ac_param':{'ea_mount':{'value':20,'multiplier':10,'unit':'wh'},'max_voltage':{'value':400,'multiplier':1,'unit':'volt'},'max_current':{'value':64,'multiplier':1,'unit':'ampere'},'min_current':{'value':10,'multiplier':1,'unit':'ampere'},'departure_time':1234}}"),
        },
        MessageTagId::ParamDiscoveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "8.4.3.8.3 [V2G2-218]..[V2G2-220]",
            sample: Some("{'rcode':'ok','processing':'ongoing','tuples':[{'description':1,'pmax':[{'start':1,'duration':2,'value':{'value':240,'multiplier':1,'unit':'volt'}},{'start':1,'duration':2,'value':{'value':10,'multiplier':1,'unit':'ampere'}}]},{'description':1,'pmax':[{'start':1,'duration':2,'value':{'value':400,'multiplier':1,'unit':'volt'}},{'start':1,'duration':2,'value':{'value':100,'multiplier':1,'unit':'ampere'}}]}],'evse_dc_charge_param':{'status':{'error':'ready','notification':'re_negotiation','delay':160},'max_voltage':{'value':250,'multiplier':1,'unit':'volt'},'min_voltage':{'value':200,'multiplier':1,'unit':'volt'},'max_current':{'value':64,'multiplier':1,'unit':'ampere'},'min_current':{'value':10,'multiplier':1,'unit':'ampere'},'max_power':{'value':6400,'multiplier':100,'unit':'watt'},'current_ripple':{'value':1,'multiplier':1,'unit':'volt'}}}"),
        },
        MessageTagId::ChargingStatusReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.4.2.2 [V2G2-242]",
            sample: Some("{}"),
        },
        MessageTagId::ChargingStatusRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.4.2.3 [V2G2-243][V2G2-244]",
            sample: Some("{'rcode':'ok','evse_id':'tux-evse-001','tuple_id':64,'status':{'notification':'stop_charging','delay':1234,'rcd':true}}"),
        },
        MessageTagId::CurrentDemandReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.5.4.2 [V2G2-257][V2G2-258]",
            sample: Some("{'status':{'ready':true,'error':'no_error','evresssoc':1},'voltage_target':{'value':400,'multiplier':1,'unit':'volt'},'current_target':{'value':80,'multiplier':1,'unit':'ampere'},'charging_complete':true,'voltage_limit':{'value':800,'multiplier':1,'unit':'volt'}}"),
        },
        MessageTagId::CurrentDemandRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.5.4.3 [V2G2-259][V2G2-260]",
            sample: Some("{'rcode':'ok','id':'tux-evse-001','status':{'error':'not_ready','notification':'stop_charging','delay':1234,'isolation_status':'warning'},'voltage':{'value':400,'multiplier':1,'unit':'volt'},'current':{'value':64,'multiplier':1,'unit':'ampere'},'current_limit_reach':true,'voltage_limit_reach':false,'power_limit_reach':true,'tuple_id':56}"),
        },
        MessageTagId::MeteringReceiptReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.13.2 [V2G2-245]..[V2G2-904]",
            sample: Some("{'session':'[01,02,03,04,05,06]','info':{'id':'tux-evse','reading':64,'status':255,'tmeter':123546789,'sig':'CgsMDQ4='},'id':'fulup-iot-bzh','tuple':64}"),
        },
        MessageTagId::MeteringReceiptRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.13.3 [V2G2-247][V2G2-248]",
            sample: Some("{'rcode':'ok'}"),
        },
        MessageTagId::PaymentDetailsReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.6.2 [V2G2-205][V2G2-206]",
            sample:  Some("{'contract':{'id':'tux-evese-cert','cert':'qrvM3e7/','sub_certs':['obHB0eHx','orLC0uLy']},'emaid':'tux-evese-emaid'}"),
        },
        MessageTagId::PaymentDetailsRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.6.3 [V2G2-208]..[V2G2-899]",
            sample: Some("{'option':'contract','services':[{'service_id':1234,'param_id':4321},{'service_id':4321,'param_id':9876}]}"),
        },
        MessageTagId::PaymentSelectionReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.5.2 [V2G2-201][V2G2-202]",
            sample: Some("{'option':'contract','services':[{'service_id':1234,'param_id':4321},{'service_id':4321,'param_id':9876}]}"),
        },
        MessageTagId::PaymentSelectionRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.5.3 [V2G2-203][V2G2-204]",
            sample:  Some("{'rcode':'ok'}"),
        },
        MessageTagId::PowerDeliveryReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,

            name: msg_api,
            info: "§8.4.3.9.2 [V2G2-221][V2G2-222]",
            sample: Some("{'charge_progress':'renegotiate','schedule_id':64,'charging_profiles':[{'start':1234,'power_max':{'value':64,'multiplier':1,'unit':'watt'},'phases_max':3},{'start':4567,'power_max':{'value':64,'multiplier':1,'unit':'watt'},'phases_max':2}],'dc_delivery_params':{'status':{'ready':true,'error':'fail_volt_out_of_range','evresssoc':64},'charge_complete':true,'bulk_complete':true}}"),
        },
        MessageTagId::PowerDeliveryRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
            msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.3.9.3 [V2G2-223]..[V2G2-226]",
            sample: Some("{'rcode':'certificate_expires_soon','status':{'error':'reserve8','notification':'re_negotiation','delay':160,'isolation_status':'warning'},'voltage':{'value':400,'multiplier':1,'unit':'volt'}}"),
        },
        MessageTagId::PreChargeReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,

            name: msg_api,
            info: "§8.4.5.3.2 [V2G2-253][V2G2-254]",
            sample: Some("{'status':{'ready':true,'error':'no_error','evresssoc':1},'target_voltage':{'value':400,'multiplier':1,'unit':'volt'},'target_current':{'value':80,'multiplier':1,'unit':'ampere'}}"),
        },
        MessageTagId::PreChargeRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,

            name: msg_api,
            info: "§8.4.5.3.3 [V2G2-255][V2G2-256]",
            sample: Some("{'status':{'ready':true,'error':'no_error','evresssoc':1},'target_voltage':{'value':400,'multiplier':1,'unit':'volt'},'target_current':{'value':80,'multiplier':1,'unit':'ampere'}}
"),
        },
        MessageTagId::SessionStopReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,

            name: msg_api,
            info: "§8.4.3.12.2 [V2G2-239][V2G2-738]",
            sample: Some("{'action':'terminate'}"),
        },
        MessageTagId::SessionStopRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,

            name: msg_api,
            info: "§8.4.3.12.3 [V2G2-240][V2G2-241]",
            sample:  Some("{'rcode':'failed'}"),
        },
        MessageTagId::WeldingDetectionReq => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.5.5.2 [V2G2-261]",
            sample: Some("{'status':{'ready':true,'error':'no_error','evresssoc':16}}"),
        },
        MessageTagId::WeldingDetectionRes => ApiMsgInfo {
            uid: to_static_str(msg_uid),
                        msg_id: msg_id as u32,
            name: msg_api,
            info: "§8.4.5.5.3 [V2G2-263][V2G2-264]",
            sample: Some("{'rcode':'new_session','status':{'error':'ready','notification':'re_negotiation','delay':160},'voltage':{'value':400,'multiplier':1,'unit':'volt'}}"),
        },

        _ => return afb_error!("hoops", "Unknown message"),
    };
    Ok(api_info)
}
