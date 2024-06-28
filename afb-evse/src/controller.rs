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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

use iso15118::prelude::*;
use iso15118_jsonc::prelude::*;
use std::sync::{Mutex, MutexGuard};

pub struct ControlerConfig {}

pub struct ControlerState {
    pub status: u32,
    pub protocol: v2g::ProtocolTagId,
    session_id: Vec<u8>,
    public_key: Option<PkiPubKey>,
    challenge: Vec<u8>,
}

pub struct Iso2Controller {
    pub config: ControlerConfig,
    pub pki: Option<&'static PkiConfig>,
    pub data_set: Mutex<ControlerState>,
}

pub enum IsoMsgBody {
    Din(din_exi::MessageBody),
    Iso2(iso2_exi::MessageBody),
    Sdp,
}

impl Iso2Controller {
    pub fn new(pki: Option<&'static PkiConfig>) -> Self {
        let state = Mutex::new(ControlerState {
            status: 0,
            protocol: v2g::ProtocolTagId::Unknown,
            public_key: None,
            session_id: Vec::new(),
            challenge: Vec::new(),
        });
        let controler = Self {
            data_set: state,
            config: ControlerConfig {},
            pki,
        };
        controler
    }

    #[track_caller]
    pub fn lock_data_set(&self) -> Result<MutexGuard<'_, ControlerState>, AfbError> {
        let guard = self.data_set.lock().unwrap();
        Ok(guard)
    }

    pub fn decode_from_stream(
        &self,
        lock: &mut MutexGuard<RawStream>,
    ) -> Result<IsoMsgBody, AfbError> {
        let mut data_set = self.lock_data_set()?;
        let body= match data_set.protocol {
            v2g::ProtocolTagId::Unknown => {
                // initial message should be v2g::AppHandSupportedAppProtocolReq
                let v2g_msg = v2g::SupportedAppProtocolExi::decode_from_stream(lock)?;
                let app_protocol_req = match v2g_msg {
                    v2g::V2gMsgBody::Response(_) => {
                        return afb_error!(
                            "iso2-controller-protocol",
                            "expect 'AppHandSupportedAppProtocolReq' as initial request"
                        )
                    }
                    v2g::V2gMsgBody::Request(value) => value,
                };

                // compare AppHandSupportedAppProtocolReq with evse supported protocols
                let (rcode, schema_id) = match app_protocol_req
                    .match_protocol(&v2g::V2G_PROTOCOLS_SUPPORTED_LIST)
                {
                    Ok((rcode, proto)) => {
                        data_set.protocol = proto.get_schema();
                        afb_log_msg!(
                            Debug,
                            None,
                            "iso-app-hand: selected protocol:{}",
                            proto.get_name()
                        );
                        (rcode, proto.get_schema() as u8)
                    }
                    Err(rcode) => {
                        afb_log_msg!(Error, None, "iso-app-hand: No common iso protocol founded");
                        (rcode, 255)
                    }
                };

                let v2g_response = v2g::SupportedAppProtocolRes::new(rcode, schema_id).encode();
                v2g::SupportedAppProtocolExi::encode_to_stream(lock, &v2g_response)?;

                IsoMsgBody::Sdp
            }

            v2g::ProtocolTagId::Iso2 => {
                use iso2_exi::*;
                let message = ExiMessageDoc::decode_from_stream(lock)?;
                let header= message.get_header();
                let body = message.get_body()?;

                if header.get_signature_used() {
                    match &data_set.public_key {
                        None => return afb_error!("iso2-decode_stream", "msg is signed, but no public key available"),
                        Some(key) => message.pki_sign_check(body.get_tagid(), &data_set.challenge, &key)?,
                    }
                }

                // we have to store session_id as it is use to create every following response messages
                match &body {
                    MessageBody::SessionSetupReq(msg)=> data_set.session_id= msg.get_id().to_vec(),
                    MessageBody::PaymentDetailsReq(msg) => {
                        let pki = match self.pki {
                            None => return afb_error!("iso2-payment-detail", "missing mandatory pki config"),
                            Some(pki) => pki,
                        };

                        // extract certificate and check it match with ca_trust root list
                        let contract= msg.get_contract_chain();
                        let cert_datum= GnuPkiDatum::new(contract.get_cert()).b64decode()?;
                        let mut contract_cert= GnuPkiCerts::new()?;
                        contract_cert.add_datum(&cert_datum, GnuPkiCertFormat::DER)?;

                        for sub_cert in contract.get_subcerts() {
                           let subcert_datum= GnuPkiDatum::new(sub_cert).b64decode()?;
                           contract_cert.add_datum(&subcert_datum, GnuPkiCertFormat::DER)?;
                        }

                        // certificate match trusted authority list, let's check emaid
                        let emaid= msg.get_emaid()?.to_uppercase();
                        let cn= contract_cert.get_cn().to_uppercase();
                        if emaid != cn {
                           return afb_error!("iso2-payment-detail", "email:{} != cn:{}", emaid, cn)
                        }

                        let mut data_set= self.lock_data_set()?;
                        data_set.public_key= Some(pki.check_cert(&mut contract_cert)?);
                    }

                    _ => {},
                }
                IsoMsgBody::Iso2(body)
            }

            v2g::ProtocolTagId::Din => {
                use din_exi::*;
                let message = ExiMessageDoc::decode_from_stream(lock)?;

                // we have to store session_id as it is use to create every following response messages
                let payload = message.get_body()?;
                if let MessageBody::SessionSetupReq(msg)= payload {
                    data_set.session_id= msg.get_id().to_vec();
                };
                IsoMsgBody::Din(message.get_body()?)
            }

            // unexpected request coming from EV
            _ => return afb_error!("controller-handle-exi", "unsupported exi document type"),
        };
        Ok(body)
    }

    pub fn encode_to_stream(
        &self,
        mut lock: &mut MutexGuard<RawStream>,
        msgid: u32,
        jsonc: JsoncObj,
    ) -> Result<(), AfbError> {

        let state = self.lock_data_set()?;
        match state.protocol {
            v2g::ProtocolTagId::Unknown => return afb_error! ("iso-encode-payload", "SDP should set state before responding exi message"),

            v2g::ProtocolTagId::Iso2 => {
                use iso2_jsonc::*;
                use iso2_exi::*;
                let tagid= MessageTagId::from_u32(msgid);
                let body = body_from_jsonc(tagid, jsonc)?;
                let header= ExiMessageHeader::new(&state.session_id)?;
                ExiMessageDoc::new(&header, &body).encode_to_stream(&mut lock)?;
            }

            v2g::ProtocolTagId::Din => {
                use din_jsonc::*;
                use din_exi::*;
                let tagid= MessageTagId::from_u32(msgid);
                let body = body_from_jsonc(tagid, jsonc)?;
                let header= ExiMessageHeader::new(&state.session_id)?;
                ExiMessageDoc::new(&header, &body).encode_to_stream(&mut lock)?;
            }

            // unexpected request coming from EV
            _ => return afb_error!("controller-handle-exi", "unsupported exi document type"),
        };

        Ok(())
    }
}
