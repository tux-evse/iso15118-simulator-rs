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
}

pub struct IsoController {
    pub config: ControlerConfig,
    pub data_set: Mutex<ControlerState>,
}

pub enum IsoMsgBody {
    Din(din_exi::MessageBody),
    Iso2(iso2_exi::MessageBody),
    Sdp,
}

impl IsoController {
    pub fn new() -> Self {
        let state = Mutex::new(ControlerState {
            status: 0,
            protocol: v2g::ProtocolTagId::Unknown,
            session_id: Vec::new(),
        });
        let controler = Self {
            data_set: state,
            config: ControlerConfig {},
        };
        controler
    }

    #[track_caller]
    pub fn lock_handle(&self) -> Result<MutexGuard<'_, ControlerState>, AfbError> {
        let guard = self.data_set.lock().unwrap();
        Ok(guard)
    }

    pub fn decode_from_stream(
        &self,
        lock: &mut MutexGuard<RawStream>,
    ) -> Result<IsoMsgBody, AfbError> {
        let mut state = self.lock_handle()?;
        let body= match state.protocol {
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
                        state.protocol = proto.get_schema();
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

                // we have to store session_id as it is use to create every following response messages
                let payload = message.get_body()?;
                if let MessageBody::SessionSetupReq(msg)= &payload {
                    state.session_id= msg.get_id().to_vec();
                };
                IsoMsgBody::Iso2(payload)
            }

            v2g::ProtocolTagId::Din => {
                use din_exi::*;
                let message = ExiMessageDoc::decode_from_stream(lock)?;

                // we have to store session_id as it is use to create every following response messages
                let payload = message.get_body()?;
                if let MessageBody::SessionSetupReq(msg)= payload {
                    state.session_id= msg.get_id().to_vec();
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

        let state = self.lock_handle()?;
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
