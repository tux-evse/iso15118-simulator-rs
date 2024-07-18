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
use iso15118_exi::prelude::*;
use iso15118_jsonc::prelude::*;
use nettls::prelude::*;
use std::sync::{Mutex, MutexGuard};

#[derive(Clone, Copy)]
pub struct ResponderConfig {
    pub api: &'static str,
    pub prefix: &'static str,
}

pub struct ControllerEvse {
    pub network: IsoNetConfig,
    pub session: Mutex<IsoSessionState>,
    pub apiv4: AfbApiV4,
    pub responder: ResponderConfig,
}

impl ControllerEvse {
    pub fn new(
        pki_conf: Option<&'static PkiConfig>,
        apiv4: AfbApiV4,
        responder: ResponderConfig,
    ) -> Self {
        let state = Mutex::new(IsoSessionState {
            protocol: v2g::ProtocolTagId::Unknown,
            public_key: None,
            session_id: Vec::new(),
            challenge: Vec::new(),
            pending: None,
        });
        let controller = Self {
            session: state,
            apiv4,
            responder,
            network: IsoNetConfig {
                pki_conf,
                stream: ExiStream::new(),
            },
        };
        controller
    }

    #[track_caller]
    pub fn lock_state(&self) -> Result<MutexGuard<'_, IsoSessionState>, AfbError> {
        let guard = self.session.lock().unwrap();
        Ok(guard)
    }

    fn send_error(
        &self,
        _sock: &dyn NetConnection,
        state: &mut IsoSessionState,
        tagid: &str,
        error: AfbError,
    ) -> Result<AfbError, AfbError> {
        // try to return a status code
        let _res_id = match &state.protocol {
            v2g::ProtocolTagId::Din => {
                use iso2_exi::*;
                let tagid = MessageTagId::from_label(tagid)?;
                match tagid.match_resid() {
                    MessageTagId::Unsupported => return Err(error),
                    others => others as u32,
                }
            }
            v2g::ProtocolTagId::Iso2 => {
                use iso2_exi::*;
                let tagid = MessageTagId::from_label(tagid)?;
                match tagid.match_resid() {
                    MessageTagId::Unsupported => return Err(error),
                    others => others as u32,
                }
            }
            _ => return Err(error),
        };

        let jerror = JsoncObj::new();
        jerror.add("rcode", "sequence_error")?;
        // Fulup TBD return error message with a dedicated command or a specific sock channel
        // self.network.send_exi_message(sock, state, res_id, jerror)?;
        Ok(error)
    }

    pub fn process_exi_message(&self, sock: &dyn NetConnection) -> Result<(), AfbError> {
        // wait until we get a complete exi message from socket
        match self.network.rec_exi_message(sock)? {
            IsoStreamStatus::Complete => {}
            IsoStreamStatus::Incomplete => return Ok(()),
        }

        // try to decode message depending on session protocol
        let mut state = self.lock_state()?;
        let jbody = match self.network.decode_from_stream(&mut state)? {
            IsoMsgBody::Sdp(schema) => {
                return {
                    state.protocol = schema; // update schema to received schema
                    self.network.send_exi_stream(sock)
                };
            }
            IsoMsgBody::Din(body) => din_jsonc::body_to_jsonc(&body)?,
            IsoMsgBody::Iso2(body) => iso2_jsonc::body_to_jsonc(&body)?,
        };

        // send request to responder and wait for jsonc reply to encode as response to iso15118
        let tagid = jbody.get::<String>("tagid")?;
        let api_verb = format!(
            "{}:{}:{}",
            self.responder.prefix,
            jbody.get::<String>("proto")?,
            jbody.get::<String>("tagid")?
        );

        // call scenario responder api
        let response = match AfbSubCall::call_sync(self.apiv4, self.responder.api, &api_verb, jbody.clone())
        {
            Ok(result) => result.get::<JsoncObj>(0)?,
            Err(error) => {
                println!( "**** AfbSubCall::call_sync api:{} verb:{} jbody:{}", self.responder.api, &api_verb, jbody);
                return Err(self.send_error(sock, &mut state, &tagid, error)?);
            }
        };

        // check if incoming message expect a response
        if let Some(msgid) = response.optional::<u32>("msgid")? {
            if let Err(error) =
                self.network
                    .send_exi_message(sock, &mut state, msgid, response.clone())
            {
                afb_log_msg!(
                    Critical,
                    None,
                    "fail to send/encode: {} error:{}",
                    response,
                    error
                );
            }
        }
        Ok(())
    }
}
