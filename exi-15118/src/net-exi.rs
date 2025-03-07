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
use iso15118::prelude::*;
use iso15118_jsonc::prelude::*;
use nettls::prelude::*;
use std::sync::MutexGuard;

#[track_caller]
fn _buffer_to_str(buffer: &[u8]) -> Result<&str, AfbError> {
    let text = match std::str::from_utf8(buffer) {
        Ok(value) => value,
        Err(_) => return afb_error!("buffer-to_str", "fail UTF8 conversion"),
    };
    Ok(text)
}
pub struct IsoSessionState {
    pub protocol: v2g::ProtocolTagId,
    pub session_id: Vec<u8>,
    pub public_key: Option<PkiPubKey>,
    pub challenge: Vec<u8>,
    pub pending: Option<IsoPendingState>,
}

pub struct IsoJobPost {
    pub afb_rqt: AfbRequest,
}

pub struct IsoPendingState {
    pub afb_rqt: AfbRequest,
    pub msg_id: IsoMsgResId,
    pub job_id: i32,
}

pub enum RecExiResponse {
    Retry,
    Din(JsoncObj),
    Iso2(JsoncObj),
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum IsoMsgResId {
    Din(din_exi::MessageTagId),
    Iso2(iso2_exi::MessageTagId),
    None,
}
pub enum IsoMsgBody {
    Din(din_exi::MessageBody),
    Iso2(iso2_exi::MessageBody),
    Sdp(v2g::ProtocolTagId),
}

pub enum IsoStreamStatus {
    Incomplete,
    Complete,
}

pub struct IsoNetConfig {
    pub stream: ExiStream,
    pub pki_conf: Option<&'static PkiConfig>,
}

impl IsoNetConfig {
    pub fn rec_exi_message(&self, sock: &dyn NetConnection) -> Result<IsoStreamStatus, AfbError> {
        // move tcp socket data into exi stream buffer
        let mut lock = self.stream.lock_stream();
        let read_count = {
            let (stream_idx, stream_available) = self.stream.get_index(&lock);
            let read_count = if stream_available == 0 {
                sock.close()?;
                return afb_error!(
                    "rec-exi-message",
                    "async_exi_client {:?}, buffer full close session",
                    sock.get_source()
                );
            } else {
                let buffer = &mut lock.buffer[stream_idx..];
                sock.get_data(buffer)?
            };

            // when facing a new exi check how much data should be read
            if stream_idx == 0 {
                lock.current_len = 0;
                let len = self.stream.get_payload_len(&lock);
                if len < 0 {
                    afb_log_msg!(
                        Warning,
                        None,
                        "async_exi_client: packet ignored (invalid v2g header) size:{}",
                        read_count
                    );
                } else {
                    lock.current_len = len as u32;
                }
            }
            read_count
        };

        // fix stream len for decoding
        lock.current_len = lock.current_len + read_count;
        let response = if lock.current_len < lock.expected_len {
            // message not completely received
            IsoStreamStatus::Incomplete
        } else {
            // fix stream len for decoding
            self.stream.finalize(&lock, lock.current_len)?;

            // assert payload header match iso15118/din
            match self.stream.get_payload_id(&lock) {
                v2g::PayloadMsgId::SAP => {}
                _ => {
                    return afb_error!(
                        "rec-exi-message",
                        "Invalid message payload id:{:?}",
                        self.stream.get_payload_id(&lock)
                    )
                }
            }
            IsoStreamStatus::Complete
        };

        Ok(response)
    }

    #[track_caller]
    // flush stream contend to socket
    pub fn send_exi_stream(&self, sock: &dyn NetConnection) -> Result<(), AfbError> {
        let mut lock = self.stream.lock_stream();
        let exi_buffer = self.stream.get_buffer(&lock);
        sock.put_data(exi_buffer)?;
        self.stream.reset(&mut lock);
        Ok(())
    }

    #[track_caller]
    pub fn send_exi_message(
        &self,
        sock: &dyn NetConnection,
        session: &IsoSessionState,
        msg_id: u32,
        jbody: JsoncObj,
    ) -> Result<IsoMsgResId, AfbError> {
        // move tcp socket data into exi stream buffer
        let mut lock = self.stream.lock_stream();

        let res_id = self.encode_to_stream(&mut lock, session, msg_id, jbody, self.pki_conf)?;
        let exi_buffer = self.stream.get_buffer(&lock);
        sock.put_data(exi_buffer)?;
        self.stream.reset(&mut lock);
        Ok(res_id)
    }

    #[track_caller]
    pub fn iso2_encode_payload(
        &self,
        lock: &mut MutexGuard<RawStream>,
        session: &IsoSessionState,
        tag_id: iso2_exi::MessageTagId,
        body: iso2_exi::Iso2BodyType,
    ) -> Result<(), AfbError> {
        use iso2_exi::*;

        let null_session = vec![0 as u8];

        let session_id = {
            if session.session_id.len() == 0 {
                &null_session
            } else {
                &session.session_id
            }
        };

        // build exi payload from json
        let header = ExiMessageHeader::new(session_id)?;

        let mut exi_doc = ExiMessageDoc::new(&header, &body);
        if let Some(pki) = self.pki_conf {
            match tag_id {
                MessageTagId::CertificateInstallReq
                | MessageTagId::CertificateUpdateReq
                | MessageTagId::CertificateUpdateRes
                | MessageTagId::AuthorizationReq
                | MessageTagId::MeteringReceiptReq => {
                    exi_doc.pki_sign_sign(tag_id, &pki.get_private_key()?)?
                }
                _ => {}
            }
        }
        exi_doc.encode_to_stream(lock)?;

        Ok(())
    }

    #[track_caller]
    pub fn din_encode_payload(
        &self,
        lock: &mut MutexGuard<RawStream>,
        session: &IsoSessionState,
        tag_id: din_exi::MessageTagId,
        body: din_exi::DinBodyType,
    ) -> Result<(), AfbError> {
        use din_exi::*;

        // build exi payload from json
        let header = ExiMessageHeader::new(&session.session_id)?;

        let exi_doc = ExiMessageDoc::new(&header, &body);
        if let Some(_pki) = self.pki_conf {
            match tag_id {
                MessageTagId::CertificateInstallReq
                | MessageTagId::CertificateUpdateReq
                | MessageTagId::CertificateUpdateRes
                | MessageTagId::MeteringReceiptReq => {
                    afb_log_msg!(Critical, None, "Din Message signature not implemented");
                    // exi_doc.pki_sign_sign(tag_id, &pki.get_private_key()?)?
                }
                _ => {}
            }
        }
        exi_doc.encode_to_stream(lock)?;

        Ok(())
    }

    #[track_caller]
    pub fn encode_to_stream(
        &self,
        lock: &mut MutexGuard<RawStream>,
        session: &IsoSessionState,
        msg_id: u32,
        jsonc: JsoncObj,
        pki_conf: Option<&'static PkiConfig>,
    ) -> Result<IsoMsgResId, AfbError> {
        // extract message id from json

        let res_id = match session.protocol {
            v2g::ProtocolTagId::Unknown => {
                return afb_error!(
                    "iso-encode-payload",
                    "SDP should set session before responding exi message"
                )
            }

            v2g::ProtocolTagId::Iso2 => {
                use iso2_exi::*;
                use iso2_jsonc::*;
                let tagid = MessageTagId::from_u32(msg_id);
                match tagid {
                    MessageTagId::AuthorizationReq => {
                        // Add the challenge from the session if needed
                        if jsonc.optional::<String>("challenge")?.is_none()
                            && session.challenge.len() > 0
                        {
                            jsonc.add("challenge", &base64_encode(session.challenge.as_ref()))?;
                        }
                    }
                    MessageTagId::MeteringReceiptReq => {
                        // Ass the session id if not present
                        if jsonc.optional::<String>("session")?.is_none() {
                            jsonc.add("session", &bytes_to_hexa(&session.session_id))?;
                        }
                    }
                    _ => {}
                }
                let body = body_from_jsonc(tagid, jsonc, pki_conf.clone())?;
                self.iso2_encode_payload(lock, session, tagid, body)?;
                IsoMsgResId::Iso2(tagid.match_resid())
            }

            v2g::ProtocolTagId::Din => {
                use din_exi::*;
                use din_jsonc::*;
                let tagid = MessageTagId::from_u32(msg_id);
                let body = body_from_jsonc(tagid, jsonc)?;
                self.din_encode_payload(lock, session, tagid, body)?;
                IsoMsgResId::Din(tagid.match_resid())
            }

            // unexpected request coming from EV
            _ => return afb_error!("controller-handle-exi", "unsupported exi document type"),
        };

        Ok(res_id)
    }

    pub fn decode_from_stream(
        &self,
        session: &mut IsoSessionState,
    ) -> Result<IsoMsgBody, AfbError> {
        let mut lock = self.stream.lock_stream();
        let body = match session.protocol {
            v2g::ProtocolTagId::Unknown => {
                use v2g::*;

                // initial message should be v2g::AppHandSupportedAppProtocolReq
                let v2g_msg = v2g::SupportedAppProtocolExi::decode_from_stream(&lock)?;
                let app_protocol_req = match v2g_msg {
                    v2g::V2gMsgBody::Request(app_protocol) => {
                        // compare AppHandSupportedAppProtocolReq with evse supported protocols
                        let (rcode, schema_id) =
                            match app_protocol.match_protocol(&v2g::V2G_PROTOCOLS_SUPPORTED_LIST) {
                                Err(_rcode) => {
                                    return afb_error!(
                                        "decode_from_stream",
                                        "SDP no supported iso protocol founded"
                                    )
                                }
                                Ok((rcode, proto)) => {
                                    afb_log_msg!(
                                        Debug,
                                        None,
                                        "iso-app-hand: selected protocol:{}",
                                        proto.get_name()
                                    );
                                    (rcode, proto.get_schema())
                                }
                            };

                        let v2g_response =
                            v2g::SupportedAppProtocolRes::new(rcode, schema_id as u8).encode();
                        v2g::SupportedAppProtocolExi::encode_to_stream(&mut lock, &v2g_response)?;
                        IsoMsgBody::Sdp(schema_id)
                    }
                    v2g::V2gMsgBody::Response(app_protocol) => {
                        let schema_id = ProtocolTagId::from_u8(app_protocol.get_schema());
                        IsoMsgBody::Sdp(schema_id)
                    }
                };
                app_protocol_req
            }

            v2g::ProtocolTagId::Iso2 => {
                use iso2_exi::*;
                let message = ExiMessageDoc::decode_from_stream(&mut lock)?;
                let header = message.get_header();
                let body = message.get_body()?;

                if header.get_signature_used() {
                    let public_key = match self.pki_conf {
                        None => {
                            return afb_error!(
                                "decode-from-stream",
                                "missing mandatory pki configuration"
                            )
                        }
                        Some(pki) => {
                            if body.get_tagid() == MessageTagId::ParamDiscoveryRes {
                                pki.get_mo_sub_ca_2_public_key()?
                            } else {
                                pki.get_public_key()?
                            }
                        }
                    };

                    message.pki_sign_check(body.get_tagid(), &session.challenge, &public_key)?
                }

                // we have to store session_id as it is use to create every following response messages
                match &body {
                    MessageBody::SessionSetupRes(_msg) => {
                        session.session_id = header.get_session_id().to_vec()
                    }
                    MessageBody::PaymentDetailsRes(msg) => {
                        session.challenge = msg.get_challenge().to_vec();
                    }
                    MessageBody::PaymentDetailsReq(msg) => {
                        // extract certificate and check it match with ca_trust root list
                        let contract = msg.get_contract_chain();
                        let cert_datum = GnuPkiDatum::new(contract.get_cert()).b64decode()?;
                        let mut contract_cert = GnuPkiCerts::new()?;
                        contract_cert.add_datum(&cert_datum, GnuPkiCertFormat::DER)?;

                        for sub_cert in contract.get_subcerts() {
                            let subcert_datum = GnuPkiDatum::new(sub_cert).b64decode()?;
                            contract_cert.add_datum(&subcert_datum, GnuPkiCertFormat::DER)?;
                        }

                        // certificate match trusted authority list, let's check emaid
                        let emaid = msg.get_emaid()?.to_uppercase();
                        let cn = contract_cert.get_cn().to_uppercase();
                        if emaid != cn {
                            return afb_error!(
                                "iso2-payment-detail",
                                "email:{} != cn:{}",
                                emaid,
                                cn
                            );
                        }

                        let pki = match self.pki_conf {
                            None => {
                                return afb_error!(
                                    "decode-from-stream",
                                    "iso2-payment-detail missing mandatory pki configuration"
                                )
                            }
                            Some(pki) => pki,
                        };

                        session.public_key = Some(pki.check_cert(&mut contract_cert)?);
                    }

                    _ => {}
                }
                IsoMsgBody::Iso2(body)
            }

            v2g::ProtocolTagId::Din => {
                use din_exi::*;
                let message = ExiMessageDoc::decode_from_stream(&mut lock)?;

                let header = message.get_header();
                let body = message.get_body()?;

                // Fulup TBD handle Din signature

                // we have to store session_id as it is use to create every following response messages
                match &body {
                    MessageBody::SessionSetupRes(_msg) => {
                        session.session_id = header.get_session_id().to_vec()
                    }
                    _ => {}
                }
                IsoMsgBody::Din(message.get_body()?)
            }

            // unexpected request coming from EV
            _ => return afb_error!("controller-handle-exi", "unsupported exi document type"),
        };
        Ok(body)
    }

    #[track_caller]
    pub fn check_msg_id(
        &self,
        iso_body: &IsoMsgBody,
        pending_state: &Option<IsoPendingState>,
    ) -> Result<bool, AfbError> {
        let pending = match pending_state {
            None => return Ok(false),
            Some(value) => value,
        };

        let msg_id: IsoMsgResId = match iso_body {
            IsoMsgBody::Din(body) => IsoMsgResId::Din(body.get_tagid()),
            IsoMsgBody::Iso2(body) => IsoMsgResId::Iso2(body.get_tagid()),
            IsoMsgBody::Sdp(_) => return Ok(true), // SDP expect e response
        };

        if msg_id != pending.msg_id {
            return afb_error!(
                "exi-message-in",
                "unexpected exi message expected:{:?} got:{:?}",
                pending.msg_id,
                msg_id
            );
        }

        Ok(true)
    }
}
