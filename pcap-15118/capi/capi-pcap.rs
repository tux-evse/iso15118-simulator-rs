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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *  References:
 *   - TLS headers: https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art080
 *   * gnutls: https://www.gnutls.org/manual/html_node/Cryptographic-API.html
 *   * tls 1.3: https://www.youtube.com/watch?v=VKHeuH1D2RA
 *   * tls https://lekensteyn.nl/files/wireshark-ssl-tls-decryption-secrets-sharkfest18eu.pdf
 *   * key-log-format: https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format
 *   * key-log-spec: https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
 *   * tls: https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf
 *   * decrypt: https://gist.github.com/fulup-bzh/cbca88fc07b3d92cc3e5f3a047ffde7f
 */

mod cglue {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused_imports)]
    include!("_capi_pcap.rs");
}

//use afbv4::prelude::*;
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufRead};
use std::mem;
use std::os::raw::c_char;
use std::slice;
use std::str;
use std::time::Duration;

// return iteration on file buffer
fn get_lines(filename: &str) -> io::Result<io::Lines<io::BufReader<File>>> {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

#[track_caller]
fn read_uint24(data: &[u8]) -> u32 {
    let len = ((data[0] as u32) << 16) | ((data[1] as u32) << 8) | (data[2] as u32);
    len
}

#[track_caller]
fn read_uint16(data: &[u8]) -> u16 {
    let len = ((data[0] as u16) << 8) | (data[1] as u16);
    len
}

#[track_caller]
fn write_uint16(number: u16, data: &mut [u8]) -> usize {
    data[0] = (number >> 8 & 0xFF) as u8;
    data[1] = (number & 0xFF) as u8;
    mem::size_of::<u16>()
}

#[track_caller]
fn write_text(text: &[u8], data: &mut [u8]) -> usize {
    for idx in 0..text.len() {
        data[idx] = text[idx];
    }
    text.len()
}

#[track_caller]
fn encode_nonce(number: u64, data: &mut [u8]) {
    data[0] = (number >> 56 & 0xFF) as u8;
    data[1] = (number >> 48 & 0xFF) as u8;
    data[2] = (number >> 40 & 0xFF) as u8;
    data[3] = (number >> 32 & 0xFF) as u8;
    data[4] = (number >> 24 & 0xFF) as u8;
    data[5] = (number >> 16 & 0xFF) as u8;
    data[6] = (number >> 8 & 0xFF) as u8;
    data[7] = (number & 0xFF) as u8;
}

#[track_caller]
fn slice_shift(buffer: &[u8], start: usize, len: usize) -> (usize, &[u8]) {
    let data = &buffer[start..start + len];
    let index = start + len;
    (index, data)
}

fn gtls_perror(code: i32) -> String {
    let error = unsafe { cglue::gnutls_strerror(code) };
    let cstring = unsafe { CStr::from_ptr(error as *const c_char) };
    let slice: &str = cstring.to_str().unwrap();
    slice.to_owned()
}

#[derive(Debug, Clone, Copy)]
enum PacketDirection {
    ClientToServer,
    ServerToClient,
    Unset,
}

#[no_mangle]
pub extern "C" fn api_pcap_cb(
    userdata: *mut u8,
    header: *const cglue::pcap_pkthdr,
    buffer: *const u8,
) {
    // get Rust pcap handle from user context
    let handle = unsafe { &mut *(userdata as *mut PcapHandle) };

    // pcap header hold timestamp and packet len
    let pcap_header = PcapHeader::new(header);
    handle.msg.pkg_count += 1;

    if handle.max_count > 0 && handle.msg.pkg_count > handle.max_count {
        unsafe { cglue::pcap_breakloop(handle.pcap_raw) };
        return;
    }
    // ignore any non IP packet
    let ether_header = EtherHeader::new(buffer, 0);
    if ether_header.get_type() != cglue::C_ETHERTYPE_IPV6 {
        if handle.verbose > 0 {
            eprintln!(
                "ether-packet-type: ignore packet:{} {:#0x} ",
                handle.msg.pkg_count,
                ether_header.get_type()
            );
        }
        return;
    }

    // ignore any non UDP/TCP packet
    let ip_header = IpHeader::new(buffer, ether_header.get_size());
    match ip_header.get_proto() {
        IpProto::TCP => {
            let tcp_header = TcpHeader::new(buffer, ether_header.get_size() + ip_header.get_size());
            let data_len = ip_header.get_len() - tcp_header.get_len();

            // ignore any external packet after tcp session start
            let pkg_dir = if handle.svc_port != 0 {
                if handle.svc_port == tcp_header.get_dst()
                    && handle.clt_port == tcp_header.get_src()
                {
                    PacketDirection::ClientToServer
                } else if handle.svc_port == tcp_header.get_src()
                    && handle.clt_port == tcp_header.get_dst()
                {
                    PacketDirection::ServerToClient
                } else {
                    if handle.verbose > 1 {
                        eprintln!(
                            "pkg:{} Ignore out of session TCP packet src:{} ack:{} seq:{} next:{}",
                            handle.msg.pkg_count,
                            tcp_header.get_src(),
                            tcp_header.get_ack(),
                            tcp_header.get_seq(),
                            tcp_header.get_ack_seq(),
                        );
                    }
                    return;
                }
            } else {
                PacketDirection::Unset
            };

            // new sequence check destination port and set relative timestamp
            if tcp_header.get_syn() {
                if !tcp_header.get_ack() {
                    if handle.tcp_port != 0 && tcp_header.get_dst() != handle.tcp_port {
                        if handle.verbose > 1 {
                            eprintln!(
                                "pkg:{} Ignore TCP stream src:{} ack:{} seq:{} next:{}",
                                handle.msg.pkg_count,
                                tcp_header.get_src(),
                                tcp_header.get_ack(),
                                tcp_header.get_seq(),
                                tcp_header.get_ack_seq(),
                            );
                        }
                        return;
                    }

                    handle.msg.start_stamp = pcap_header.get_timestamp();
                    handle.seq_time = handle.msg.start_stamp;
                    handle.clt_port = tcp_header.get_src();
                    handle.svc_port = tcp_header.get_dst();
                }
                handle.seq_next = tcp_header.get_ack_seq();
                eprintln!(
                    "pkg:{} New TCP stream src:{} ack:{} seq:{} next:{}",
                    handle.msg.pkg_count,
                    tcp_header.get_src(),
                    tcp_header.get_ack(),
                    tcp_header.get_seq(),
                    tcp_header.get_ack_seq(),
                );
                return;
            }

            // on session hand we close current scenario and restart looping
            if tcp_header.get_fin() {
                if handle.verbose > 0 {
                    eprintln!(
                        "pkg:{} ip-packet-type: closing tcp session src:{}",
                        handle.msg.pkg_count,
                        tcp_header.get_src()
                    );
                }

                // close scenario output with calling callback with dummy values
                let _ =
                    (handle.msg.callback)(handle.msg.pkg_count, &[0; 0], handle.msg.start_stamp, &handle.msg.context);
                return;
            }

            // keep track of newt expected sequence number
            handle.seq_next = tcp_header.get_ack_seq();

            if data_len == 0 {
                if handle.verbose > 1 {
                    eprintln!(
                        "pkg:{} tcp-packet-type: ignoring empty packet ack:{} src:{} seq:{} next:{}",
                        handle.msg.pkg_count,
                        tcp_header.get_ack(),
                        tcp_header.get_src(),
                        tcp_header.get_seq(),
                        tcp_header.get_ack_seq(),
                    );
                }
                return;
            }

            if handle.verbose > 8 {
                eprintln!(
                    "pkg:{} tcp-packet-data: len:{} ack:{} src:{} seq:{} next:{}",
                    handle.msg.pkg_count,
                    data_len,
                    tcp_header.get_ack(),
                    tcp_header.get_src(),
                    tcp_header.get_seq(),
                    tcp_header.get_ack_seq(),
                );
            }

            let data = unsafe {
                slice::from_raw_parts(
                    buffer.wrapping_add(
                        ether_header.get_size() + ip_header.get_size() + tcp_header.get_len(),
                    ),
                    data_len,
                )
            };

            // check is SSL pre_shared key is set
            let status = match &mut handle.tls_session {
                None => (handle.msg.callback)(
                    handle.msg.pkg_count,
                    &data,
                    pcap_header.get_timestamp(),
                    &handle.msg.context,
                ),
                Some(tls_session) => {
                    let mut tls_start = 0;

                    loop {
                        // check TLS message header
                        let (index, tls_header) =
                            slice_shift(data, tls_start, cglue::TLS_RECORD_HEADER_SIZE);
                        // Fulup TBD auth buffer
                        let msg_tag = tls_header[0] as u32;
                        let msg_major = tls_header[1];
                        let msg_minor = tls_header[2];
                        let msg_len = read_uint16(&tls_header[3..3 + 2]);
                        let tls_auth = &tls_header[0..5];

                        if msg_major < 3 {
                            eprintln!(
                                "tls-packet-tls: SSL version < 3.x header len src:{} packet:{}",
                                tcp_header.get_src(),
                                handle.msg.pkg_count
                            );
                            return;
                        }

                        // shift to tls data record
                        let (index, tls_data) = slice_shift(data, index, msg_len as usize);

                        let status = match msg_tag {
                            cglue::TLS_MSG_TAG_HANDSHAKE => {
                                tls_session.process_handshake(handle.msg.pkg_count, &tls_data)
                            }

                            cglue::TLS_MSG_TAG_ALERT => {
                                tls_session.process_alert(handle.msg.pkg_count, &tls_data)
                            }

                            cglue::TLS_MSG_TAG_CIPHER_CHANGE => {
                                // wait for client cipher change before starting decoding
                                tls_session.cipher_changed += 1;
                                match pkg_dir {
                                    PacketDirection::ClientToServer => {
                                        tls_session.client.sequence = 0;
                                    }
                                    PacketDirection::ServerToClient => {
                                        tls_session.server.sequence = 0;
                                    }
                                    PacketDirection::Unset => {}
                                }
                                return; // ignore any sub tls packets (useless certificates)
                            }

                            cglue::TLS_MSG_TAG_APPDATA => {
                                if msg_minor < 3 {
                                    eprintln!(
                                    "tls-packet-tls: SSL version < 3.3 header len src:{} packet:{}",
                                    tcp_header.get_src(),
                                    handle.msg.pkg_count
                                    );
                                    return;
                                }

                                if tls_session.cipher_changed < 2 {
                                    return;
                                };

                                let decrypted_data = tls_session.application_data(
                                    handle.msg.pkg_count,
                                    pkg_dir,
                                    tls_auth,
                                    tls_data,
                                );

                                // if decrypt ok transfer to callback otherwise propagate error
                                match decrypted_data {
                                    Ok(data) => (handle.msg.callback)(
                                        handle.msg.pkg_count,
                                        &data,
                                        pcap_header.get_timestamp(),
                                        &handle.msg.context,
                                    ),
                                    Err(error) => Err(error),
                                }
                            }
                            _ => afb_error!(
                                "tls-packet-tls",
                                "unsupported TLS message tag src:{} packet:{}",
                                tcp_header.get_src(),
                                handle.msg.pkg_count
                            ),
                        };

                        // when error stop lopping and propagate
                        if let Err(error) = status {
                            break Err(error);
                        }

                        // move to next tls-1.3 extension until end of tcp buffer
                        tls_start = index;
                        if tls_start == data.len() as usize {
                            break Ok(());
                        }
                    }
                }
            };

            // collect tls and non tls error
            if let Err(error) = status {
                eprintln!("pkg:{} error:{}", handle.msg.pkg_count, error);
                return;
            }
        }

        IpProto::UDP => {
            let udp_header = UdpHeader::new(buffer, ether_header.get_size() + ip_header.get_size());
            let data_offset =
                ether_header.get_size() + ip_header.get_size() + udp_header.get_size();
            let data_length = pcap_header.get_len() as usize - data_offset;
            let _data =
                unsafe { slice::from_raw_parts(buffer.wrapping_add(data_offset), data_length) };
            if handle.verbose > 0 {
                eprintln!(
                    "ip-packet-type: ignoring packet:{} UDP",
                    handle.msg.pkg_count
                );
            }
        }

        IpProto::Unsupported(value) => {
            if handle.verbose > 0 {
                eprintln!(
                    "ip-packet-type: ignoring packet:{} proto:{:#0x} ",
                    handle.msg.pkg_count, value
                );
            }
        }
    }
}

struct PskMasterKey {
    random: Vec<u8>,
    secret: Vec<u8>,
}

impl PskMasterKey {
    fn new(random: &[u8], secret: &[u8]) -> Self {
        Self {
            random: hexa_to_vec(random),
            secret: hexa_to_vec(secret),
        }
    }
}

enum TlsVersion {
    Tls1_2,
    Tls1_3,
    Unknown,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
enum TlsCipherSuite {
    Unknown = 0,
    TLS_AES_128_GCM_SHA256 = cglue::gnutls_cipher_algorithm_GNUTLS_CIPHER_AES_128_GCM,
    TLS_AES_256_GCM_SHA384 = cglue::gnutls_cipher_algorithm_GNUTLS_CIPHER_AES_256_GCM,
    TLS_CHACHA20_POLY1305_SHA256 = cglue::gnutls_cipher_algorithm_GNUTLS_CIPHER_CHACHA20_POLY1305,
    TLS_AES_128_CCM_SHA256 = cglue::gnutls_cipher_algorithm_GNUTLS_CIPHER_AES_128_CCM,
    TLS_AES_128_CCM_8_SHA256 = cglue::gnutls_cipher_algorithm_GNUTLS_CIPHER_AES_128_CCM_8,
}

#[allow(unused)]
impl TlsCipherSuite {
    pub fn from_tagid(tagid: u16) -> Self {
        match tagid {
            0x1301 => TlsCipherSuite::TLS_AES_128_GCM_SHA256,
            0x1302 => TlsCipherSuite::TLS_AES_256_GCM_SHA384,
            0x1303 => TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            0x1304 => TlsCipherSuite::TLS_AES_128_CCM_SHA256,
            0x1305 => TlsCipherSuite::TLS_AES_128_CCM_8_SHA256,
            _ => TlsCipherSuite::Unknown,
        }
    }

    pub fn get_hmac(self) -> TlsCipherHmac {
        match self {
            TlsCipherSuite::TLS_AES_128_GCM_SHA256 => TlsCipherHmac::GNUTLS_MAC_SHA256,
            TlsCipherSuite::TLS_AES_256_GCM_SHA384 => TlsCipherHmac::GNUTLS_MAC_SHA384,
            TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256 => TlsCipherHmac::GNUTLS_MAC_SHA256,
            TlsCipherSuite::TLS_AES_128_CCM_SHA256 => TlsCipherHmac::GNUTLS_MAC_SHA256,
            TlsCipherSuite::TLS_AES_128_CCM_8_SHA256 => TlsCipherHmac::GNUTLS_MAC_SHA256,
            _ => TlsCipherHmac::Unknown,
        }
    }

    pub fn get_digest(self) -> TlsCipherDigest {
        match self {
            TlsCipherSuite::TLS_AES_128_GCM_SHA256 => TlsCipherDigest::GNUTLS_MAC_SHA256,
            TlsCipherSuite::TLS_AES_256_GCM_SHA384 => TlsCipherDigest::GNUTLS_MAC_SHA384,
            TlsCipherSuite::TLS_CHACHA20_POLY1305_SHA256 => TlsCipherDigest::GNUTLS_MAC_SHA256,
            TlsCipherSuite::TLS_AES_128_CCM_SHA256 => TlsCipherDigest::GNUTLS_MAC_SHA256,
            TlsCipherSuite::TLS_AES_128_CCM_8_SHA256 => TlsCipherDigest::GNUTLS_MAC_SHA256,
            _ => TlsCipherDigest::Unknown,
        }
    }
}

#[allow(non_camel_case_types, unused)]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
enum TlsCipherHmac {
    Unknown = 0,
    GNUTLS_MAC_SHA256 = cglue::gnutls_mac_algorithm_t_GNUTLS_MAC_SHA256,
    GNUTLS_MAC_SHA384 = cglue::gnutls_mac_algorithm_t_GNUTLS_MAC_SHA384,
    GNUTLS_MAC_SHA512 = cglue::gnutls_mac_algorithm_t_GNUTLS_MAC_SHA512,
}

#[allow(non_camel_case_types, unused)]
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
enum TlsCipherDigest {
    Unknown = cglue::gnutls_digest_algorithm_t_GNUTLS_DIG_UNKNOWN,
    GNUTLS_MAC_SHA256 = cglue::gnutls_digest_algorithm_t_GNUTLS_DIG_SHA256,
    GNUTLS_MAC_SHA384 = cglue::gnutls_digest_algorithm_t_GNUTLS_DIG_SHA384,
    GNUTLS_MAC_SHA512 = cglue::gnutls_digest_algorithm_t_GNUTLS_DIG_SHA512,
}

fn hexa_to_vec(keytext: &[u8]) -> Vec<u8> {
    let byte = |slot| -> u8 {
        let hexa = str::from_utf8(slot).unwrap();
        u8::from_str_radix(hexa, 16).unwrap()
    };

    let result = keytext
        .chunks(2)
        .into_iter()
        .map(|slot| byte(slot))
        .collect();
    result
}

struct Datum {
    buffer: Vec<u8>,
    payload: cglue::gnutls_datum_t,
}

#[allow(unused)]
impl Datum {
    pub fn new(buffer: Vec<u8>) -> Self {
        let mut payload = unsafe { mem::zeroed::<cglue::gnutls_datum_t>() };
        payload.size = buffer.len() as u32;
        payload.data = buffer.as_ptr() as *const _ as *mut u8;
        Self { buffer, payload }
    }

    pub fn get_hexa(&self) -> String {
        bytes_to_hexa(&self.buffer)
    }

    pub fn get_string(&self) -> String {
        match str::from_utf8(&self.buffer) {
            Ok(value) => value.to_string(),
            Err(_) => "Fail UTF8 conversion".to_string(),
        }
    }

    pub fn get_data(&self) -> cglue::gnutls_datum_t {
        self.payload
    }

    pub fn get_size(&self) -> usize {
        self.payload.size as usize
    }
}

#[derive(Clone, Debug)]
#[allow(unused)]
enum MasterKeyTag {
    ClientApplication,
    ServerApplication,
}

// Fulup TBD do we need two aead handlers for TLS stream ???
struct TlsStream {
    _tag: MasterKeyTag,
    random: Vec<u8>,
    nonce_secret: Vec<u8>,
    keys_hasht: Vec<PskMasterKey>,
    aead_handle: cglue::gnutls_aead_cipher_hd_t,
    sequence: u32,
}

impl TlsStream {
    pub fn new(tag: MasterKeyTag, keys_hasht: Vec<PskMasterKey>) -> Self {
        Self {
            _tag: tag,
            aead_handle: unsafe { mem::zeroed::<cglue::gnutls_aead_cipher_hd_t>() },
            random: Vec::new(),
            nonce_secret: Vec::new(),
            keys_hasht: keys_hasht,
            sequence: 0,
        }
    }
}

struct TlsSession {
    version: TlsVersion,
    cipher_changed: u16,
    cipher: TlsCipherSuite,
    client: TlsStream,
    server: TlsStream,
    verbose: u8,
}

impl TlsSession {
    fn new(key_log: &str, verbose: u8) -> Result<Self, AfbError> {
        let mut client_data_keys = Vec::new();
        let mut server_data_keys = Vec::new();
        //let mut client_handshake_keys = Vec::new();
        //let mut server_handshake_keys = Vec::new();
        match get_lines(key_log) {
            Err(error) => {
                return afb_error!(
                    "tls-session-new",
                    "fail to open pre-master-key file {}",
                    error
                )
            }
            Ok(lines) => {
                for line in lines.flatten() {
                    let parts = line.split(" ").collect::<Vec<&str>>();
                    let label = parts[0];
                    let random = parts[1].as_bytes();
                    let secret = parts[2].as_bytes();

                    match label {
                        "CLIENT_TRAFFIC_SECRET_0" => {
                            client_data_keys.push(PskMasterKey::new(random, secret))
                        }

                        "SERVER_TRAFFIC_SECRET_0" => {
                            server_data_keys.push(PskMasterKey::new(random, secret))
                        }
                        // "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
                        // "SERVER_HANDSHAKE_TRAFFIC_SECRET"
                        // "CLIENT_RANDOM"
                        // "EXPORTER_SECRET"
                        _ => {} // ignore other records
                    }
                }

                // Fulup TBD what's about EXPORTER_SECRET | CLIENT_RANDOM ?
                client_data_keys.sort_by(|a, b| a.random.cmp(&b.random));
                server_data_keys.sort_by(|a, b| a.random.cmp(&b.random));
            }
        };
        Ok(Self {
            cipher_changed: 0,
            verbose,
            version: TlsVersion::Unknown,
            cipher: TlsCipherSuite::Unknown,
            client: TlsStream::new(MasterKeyTag::ClientApplication, client_data_keys),
            server: TlsStream::new(MasterKeyTag::ServerApplication, server_data_keys),
        })
    }

    fn get_master_key(&self, tag: &MasterKeyTag) -> Option<Vec<u8>> {
        let hash_table = match tag {
            MasterKeyTag::ClientApplication => &self.client.keys_hasht,
            MasterKeyTag::ServerApplication => &self.server.keys_hasht,
        };

        // all master keys are indexed with client random
        match hash_table.binary_search_by(|key| key.random.cmp(&self.client.random)) {
            Ok(index) => Some(hash_table[index].secret.clone()),
            Err(_) => None,
        }
    }

    fn expand_hkdf_secret(
        &self,
        master_secret: &Datum,
        iv_label: &str,
        key_size: usize,
    ) -> Option<Vec<u8>> {
        // create iv datum key
        let mut iv_buffer = [0 as u8; 64];
        let mut index = write_uint16(key_size as u16, &mut iv_buffer);
        iv_buffer[index] = 6 + iv_label.len() as u8;
        index += 1;
        index += write_text("tls13 ".as_bytes(), &mut iv_buffer[index..]);
        index += write_text(iv_label.as_bytes(), &mut iv_buffer[index..]);
        index += 1; // extra msg non used add ""(len:0)
        let iv_datum = Datum::new(iv_buffer[0..index].to_vec());

        let mut buffer = vec![0u8; key_size];
        let status = unsafe {
            cglue::gnutls_hkdf_expand(
                self.cipher.get_hmac() as u32,
                &master_secret.get_data(),
                &iv_datum.get_data(),
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                key_size,
            )
        };
        if status < 0 {
            eprintln!(
                "hkdf-expand-secret: fail gnutls_hkdf_expand iv_label:{} error:{}",
                iv_label,
                gtls_perror(status)
            );
            return None;
        }
        Some(buffer)
    }

    fn aead_cipher_init(
        &mut self,
        pkg_count: u32,
        keys_hasht_tag: MasterKeyTag,
    ) -> Option<(Vec<u8>, cglue::gnutls_aead_cipher_hd_t)> {
        // compute secret from master secret and client random
        // see https://security.stackexchange.com/questions/184739/tls-1-3-server-handshake-traffic-secret-calculation?rq=1

        // extract master key from SSLKEYLOG stored data indexed by client random
        let master_secret = match self.get_master_key(&keys_hasht_tag) {
            Some(value) => Datum::new(value),
            None => {
                eprintln!(
                    "tls-packet-hello: packet:{} fail to find server psk:{}",
                    pkg_count,
                    bytes_to_hexa(&self.client.random),
                );
                return None;
            }
        };

        println!(
            "aead_cipher_init:{:?} master={}",
            keys_hasht_tag,
            master_secret.get_hexa()
        );
        // expand nonce iv_key used for nonce
        let iv_size = unsafe { cglue::gnutls_cipher_get_iv_size(self.cipher as u32) } as usize;
        let nonce_secret = match self.expand_hkdf_secret(&master_secret, "iv", iv_size) {
            Some(value) => value,
            None => return None,
        };

        // expand application iv_key used for nonce
        let key_size = unsafe { cglue::gnutls_cipher_get_key_size(self.cipher as u32) };
        let application_secret = match self.expand_hkdf_secret(&master_secret, "key", key_size) {
            Some(value) => Datum::new(value),
            None => return None,
        };

        // println! ("secret size:{} hexa:{}", client_secret.get_size(), client_secret.get_hexa());
        // let tag_size = unsafe { cglue::gnutls_cipher_get_tag_size(cipher as u32) };
        let mut aead_handle = unsafe { mem::zeroed::<cglue::gnutls_aead_cipher_hd_t>() };
        let status = unsafe {
            cglue::gnutls_aead_cipher_init(
                &mut aead_handle,
                self.cipher as u32,
                &application_secret.get_data(),
            )
        };
        if status < 0 {
            eprintln!(
                "tls-packet-hello:  packet:{} fail gnutls_aead_cipher_init error:{}",
                pkg_count,
                gtls_perror(status)
            );
            return None;
        }
        return Some((nonce_secret, aead_handle));
    }

    fn process_handshake(&mut self, pkg_count: u32, tls_data: &[u8]) -> Result<(), AfbError> {
        let handshake_msg = tls_data[0] as u32;
        let _data_len = read_uint24(&tls_data[1..1 + 3]);
        let ssl_major = tls_data[4];
        let ssl_minor = tls_data[5];
        // version is deprecated in tls-1.3 and version extension overload it
        if ssl_major == 3 && ssl_minor == 3 {
            self.version = TlsVersion::Tls1_2
        }
        let index = 6;

        match handshake_msg {
            cglue::gnutls_handshake_description_t_GNUTLS_HANDSHAKE_CLIENT_HELLO => {
                let (_index, random) = slice_shift(tls_data, index, 32);
                self.client.random = random.to_vec();
            }

            cglue::gnutls_handshake_description_t_GNUTLS_HANDSHAKE_SERVER_HELLO => {
                // ignore server random
                let (index, random) = slice_shift(tls_data, index, 32);
                self.server.random = random.to_vec();

                // ignore depreciated session id
                let session_len = tls_data[index];
                let index = index + 1 + session_len as usize;

                // get selected cipher
                let (index, data) = slice_shift(tls_data, index, 2);
                let cipher_tag = read_uint16(data);

                // ignore depreciated compression method
                let index = index + 1;

                // get extension length
                let (index, data) = slice_shift(tls_data, index, 2);
                let extensions_len = read_uint16(data);

                // loop on extensions
                if extensions_len > 0 {
                    let extensions_start = index;
                    let mut ext_start = extensions_start;
                    loop {
                        let (index, data) = slice_shift(tls_data, ext_start, 2);
                        let ext_tag = read_uint16(data);
                        let (index, data) = slice_shift(tls_data, index, 2);
                        let ext_len = read_uint16(data);

                        match ext_tag {
                            0x002b => {
                                // ssl version (3.4 => tls-1.3)
                                let ssl_major = tls_data[index];
                                let ssl_minor = tls_data[index + 1];
                                if ssl_major == 3 && ssl_minor == 4 {
                                    self.version = TlsVersion::Tls1_3
                                }
                            }
                            _ => {} // ignore extensions
                        }
                        ext_start = index + ext_len as usize;

                        if ext_start == extensions_start + extensions_len as usize {
                            break;
                        }
                    }
                }

                self.cipher = TlsCipherSuite::from_tagid(cipher_tag);
                if let TlsCipherSuite::Unknown = self.cipher {
                    return afb_error!(
                        "tls-packet-hello",
                        "pkg:{} unsupported TLS cipher-tagid:{:0x}",
                        pkg_count,
                        cipher_tag
                    );
                }

                // create aead_cipher handles for client and server channel
                match self.aead_cipher_init(pkg_count, MasterKeyTag::ClientApplication) {
                    Some((nonce_secret, aead_handle)) => {
                        self.client.aead_handle = aead_handle;
                        self.client.nonce_secret = nonce_secret;
                    }
                    None => {
                        return afb_error!(
                            "tls-packet-hello",
                            "pkg:{} client_application fail gnutls_aead_cipher_init",
                            pkg_count
                        )
                    }
                }

                match self.aead_cipher_init(pkg_count, MasterKeyTag::ServerApplication) {
                    Some((nonce_secret, aead_handle)) => {
                        self.server.aead_handle = aead_handle;
                        self.server.nonce_secret = nonce_secret;
                    }
                    None => {
                        return afb_error!(
                            "tls-packet-hello",
                            "pkg:{} server fail gnutls_aead_cipher_init",
                            pkg_count
                        )
                    }
                }
            }
            _ => {
                return afb_error!(
                    "tls-packet-tls",
                    "pkg:{} unsupported TLS hello-tag",
                    pkg_count
                )
            }
        }
        Ok(())
    }

    fn application_data(
        &mut self,
        pkg_count: u32,
        pkg_dir: PacketDirection,
        tls_auth: &[u8],
        tls_data: &[u8],
    ) -> Result<Vec<u8>, AfbError> {
        // depending on direction select corresponding tls steam sub-handle
        let tls_stream = match pkg_dir {
            PacketDirection::ClientToServer => &mut self.client,
            PacketDirection::ServerToClient => &mut self.server,
            _ => {
                return afb_error!(
                    "application_data",
                    "pkg:{} invalid direction:{:?}",
                    pkg_count,
                    pkg_dir
                );
            }
        };

        // for tls-1.3 nonce size should be 12bytes
        let nonce_size = unsafe { cglue::gnutls_cipher_get_iv_size(self.cipher as u32) as usize };
        let mut seq_nonce = vec![0u8; nonce_size];
        encode_nonce(
            tls_stream.sequence as u64, // sequence start from zero
            &mut seq_nonce[(nonce_size - 8)..nonce_size],
        );

        // sequence number start at 0, increment after nonce computation
        tls_stream.sequence += 1;

        unsafe {
            cglue::nettle_memxor(
                seq_nonce.as_ptr() as *mut c_void,
                tls_stream.nonce_secret.as_ptr() as *const c_void,
                tls_stream.nonce_secret.len(),
            )
        };

        let tag_size = unsafe { cglue::gnutls_cipher_get_tag_size(self.cipher as u32) };
        let mut decrypted = [0 as u8; 256];
        let mut len = decrypted.len();

        let status = unsafe {
            cglue::gnutls_aead_cipher_decrypt(
                tls_stream.aead_handle,
                seq_nonce.as_ptr() as *const c_void,
                seq_nonce.len(),
                tls_auth.as_ptr() as *const c_void,
                tls_auth.len(),
                tag_size as usize,
                tls_data.as_ptr() as *const c_void,
                tls_data.len(),
                decrypted.as_mut_ptr() as *mut c_void,
                &mut len as *const _ as *mut usize,
            )
        };

        if status < 0 {
            return afb_error!(
                "application_data",
                "pkg:{} dir:{:?} error:{}",
                pkg_count,
                pkg_dir,
                gtls_perror(status)
            );
        } else {
            if self.verbose > 8 {
                let text = str::from_utf8(&decrypted[0..len - 2]).unwrap(); // ignore "\n\0"
                println!(
                    "application_data pkg:{} text:'{}' len:{}",
                    pkg_count,
                    text,
                    len - 2
                );
            }
        }

        let data = Vec::new();
        Ok(data)
    }
    fn process_alert(&mut self, _pkg_count: u32, _tls_data: &[u8]) -> Result<(), AfbError> {
        Ok(())
    }
}

struct PcapHeader {
    payload: cglue::pcap_pkthdr,
}
impl PcapHeader {
    fn new(payload: *const cglue::pcap_pkthdr) -> Self {
        Self {
            payload: unsafe { *payload },
        }
    }

    pub fn get_len(&self) -> usize {
        self.payload.len as usize
    }

    pub fn get_timestamp(&self) -> Duration {
        Duration::new(
            self.payload.ts.tv_sec as u64,
            self.payload.ts.tv_usec as u32 * 1000,
        )
    }
}

#[allow(dead_code)]
struct UdpHeader {
    payload: cglue::udp_header,
    size: usize,
}
impl UdpHeader {
    fn new(buffer: *const u8, offset: usize) -> Self {
        let size = mem::size_of::<cglue::udp_header>();
        let data = buffer.wrapping_add(offset);
        let slice = unsafe { slice::from_raw_parts(data, size) };
        let payload = slice.as_ptr() as *const cglue::udp_header;
        let header = unsafe { payload.as_ref().unwrap() };
        Self {
            payload: *header,
            size,
        }
    }
    pub fn get_size(&self) -> usize {
        self.size
    }
}

struct TcpHeader {
    payload: cglue::tcp_header,
    size: usize,
}
#[allow(dead_code)]
impl TcpHeader {
    fn new(buffer: *const u8, offset: usize) -> Self {
        let size = mem::size_of::<cglue::tcp_header>();
        let data = buffer.wrapping_add(offset);
        let slice = unsafe { slice::from_raw_parts(data, size) };
        let payload = slice.as_ptr() as *const cglue::tcp_header;
        let header = unsafe { payload.as_ref().unwrap() };
        Self {
            payload: *header,
            size,
        }
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_len(&self) -> usize {
        //tcp header length is 4*data_offset
        let len = unsafe { self.payload.__bindgen_anon_1.__bindgen_anon_2.doff() };
        4 * len as usize
    }

    pub fn get_src(&self) -> u16 {
        unsafe { cglue::ntohs(self.payload.__bindgen_anon_1.__bindgen_anon_2.source) }
    }

    pub fn get_dst(&self) -> u16 {
        unsafe { cglue::ntohs(self.payload.__bindgen_anon_1.__bindgen_anon_2.dest) }
    }

    pub fn get_seq(&self) -> u32 {
        unsafe { cglue::ntohl(self.payload.__bindgen_anon_1.__bindgen_anon_2.seq) }
    }

    pub fn get_ack_seq(&self) -> u32 {
        unsafe { cglue::ntohl(self.payload.__bindgen_anon_1.__bindgen_anon_2.ack_seq) }
    }

    pub fn get_fin(&self) -> bool {
        if unsafe { self.payload.__bindgen_anon_1.__bindgen_anon_2.fin() } == 0 {
            false
        } else {
            true
        }
    }

    pub fn get_syn(&self) -> bool {
        if unsafe { self.payload.__bindgen_anon_1.__bindgen_anon_2.syn() } == 0 {
            false
        } else {
            true
        }
    }

    pub fn get_ack(&self) -> bool {
        if unsafe { self.payload.__bindgen_anon_1.__bindgen_anon_2.ack() } == 0 {
            false
        } else {
            true
        }
    }
}

struct EtherHeader {
    payload: cglue::ether_header,
    size: usize,
}
impl EtherHeader {
    fn new(buffer: *const u8, offset: usize) -> Self {
        let size = mem::size_of::<cglue::ether_header>();
        let data = buffer.wrapping_add(offset);
        let slice = unsafe { slice::from_raw_parts(data, size) };
        let payload = slice.as_ptr() as *const cglue::ether_header;
        let header = unsafe { payload.as_ref().unwrap() };
        Self {
            payload: *header,
            size,
        }
    }

    pub fn get_type(&self) -> u16 {
        unsafe { cglue::ntohs(self.payload.ether_type) }
    }

    pub fn get_size(&self) -> usize {
        self.size
    }
}

pub enum IpProto {
    UDP,
    TCP,
    Unsupported(u8),
}

struct IpHeader {
    payload: cglue::ip6_header,
    size: usize,
}

#[allow(dead_code)]
impl IpHeader {
    fn new(buffer: *const u8, offset: usize) -> Self {
        let size = mem::size_of::<cglue::ip6_header>();
        let data = buffer.wrapping_add(offset);
        let slice = unsafe { slice::from_raw_parts(data, size) };
        let payload = slice.as_ptr() as *const cglue::ip6_header;
        let header = unsafe { payload.as_ref().unwrap() };
        Self {
            payload: *header,
            size,
        }
    }

    pub fn get_proto(&self) -> IpProto {
        let proto = unsafe {
            match self.payload.ip6_ctlun.ip6_un1.ip6_un1_nxt {
                cglue::C_IPPROTO_TCP => IpProto::TCP,
                cglue::C_IPPROTO_UDP => IpProto::UDP,
                _ => IpProto::Unsupported(self.payload.ip6_ctlun.ip6_un1.ip6_un1_nxt),
            }
        };
        proto
    }

    pub fn get_len(&self) -> usize {
        unsafe { cglue::ntohs(self.payload.ip6_ctlun.ip6_un1.ip6_un1_plen) as usize }
    }

    pub fn get_size(&self) -> usize {
        self.size
    }
}

pub type PcapCallback = fn(
    pkg_count: u32,
    buffer: &[u8],
    timestamp: Duration,
    ctx: &AfbCtxData,
) -> Result<(), AfbError>;

#[track_caller]
fn pcap_default_cb(
    _count: u32,
    _buffer: &[u8],
    _timestamp: Duration,
    _user_data: &AfbCtxData,
) -> Result<(), AfbError> {
    return afb_error!("pcap-default-cb", "no pcap callback defined");
}

pub struct MsgHandle {
    callback: PcapCallback,
    context: AfbCtxData,
    start_stamp: Duration,
    pkg_count: u32,
}

pub struct PcapHandle {
    verbose: u8,
    msg: MsgHandle,
    tls_session: Option<TlsSession>,
    pcap_in: String,
    pcap_raw: *mut cglue::pcap_t,
    seq_time: Duration,
    tcp_port: u16,
    clt_port: u16,
    svc_port: u16,
    seq_next: u32,
    max_count: u32,
}

impl PcapHandle {
    pub fn new() -> Self {
        let msg_handle = MsgHandle {
            start_stamp: Duration::new(0, 0),
            callback: pcap_default_cb,
            context: AfbCtxData::new(AFB_NO_DATA),
            pkg_count: 0,
        };

        PcapHandle {
            pcap_raw: 0 as *mut cglue::pcap_t,
            tls_session: None,
            pcap_in: String::new(),
            msg: msg_handle,
            seq_time: Duration::new(0, 0),
            verbose: 0,
            tcp_port: 0,
            clt_port: 0,
            svc_port: 0,
            seq_next: 0,
            max_count: 0,
        }
    }

    #[track_caller]
    pub fn set_pcap_file(&mut self, filename: &str) -> Result<&mut Self, AfbError> {
        let path = match CString::new(filename) {
            Ok(value) => value,
            Err(_) => return afb_error!("pcap_open_offline", "invalid filename:{}", filename),
        };

        // keep a copy of input file for info
        self.pcap_in = filename.to_string();

        let pcap_raw = unsafe {
            let mut cbuffer =
                mem::MaybeUninit::<[c_char; cglue::PCAP_ERRBUF_SIZE as usize]>::uninit();
            let pcap =
                cglue::pcap_open_offline(path.into_raw(), (cbuffer.as_mut_ptr()) as *mut c_char);
            let buffer = cbuffer.assume_init();
            if pcap == std::ptr::null_mut() {
                let cstring = CStr::from_ptr(buffer.as_ptr());
                return afb_error!(
                    "pcap_open",
                    "error:{}",
                    cstring.to_str().unwrap()
                );
            }
            pcap
        };
        self.pcap_raw = pcap_raw;
        Ok(self)
    }

    pub fn get_pcap_in(&self) -> &str {
        &self.pcap_in
    }

    #[track_caller]
    pub fn set_psk_log(&mut self, key_log: &str) -> Result<&mut Self, AfbError> {
        let tls_session = TlsSession::new(key_log, self.verbose)?;
        self.tls_session = Some(tls_session);
        Ok(self)
    }

    pub fn set_callback(&mut self, callback: PcapCallback) -> &mut Self {
        self.msg.callback = callback;
        self
    }

    pub fn set_verbose(&mut self, verbose: u8) -> &mut Self {
        self.verbose = verbose;
        self
    }

    pub fn set_context<T>(&mut self, ctx: T) -> &mut Self
    where
        T: 'static,
    {
        self.msg.context = AfbCtxData::new(ctx);
        self
    }

    pub fn set_max_packets(&mut self, count: u32) -> &mut Self {
        self.max_count = count;
        self
    }

    pub fn set_tcp_port(&mut self, port: u16) -> &mut Self {
        self.tcp_port = port;
        self
    }

    pub fn get_pkg_count(&self) -> u32 {
        self.msg.pkg_count
    }

    pub fn finalize(&mut self) -> Result<&Self, AfbError> {
        if self.verbose > 0 {
            eprintln!("\n --- start ---")
        }
        let result = unsafe {
            cglue::pcap_loop(
                self.pcap_raw,
                self.max_count as i32,
                Some(api_pcap_cb),
                self as *const _ as *mut u8,
            )
        };

        // close scenario output with calling callback with empty exi
        if let Err(error) =
            (self.msg.callback)(0, &[0; 0], self.msg.start_stamp, &self.msg.context)
        {
            eprintln!("pkg:{} {:?}", self.msg.pkg_count, error);
        }

        if result < 0 {
            let cstr = unsafe { CStr::from_ptr(cglue::pcap_geterr(self.pcap_raw)) };
            return afb_error!(
                "pcap_handle-loop",
                "pkg:{} error:{}",
                self.msg.pkg_count,
                (cstr.to_str().unwrap())
            );
        }

        Ok(self)
    }
}
