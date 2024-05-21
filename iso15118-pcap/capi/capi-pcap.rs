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
 *   * secret: https://security.stackexchange.com/questions/184739/tls-1-3-server-handshake-traffic-secret-calculation
 *  * tls: https://owasp.org/www-chapter-london/assets/slides/OWASPLondon20180125_TLSv1.3_Andy_Brodie.pdf
 */

mod cglue {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi_pcap.rs");
}

//use afbv4::prelude::*;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufRead};
use std::mem;
use std::os::raw::c_char;
use std::slice;
use std::str;
use std::sync::MutexGuard;
use std::time::Duration;
use  std::ffi::c_void;

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

#[no_mangle]
pub extern "C" fn api_pcap_cb(
    userdata: *mut u8,
    header: *const cglue::pcap_pkthdr,
    buffer: *const u8,
) {
    // get Rust pacl handle from user context
    let handle = unsafe { &mut *(userdata as *mut PcapHandle) };

    // pcap header hold timestamp and packet len
    let pcap_header = PcapHeader::new(header);
    handle.count += 1;

    // ignore any non IP packet
    let ether_header = EtherHeader::new(buffer, 0);
    if ether_header.get_type() != cglue::C_ETHERTYPE_IPV6 {
        if handle.verbose > 0 {
            eprintln!(
                "ether-packet-type: ignore packet:{} {:#0x} ",
                handle.count,
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

            // new sequence check destination port and set relative timestamp
            if tcp_header.get_syn() {
                if !tcp_header.get_ack() {
                    handle.start_stamp = pcap_header.get_timestamp();
                    handle.seq_time = handle.start_stamp;
                    handle.clt_port = tcp_header.get_src();
                    handle.svc_port = tcp_header.get_dst();
                }
                handle.seq_next = tcp_header.get_ack_seq();
                eprintln!(
                    "pkg:{} New TCP stream src:{} ack:{} seq:{} next:{}",
                    handle.count,
                    tcp_header.get_src(),
                    tcp_header.get_ack(),
                    tcp_header.get_seq(),
                    tcp_header.get_ack_seq(),
                );
                return;
            }

            // check packet ordering
            let order_valid = if tcp_header.get_src() == handle.clt_port {
                if handle.seq_next == tcp_header.get_seq()
                    || handle.seq_next == tcp_header.get_ack_seq()
                {
                    true
                } else {
                    false
                }
            } else if tcp_header.get_src() == handle.svc_port {
                if handle.seq_next == tcp_header.get_seq()
                    || handle.seq_next == tcp_header.get_ack_seq()
                {
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !order_valid {
                eprintln!(
                    "pkg:{} ip-client-packet: out of stream packet ack:{} len:{} src:{} dst:{} seq:{} next:{} expected:{}",
                    handle.count,
                    tcp_header.get_ack(),
                    data_len,
                    tcp_header.get_src(),
                    tcp_header.get_dst(),
                    tcp_header.get_seq(),
                    tcp_header.get_ack_seq(),
                    handle.seq_next,
                );
                handle.finished = true;
                return;
            }

            if tcp_header.get_fin() {
                eprintln!(
                    "ip-packet-type: finish tcp session src:{}",
                    tcp_header.get_src()
                );
                handle.finished = true;
                return;
            }

            // keep track of newt expected sequence number
            handle.seq_next = tcp_header.get_ack_seq();

            if data_len == 0 {
                if handle.verbose > 0 {
                    eprintln!(
                        "pkg:{} ip-packet-type: ignoring empty packet ack:{} src:{} seq:{} next:{}",
                        handle.count,
                        tcp_header.get_ack(),
                        tcp_header.get_src(),
                        tcp_header.get_seq(),
                        tcp_header.get_ack_seq(),
                    );
                }
                return;
            }

            eprintln!(
                "pkg:{} tcp-packet-type: len:{} ack:{} src:{} seq:{} next:{}",
                handle.count,
                data_len,
                tcp_header.get_ack(),
                tcp_header.get_src(),
                tcp_header.get_seq(),
                tcp_header.get_ack_seq(),
            );

            let data = unsafe {
                slice::from_raw_parts(
                    buffer.wrapping_add(
                        ether_header.get_size() + ip_header.get_size() + tcp_header.get_len(),
                    ),
                    data_len,
                )
            };

            // check is SSL pre_shared key is set
            match &mut handle.tls_session {
                None => stream_push_data(handle, tcp_header, pcap_header.get_timestamp(), data),
                Some(tls_session) => {
                    let mut tls_start = 0;

                    loop {
                        // check TLS message header
                        let (index, tls_header) =
                            slice_shift(data, tls_start, cglue::TLS_RECORD_HEADER_SIZE);
                        let msg_handshake = tls_header[0] as u32;
                        let msg_major = tls_header[1];
                        let msg_minor = tls_header[2];
                        let msg_len = read_uint16(&tls_header[3..3 + 2]);

                        if msg_major < 3 {
                            eprintln!(
                                "tls-packet-tls: SSL version < 3.x header len src:{} packet:{}",
                                tcp_header.get_src(),
                                handle.count
                            );
                            return;
                        }

                        // shift to tls data record
                        let (index, tls_data) = slice_shift(data, index, msg_len as usize);

                        match msg_handshake {
                            cglue::TLS_MSG_TAG_HANDSHAKE => {
                                tls_session.process_handshake(handle.count, &tls_data)
                            }

                            cglue::TLS_MSG_TAG_APPDATA => {
                                if msg_minor < 3 {
                                    eprintln!(
                                    "tls-packet-tls: SSL version < 3.3 header len src:{} packet:{}",
                                    tcp_header.get_src(),
                                    handle.count
                                    );
                                    return;
                                }

                                let _appdata = tls_session.application_data(handle.count, tls_data);
                                // if let Some(data) = appdata {
                                //     stream_push_data(
                                //         handle,
                                //         tcp_header,
                                //         pcap_header.get_timestamp(),
                                //         &data,
                                //     );
                                // }
                            }
                            cglue::TLS_MSG_TAG_ALERT => {
                                tls_session.process_alert(handle.count, &tls_data)
                            }

                            cglue::TLS_MSG_TAG_CIPHER_CHANGE => {
                                // ignore message
                            }
                            _ => eprintln!(
                                "tls-packet-tls: unsupported TLS message tag src:{} packet:{}",
                                tcp_header.get_src(),
                                handle.count
                            ),
                        }

                        // move to next tls-1.3 extension until end of tcp buffer
                        tls_start = index;
                        if tls_start == data.len() as usize {
                            break;
                        }
                    }
                }
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
                eprintln!("ip-packet-type: ignoring packet:{} UDP", handle.count);
            }
        }

        IpProto::Unsupported(value) => {
            if handle.verbose > 0 {
                eprintln!(
                    "ip-packet-type: ignoring packet:{} proto:{:#0x} ",
                    handle.count, value
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

#[allow(non_camel_case_types, unused)]
enum DatumLabel {
    EARLY_TRAFFIC_LABEL,
    EXT_BINDER_LABEL,
    RES_BINDER_LABEL,
    EARLY_EXPORTER_MASTER_LABEL,
    HANDSHAKE_CLIENT_TRAFFIC_LABEL,
    HANDSHAKE_SERVER_TRAFFIC_LABEL,
    DERIVED_LABEL,
    APPLICATION_CLIENT_TRAFFIC_LABEL,
    APPLICATION_SERVER_TRAFFIC_LABEL,
    APPLICATION_TRAFFIC_UPDATE,
    EXPORTER_MASTER_LABEL,
    RMS_MASTER_LABEL,
    EXPORTER_LABEL,
    RESUMPTION_LABEL,
}

impl DatumLabel {
    fn get_data(&self) -> cglue::gnutls_datum_t {
        use DatumLabel::*;
        let label = match self {
            EARLY_TRAFFIC_LABEL => cglue::TLS_EARLY_TRAFFIC_LABEL as &[u8],
            EXT_BINDER_LABEL => cglue::TLS_EXT_BINDER_LABEL as &[u8],
            RES_BINDER_LABEL => cglue::TLS_RES_BINDER_LABEL as &[u8],
            EARLY_EXPORTER_MASTER_LABEL => cglue::TLS_EARLY_EXPORTER_MASTER_LABEL as &[u8],
            HANDSHAKE_CLIENT_TRAFFIC_LABEL => cglue::TLS_HANDSHAKE_CLIENT_TRAFFIC_LABEL as &[u8],
            HANDSHAKE_SERVER_TRAFFIC_LABEL => cglue::TLS_HANDSHAKE_SERVER_TRAFFIC_LABEL as &[u8],
            DERIVED_LABEL => cglue::TLS_DERIVED_LABEL as &[u8],
            APPLICATION_CLIENT_TRAFFIC_LABEL => cglue::TLS_APPLICATION_CLIENT_TRAFFIC_LABEL as &[u8],
            APPLICATION_SERVER_TRAFFIC_LABEL => cglue::TLS_APPLICATION_SERVER_TRAFFIC_LABEL as &[u8],
            APPLICATION_TRAFFIC_UPDATE => cglue::TLS_APPLICATION_TRAFFIC_UPDATE as &[u8],
            EXPORTER_MASTER_LABEL => cglue::TLS_EXPORTER_MASTER_LABEL as &[u8],
            RMS_MASTER_LABEL => cglue::TLS_RMS_MASTER_LABEL as &[u8],
            EXPORTER_LABEL => cglue::TLS_EXPORTER_LABEL as &[u8],
            RESUMPTION_LABEL => cglue::TLS_RESUMPTION_LABEL as &[u8],
        };
        Datum::new(label[0..label.len() - 1].to_vec()).get_data()
    }
}

struct Datum {
    buffer: Vec<u8>,
    payload: cglue::gnutls_datum_t,
}

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

    pub fn get_data(&self) -> cglue::gnutls_datum_t {
        self.payload
    }

    pub fn get_size(&self) -> usize {
        self.payload.size as usize
    }
}

enum MasterKeySecret {
    RandomTls1_2,
    ClientTls1_3,
    ServerTls1_3,
}

struct TlsSession {
    client: Vec<PskMasterKey>,
    server: Vec<PskMasterKey>,
    random: Vec<PskMasterKey>,
    version: TlsVersion,
    cipher: TlsCipherSuite,
    sequence_num: usize,
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    client_aead: cglue::gnutls_aead_cipher_hd_t,
    server_aead: cglue::gnutls_aead_cipher_hd_t,
}

impl TlsSession {
    fn new(key_log: &str) -> Result<Self, AfbError> {
        let mut client_keys = Vec::new();
        let mut server_keys = Vec::new();
        let mut random_keys = Vec::new();
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
                        "CLIENT_RANDOM" => random_keys.push(PskMasterKey::new(random, secret)),
                        "CLIENT_TRAFFIC_SECRET_0" => {
                            client_keys.push(PskMasterKey::new(random, secret))
                        }
                        "SERVER_TRAFFIC_SECRET_0" => {
                            server_keys.push(PskMasterKey::new(random, secret))
                        }
                        _ => {} // ignore other records
                    }
                }
                // sort key by client random
                random_keys.sort_by(|a, b| a.random.cmp(&b.random));
                client_keys.sort_by(|a, b| a.random.cmp(&b.random));
                server_keys.sort_by(|a, b| a.random.cmp(&b.random));
            }
        }
        Ok(Self {
            version: TlsVersion::Unknown,
            cipher: TlsCipherSuite::Unknown,
            client: client_keys,
            server: server_keys,
            random: random_keys,
            sequence_num: 0,
            client_random: Vec::new(),
            server_random: Vec::new(),
            client_aead: unsafe { mem::zeroed::<cglue::gnutls_aead_cipher_hd_t>() },
            server_aead: unsafe { mem::zeroed::<cglue::gnutls_aead_cipher_hd_t>() },
        })
    }

    fn get_master_key(&self, label: MasterKeySecret, random: &[u8]) -> Option<Vec<u8>> {
        let hash_table = match label {
            MasterKeySecret::RandomTls1_2 => &self.random,
            MasterKeySecret::ClientTls1_3 => &self.client,
            MasterKeySecret::ServerTls1_3 => &self.server,
        };

        match hash_table.binary_search_by(|key| key.random.cmp(&Vec::from(random))) {
            Ok(index) => Some(hash_table[index].secret.clone()),
            Err(_) => None,
        }
    }

    fn process_handshake(&mut self, pkg_count: u32, tls_data: &[u8]) {
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
                self.client_random = random.to_vec();
                println!("client random:{}", bytes_to_hexa(random));
                return;
            }

            cglue::gnutls_handshake_description_t_GNUTLS_HANDSHAKE_SERVER_HELLO => {
                // ignore server random
                let (index, random) = slice_shift(tls_data, index, 32);
                self.server_random = random.to_vec();
                println!("server random:{}", bytes_to_hexa(random));

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
                    eprintln!(
                        "tls-packet-hello:  packet:{} unsupported TLS cipher-tagid:{:0x}",
                        pkg_count, cipher_tag,
                    );
                    return;
                }

                // extract master key from SSLKEYLOG stored data
                let master_secret =
                    match self.get_master_key(MasterKeySecret::ServerTls1_3, &self.client_random) {
                        Some(value) => Datum::new(value),
                        None => {
                            eprintln!(
                                "tls-packet-hello: packet:{} fail to find server psk:{}",
                                pkg_count,
                                bytes_to_hexa(&self.client_random),
                            );
                            return;
                        }
                    };

                // compute secret from master secret and client random
                // see https://security.stackexchange.com/questions/184739/tls-1-3-server-handshake-traffic-secret-calculation?rq=1
                let client_secret = {
                    let key_size = unsafe { cglue::gnutls_cipher_get_key_size(self.cipher as u32) };
                    let mut buffer = vec![0u8; key_size];
                    let status = unsafe {
                        cglue::gnutls_hkdf_expand(
                            self.cipher.get_hmac() as u32,
                            &master_secret.get_data(),
                            &DatumLabel::APPLICATION_CLIENT_TRAFFIC_LABEL.get_data(),
                            buffer.as_mut_ptr() as *mut std::ffi::c_void,
                            key_size,
                        )
                    };
                    if status < 0 {
                        eprintln!(
                            "tls-packet-hello:  packet:{} fail gnutls_hkdf_expand error:{}",
                            pkg_count,
                            gtls_perror(status)
                        );
                        return;
                    }
                    Datum::new(buffer)
                };

                // println! ("secret size:{} hexa:{}", client_secret.get_size(), client_secret.get_hexa());
                // let tag_size = unsafe { cglue::gnutls_cipher_get_tag_size(cipher as u32) };

                let status = unsafe {
                    cglue::gnutls_aead_cipher_init(
                        &mut self.server_aead,
                        self.cipher as u32,
                        &client_secret.get_data(),
                    )
                };
                if status < 0 {
                    eprintln!(
                        "tls-packet-hello:  packet:{} fail gnutls_aead_cipher_init error:{}",
                        pkg_count,
                        gtls_perror(status)
                    );
                    return;
                }
            }
            _ => {
                eprintln!(
                    "tls-packet-tls: unsupported TLS hello-tag packet:{}",
                    pkg_count
                );
                return;
            }
        }
    }

    fn application_data(&mut self, pkg_count: u32, tls_data: &[u8]) -> Option<Vec<u8>> {
        println!("pkg:{} crypt data:{}", pkg_count, bytes_to_hexa(tls_data));

        // for tls-1.3 nonce size should be 12
        let nonce_size = unsafe { cglue::gnutls_cipher_get_iv_size(self.cipher as u32) as usize };
        let mut nonce = vec![0u8; nonce_size];
        encode_nonce(self.sequence_num as u64, &mut nonce[(nonce_size - 8)..nonce_size]);
        unsafe {cglue::nettle_memxor (nonce.as_ptr() as *mut c_void, self.client_random.as_ptr() as *const c_void, nonce_size as usize) };

        println!("tls_seq:{} nonce:{}", self.sequence_num, bytes_to_hexa(&nonce));

        let tag_size = unsafe { cglue::gnutls_cipher_get_tag_size(self.cipher as u32) };

        //let status = unsafe {cglue::gnutls_aead_cipher_decrypt(self.server_aead, &none, &none.len)};

        let data = Vec::new();
        Some(data)
    }
    fn process_alert(&mut self, _pkg_count: u32, _tls_data: &[u8]) {}
}

// New TCP client connecting
fn stream_push_data(
    handle: &mut PcapHandle,
    header: TcpHeader,
    timestamp: Duration,
    exi_data: &[u8],
) {
    // move tcp socket data into exi stream buffer
    let mut lock = handle.stream.lock_stream();
    let (stream_idx, stream_available) = handle.stream.get_index(&lock);

    if stream_available == 0 {
        eprintln!(
            "stream_push_data {:?}, buffer full close session",
            header.get_src()
        );
        return;
    } else {
        // move tcp data into exi stream internal buffer
        lock.buffer[stream_idx..exi_data.len()].copy_from_slice(exi_data)
    }

    // when facing a new exi check how much data should be read
    if stream_idx == 0 {
        let len = handle.stream.get_payload_len(&lock);
        if len < 0 {
            eprintln!(
                "stream_push_data: packet ignored (invalid v2g header) size:{}",
                exi_data.len()
            );
        } else {
            handle.exi_len = len as usize;
        }
        handle.data_len = 0;
    }
    // if data send in chunks let's complete exi buffer before processing it
    handle.data_len = handle.data_len + exi_data.len();
    if handle.data_len >= handle.exi_len + v2g::SDP_V2G_HEADER_LEN {
        // set data len and decode message and place response into stream-out (stream should not be lock_ined)
        if let Err(error) = handle.stream.finalize(&lock, handle.exi_len as u32) {
            eprintln!("stream-finalize: pkg:{} {:?}", handle.count, error);
            return;
        }

        // call user defined callback
        let delay = timestamp - handle.start_stamp;
        if let Err(error) = (handle.callback)(&lock, handle.count, delay, &handle.context) {
            eprintln!("pkg:{} {:?}", handle.count, error);
        }
        // wipe stream for next request
        handle.stream.reset(&lock);
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
    stream: &MutexGuard<RawStream>,
    count: u32,
    timestamp: Duration,
    ctx: &AfbCtxData,
) -> Result<(), AfbError>;

#[track_caller]
fn pcap_default_cb(
    _stream: &MutexGuard<RawStream>,
    _count: u32,
    _timestamp: Duration,
    _user_data: &AfbCtxData,
) -> Result<(), AfbError> {
    return afb_error!("pcap-default-cb", "no pcap callback defined");
}

pub struct PcapHandle {
    verbose: u8,
    stream: ExiStream,
    tls_session: Option<TlsSession>,
    handle: *mut cglue::pcap_t,
    tcp_port: u16,
    clt_port: u16,
    svc_port: u16,
    start_stamp: Duration,
    context: AfbCtxData,
    callback: PcapCallback,
    seq_next: u32,
    seq_time: Duration,
    finished: bool,
    data_len: usize,
    exi_len: usize,
    max_count: u32,
    skip_count: u32,
    count: u32,
}

impl PcapHandle {
    pub fn new() -> Self {
        PcapHandle {
            handle: 0 as *mut cglue::pcap_t,
            tls_session: None,
            verbose: 0,
            finished: false,
            tcp_port: 0,
            clt_port: 0,
            svc_port: 0,
            start_stamp: Duration::new(0, 0),
            seq_time: Duration::new(0, 0),
            seq_next: 0,
            data_len: 0,
            exi_len: 0,
            max_count: 0,
            count: 0,
            skip_count: 0,
            callback: pcap_default_cb,
            context: AfbCtxData::new(AFB_NO_DATA),
            stream: ExiStream::new(),
        }
    }

    pub fn set_pcap_file(&mut self, filename: &str) -> Result<&mut Self, AfbError> {
        let path = match CString::new(filename) {
            Ok(value) => value,
            Err(_) => return afb_error!("pcap_open_offline", "invalid filename:{}", filename),
        };

        let handle = unsafe {
            let mut cbuffer =
                mem::MaybeUninit::<[c_char; cglue::PCAP_ERRBUF_SIZE as usize]>::uninit();
            let pcap =
                cglue::pcap_open_offline(path.into_raw(), (cbuffer.as_mut_ptr()) as *mut c_char);
            let buffer = cbuffer.assume_init();
            if pcap == std::ptr::null_mut() {
                let cstring = CStr::from_ptr(buffer.as_ptr());
                return afb_error!(
                    "pcap_open_offline",
                    "fail open:{} error:{}",
                    filename,
                    cstring.to_str().unwrap()
                );
            }
            pcap
        };
        self.handle = handle;
        Ok(self)
    }

    pub fn set_psk_log(&mut self, key_log: &str) -> Result<&mut Self, AfbError> {
        let tls_session = TlsSession::new(key_log)?;
        self.tls_session = Some(tls_session);
        Ok(self)
    }

    pub fn set_callback(&mut self, callback: PcapCallback) -> &mut Self {
        self.callback = callback;
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
        self.context = AfbCtxData::new(ctx);
        self
    }

    pub fn set_skip_packet(&mut self, count: u32) -> &mut Self {
        self.skip_count = count;
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

    pub fn finalize(&mut self) -> Result<(), AfbError> {
        if self.verbose > 0 {
            eprintln!("\n --- start ---")
        }
        let result = unsafe {
            cglue::pcap_loop(
                self.handle,
                self.max_count as i32,
                Some(api_pcap_cb),
                self as *const _ as *mut u8,
            )
        };

        if result < 0 {
            let cstr = unsafe { CStr::from_ptr(cglue::pcap_geterr(self.handle)) };
            return afb_error!("pcap_handle-loop", "{}", cstr.to_str().unwrap());
        }
        Ok(())
    }
}
