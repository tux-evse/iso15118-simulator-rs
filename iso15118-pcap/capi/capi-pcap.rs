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
 */

mod cglue {
    #![allow(dead_code)]
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    include!("_capi_pcap.rs");
}

//use afbv4::prelude::*;
use iso15118::prelude::*;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::mem;
use std::os::raw::c_char;
use std::slice;
use std::sync::MutexGuard;
use std::time::Duration;

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
        eprintln!(
            "ether-packet-type: ignore packet:{} {:#0x} ",
            handle.count,
            ether_header.get_type()
        );
        return;
    }

    // ignore any non UDP/TCP packet
    let ip_header = IpHeader::new(buffer, ether_header.get_size());
    match ip_header.get_proto() {
        IpProto::TCP => {
            let tcp_header = TcpHeader::new(buffer, ether_header.get_size() + ip_header.get_size());
            let data_len = ip_header.get_len() as usize - tcp_header.get_size();

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
                    "ip-packet-type: New TCP sequence packet:{} src:{} ack:{} seq:{} next:{}",
                    handle.count,
                    tcp_header.get_src(),
                    tcp_header.get_ack(),
                    tcp_header.get_seq(),
                    tcp_header.get_ack_seq(),
                );
                return;
            }

            if tcp_header.get_seq() != handle.seq_next {
                eprintln!(
                    "ip-packet-type: broken sequence packet:{} len:{} src:{} seq:{} ack:{} next:{}",
                    handle.count,
                    data_len,
                    tcp_header.get_src(),
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

            if data_len == 0 {
                eprintln!(
                    "ip-packet-type: ignoring empty packet:{} ack:{} src:{} seq:{} next:{}",
                    handle.count,
                    tcp_header.get_ack(),
                    tcp_header.get_src(),
                    tcp_header.get_seq(),
                    tcp_header.get_ack_seq(),
                );
                return;
            }

            eprintln!(
                "ip-packet-type: data packet:{} len:{} ack:{} src:{} seq:{} next:{}",
                handle.count,
                data_len,
                tcp_header.get_ack(),
                tcp_header.get_src(),
                tcp_header.get_seq(),
                tcp_header.get_ack_seq(),
            );

            // keep track of newt expected sequence number
            handle.seq_next = tcp_header.get_ack_seq();

            let data_offset =
                ether_header.get_size() + ip_header.get_size() + tcp_header.get_size();
            let data_length = pcap_header.get_len() as usize - data_offset;
            if data_length == 0 {
                eprintln!(
                    "ip-packet-type: No data src:{} packet:{}",
                    tcp_header.get_src(),
                    handle.count
                );
                return;
            }

            let data =
                unsafe { slice::from_raw_parts(buffer.wrapping_add(data_offset), data_length) };

            let _= stream_push_data(handle, tcp_header, pcap_header.get_timestamp(), data);
        }

        IpProto::UDP => {
            let udp_header = UdpHeader::new(buffer, ether_header.get_size() + ip_header.get_size());
            let data_offset =
                ether_header.get_size() + ip_header.get_size() + udp_header.get_size();
            let data_length = pcap_header.get_len() as usize - data_offset;
            let _data =
                unsafe { slice::from_raw_parts(buffer.wrapping_add(data_offset), data_length) };
            eprintln!("ip-packet-type: ignoring packet:{} UDP", handle.count);
            return;
        }

        IpProto::Unsupported(value) => {
            eprintln!(
                "ip-packet-type: ignoring packet:{} proto:{:#0x} ",
                handle.count, value
            );
            return;
        }
    }
}

// New TCP client connecting
fn stream_push_data(
    handle: &mut PcapHandle,
    header: TcpHeader,
    timestamp: Duration,
    exi_data: &[u8],
) -> Result<(), AfbError> {
    // move tcp socket data into exi stream buffer
    let mut lock = handle.stream.lock_stream();
    let (stream_idx, stream_available) = handle.stream.get_index(&lock);

    if stream_available == 0 {
        return afb_error!(
            "stream_push_data",
            "stream_push_data {:?}, buffer full close session",
            header.get_src()
        );
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
        handle.stream.finalize(&lock, handle.exi_len as u32)?;

        // call user defined callback
        let delay = timestamp - handle.start_stamp;
        if let Err(error) = (handle.callback)(&lock, handle.count, delay, &handle.context) {
            eprintln!("{}", error);
        }
        // wipe stream for next request
        handle.stream.reset(&lock);
    }
    Ok(())
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

    pub fn get_len(&self) -> u16 {
        unsafe { cglue::ntohs(self.payload.ip6_ctlun.ip6_un1.ip6_un1_plen) }
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
    stream: ExiStream,
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
    count: u32,
}

impl PcapHandle {
    pub fn new() -> Self {
        PcapHandle {
            handle: 0 as *mut cglue::pcap_t,
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

    pub fn set_callback(&mut self, callback: PcapCallback) -> &mut Self {
        self.callback = callback;
        self
    }

    pub fn set_context<T>(&mut self, ctx: T) -> &mut Self
    where
        T: 'static,
    {
        self.context = AfbCtxData::new(ctx);
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
