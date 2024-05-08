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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>


#include <pcap.h>

const size_t C_PCAP_ERRBUF_SIZE= PCAP_ERRBUF_SIZE;
const ushort C_ETHERTYPE_IPV6= ETHERTYPE_IPV6;
const ushort C_AF_INET6 = AF_INET6;
const u_char C_IPPROTO_UDP = IPPROTO_UDP;
const u_char C_IPPROTO_TCP = IPPROTO_TCP;
const u_char C_IPPROTO_IPV6= IPPROTO_IPV6;
const u_char C_IPPROTO_ICMP= IPPROTO_ICMP;

typedef struct in6_addr C_in6_addr;
typedef struct pcap_pkthdr pcap_header;
typedef struct ip6_hdr ip6_header;
typedef struct ether_header ether_header;
typedef struct tcphdr tcp_header;
typedef struct udphdr udp_header;
