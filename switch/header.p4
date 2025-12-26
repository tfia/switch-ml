#ifndef _HEADER_
#define _HEADER_

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
typedef bit<8> ip_protocol_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<9>   portid_t;       
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86DD;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;

const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


header ethernet_h {
    mac_addr_t dst_mac;
    mac_addr_t src_mac;
    ether_type_t ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> checksum;
    ipv4_addr_t src_ip;
    ipv4_addr_t dst_ip;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_ip;
    ipv6_addr_t dst_ip;
}

header icmp_h {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> id;
    bit<16> seq_no;
    // bit<64> tstamp;
}
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    mac_addr_t sender_mac;
    ipv4_addr_t sender_ip;
    mac_addr_t target_mac;
    ipv4_addr_t target_ip;
    // ...
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    ipv6_h ipv6;
    arp_h arp;
    tcp_h tcp;
    udp_h udp;
    icmp_h     icmp;
}

struct decision_tree_metadata_t {
    // Raw features (aligned to models/decision_tree.txt)
    bit<16> frame_len;
    bit<8>  ip_proto;
    bit<16> l4_src_port;
    bit<16> l4_dst_port;

    // Discretized feature IDs used as keys in ti_forward
    bit<12> action_select_frame_len;
    bit<12> action_select_ether_type;
    bit<12> action_select_ip_proto;
    bit<12> action_select_l4_src_port;
    bit<12> action_select_l4_dst_port;
}

struct kmeans_metadata_t {
    bit<16> f_frame_len;
    bit<16> f_eth_type;
    bit<8>  f_ip_proto;
    bit<16> f_l4_src_port;
    bit<16> f_l4_dst_port;

    bit<32> dist_c1;
    bit<32> dist_c2;
    bit<32> dist_c3;

    bit<32> min_dist;
    bit<32> delta;
    bit<1> delta_sign;
    bit<8> classification; // 1 to 3
}

struct egress_metadata_t{
    ipv4_addr_t port_ip;
    mac_addr_t port_mac;
}

struct empty_header_t {}

struct empty_metadata_t {}



#endif /* _HEADER_ */