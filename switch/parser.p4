#ifndef _PARSER_
#define _PARSER_
#include <core.p4>
#include <tna.p4>
#include "header.p4"
#include "util.p4"

parser SwitchIngressParser(
        packet_in pkt, 
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
    state parse_udp{
        pkt.extract(hdr.udp);
        transition accept;
    }
    state parse_tcp{
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}
parser SwitchEgressParser(
        packet_in pkt,
        out header_t hdr,
        out egress_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md){

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_ARP : parse_arp;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            IP_PROTOCOLS_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }
    state parse_udp{
        pkt.extract(hdr.udp);
        transition accept;
    }
    state parse_tcp{
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

control SwitchEgressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in egress_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {
    // I don't think we need to recalculate IPv4 checksum here,
    // since we are not modifying the packet.
    // However the paper did this, so we follow it.
    // We can test the performance difference later...
    Checksum() ipv4_csum;
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.checksum = ipv4_csum.update({
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.frag_offset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                /* skip hdr.ipv4.hdr_checksum, */
                hdr.ipv4.src_ip,
                hdr.ipv4.dst_ip
            });
        }
        pkt.emit(hdr);
    }
}

#endif /* _PARSER_ */