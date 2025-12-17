#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "header.p4"
#include "parser.p4"

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

        action ai_set_default_features() {
            ig_md.action_select_packet_len = 0;
            ig_md.action_select_ether_type = 0;
            ig_md.action_select_ipv4_proto = 0;
            ig_md.action_select_ipv4_flags = 0;
            ig_md.action_select_ipv6_next_hdr = 0;
            ig_md.action_select_ipv6_options = 0;
            ig_md.action_select_tcp_src_port = 0;
            ig_md.action_select_tcp_dst_port = 0;
            ig_md.action_select_tcp_flags = 0;
            ig_md.action_select_udp_src_port = 0;
            ig_md.action_select_udp_dst_port = 0;
        }

        action ai_drop() {
            ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
        }

        action ai_forward(portid_t egress_port){
            ig_tm_md.ucast_egress_port = egress_port;
        }

        action ai_ipv4_forward(mac_addr_t dst_mac, portid_t egress_port){
            hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
            hdr.ethernet.dst_mac = dst_mac;
            ig_tm_md.ucast_egress_port = egress_port;
        }

        action ai_select_packet_len(bit<12> val) { ig_md.action_select_packet_len = val; }
        action ai_select_ether_type(bit<12> val) { ig_md.action_select_ether_type = val; }
        action ai_select_ipv4_proto(bit<12> val) { ig_md.action_select_ipv4_proto = val; }
        action ai_select_ipv4_flags(bit<12> val) { ig_md.action_select_ipv4_flags = val; }
        action ai_select_ipv6_next_hdr(bit<12> val) { ig_md.action_select_ipv6_next_hdr = val; }
        action ai_select_ipv6_options(bit<12> val) { ig_md.action_select_ipv6_options = val; }
        action ai_select_tcp_src_port(bit<12> val) { ig_md.action_select_tcp_src_port = val; }
        action ai_select_tcp_dst_port(bit<12> val) { ig_md.action_select_tcp_dst_port = val; }
        action ai_select_tcp_flags(bit<12> val) { ig_md.action_select_tcp_flags = val; }
        action ai_select_udp_src_port(bit<12> val) { ig_md.action_select_udp_src_port = val; }
        action ai_select_udp_dst_port(bit<12> val) { ig_md.action_select_udp_dst_port = val; }

        table ti_packet_len {
            key = { ig_md.ip_len : range; }
            actions = { NoAction; ai_select_packet_len; }
            size = 1024;
        }
        table ti_ether_type {
            key = { hdr.ethernet.ether_type : range; }
            actions = { NoAction; ai_select_ether_type; }
            size = 1024;
        }
        table ti_ipv4_proto {
            key = { hdr.ipv4.protocol : range; }
            actions = { NoAction; ai_select_ipv4_proto; }
            size = 1024;
        }
        table ti_ipv4_flags {
            key = { hdr.ipv4.flags : range; }
            actions = { NoAction; ai_select_ipv4_flags; }
            size = 1024;
        }
        table ti_ipv6_next_hdr {
            key = { hdr.ipv6.next_hdr : range; }
            actions = { NoAction; ai_select_ipv6_next_hdr; }
            size = 1024;
        }
        table ti_tcp_src_port {
            key = { hdr.tcp.src_port : range; }
            actions = { NoAction; ai_select_tcp_src_port; }
            size = 1024;
        }
        table ti_tcp_dst_port {
            key = { hdr.tcp.dst_port : range; }
            actions = { NoAction; ai_select_tcp_dst_port; }
            size = 1024;
        }
        table ti_tcp_flags {
            key = { hdr.tcp.flags : range; }
            actions = { NoAction; ai_select_tcp_flags; }
            size = 1024;
        }
        table ti_udp_src_port {
            key = { hdr.udp.src_port : range; }
            actions = { NoAction; ai_select_udp_src_port; }
            size = 1024;
        }
        table ti_udp_dst_port {
            key = { hdr.udp.dst_port : range; }
            actions = { NoAction; ai_select_udp_dst_port; }
            size = 1024;
        }

        table ti_forward {
            key = {
                ig_md.action_select_packet_len : range;
                ig_md.action_select_ether_type : range;
                ig_md.action_select_ipv4_proto : range;
                ig_md.action_select_ipv4_flags : range;
                ig_md.action_select_ipv6_next_hdr : range;
                ig_md.action_select_ipv6_options : range;
                ig_md.action_select_tcp_src_port : range;
                ig_md.action_select_tcp_dst_port : range;
                ig_md.action_select_tcp_flags : range;
                ig_md.action_select_udp_src_port : range;
                ig_md.action_select_udp_dst_port : range;
            }
            actions = {
                ai_ipv4_forward;
                ai_drop;
                NoAction;
            }
            size = 1024;
            default_action = ai_drop;
        }

        apply {
            ai_set_default_features();
            if (hdr.ipv4.isValid()) {
                ig_md.ip_len = hdr.ipv4.total_len;
            } else if (hdr.ipv6.isValid()) {
                ig_md.ip_len = hdr.ipv6.payload_len + 16w40;
            } else {
                ig_md.ip_len = 0;
            }
            ti_packet_len.apply();
            ti_ether_type.apply();
            if (hdr.ipv4.isValid()) {
                ti_ipv4_proto.apply();
                ti_ipv4_flags.apply();
            }
            if (hdr.ipv6.isValid()) {
                ti_ipv6_next_hdr.apply();
            }
            if (hdr.tcp.isValid()) {
                ti_tcp_src_port.apply();
                ti_tcp_dst_port.apply();
                ti_tcp_flags.apply();
            }
            if (hdr.udp.isValid()) {
                ti_udp_src_port.apply();
                ti_udp_dst_port.apply();
            }
            ti_forward.apply();
        }
}

control SwitchEgress(
    inout header_t hdr,
    inout egress_metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply { }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
