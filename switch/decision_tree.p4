#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "header.p4"
#define metadata_t decision_tree_metadata_t
#include "parser.p4"

control SwitchIngress(
    inout header_t hdr,
    inout decision_tree_metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action ai_set_default_features() {
        ig_md.action_select_frame_len = 0;
        ig_md.action_select_ether_type = 0;
        ig_md.action_select_ip_proto = 0;
        ig_md.action_select_l4_src_port = 0;
        ig_md.action_select_l4_dst_port = 0;
    }

    action ai_drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action ai_forward(portid_t egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action ai_select_frame_len(bit<12> val) { ig_md.action_select_frame_len = val; }
    action ai_select_ether_type(bit<12> val) { ig_md.action_select_ether_type = val; }
    action ai_select_ip_proto(bit<12> val) { ig_md.action_select_ip_proto = val; }
    action ai_select_l4_src_port(bit<12> val) { ig_md.action_select_l4_src_port = val; }
    action ai_select_l4_dst_port(bit<12> val) { ig_md.action_select_l4_dst_port = val; }

    table ti_frame_len {
        key = { ig_md.frame_len : range; }
        actions = { NoAction; ai_select_frame_len; }
        size = 1024;
    }
    table ti_ether_type {
        key = { hdr.ethernet.ether_type : range; }
        actions = { NoAction; ai_select_ether_type; }
        size = 1024;
    }
    table ti_ip_proto {
        key = { ig_md.ip_proto : range; }
        actions = { NoAction; ai_select_ip_proto; }
        size = 1024;
    }
    table ti_l4_src_port {
        key = { ig_md.l4_src_port : range; }
        actions = { NoAction; ai_select_l4_src_port; }
        size = 1024;
    }
    table ti_l4_dst_port {
        key = { ig_md.l4_dst_port : range; }
        actions = { NoAction; ai_select_l4_dst_port; }
        size = 1024;
    }

    table ti_forward {
        key = {
            ig_md.action_select_frame_len : range;
            ig_md.action_select_ether_type : range;
            ig_md.action_select_ip_proto : range;
            ig_md.action_select_l4_src_port : range;
            ig_md.action_select_l4_dst_port : range;
        }
        actions = {
            ai_forward;
            ai_drop;
            NoAction;
        }
        size = 1024;
        default_action = ai_drop;
    }

    apply {
        // For iperf3 S -> C
        if (ig_intr_md.ingress_port == 188) {
            ai_forward(156);
            exit;
        }
        ai_set_default_features();
        if (hdr.ipv4.isValid()) {
            ig_md.frame_len = hdr.ipv4.total_len;
            ig_md.ip_proto = hdr.ipv4.protocol;
        }

        if (hdr.tcp.isValid()) {
            ig_md.l4_src_port = hdr.tcp.src_port;
            ig_md.l4_dst_port = hdr.tcp.dst_port;
        } else if (hdr.udp.isValid()) {
            ig_md.l4_src_port = hdr.udp.src_port;
            ig_md.l4_dst_port = hdr.udp.dst_port;
        } else {
            ig_md.l4_src_port = 0;
            ig_md.l4_dst_port = 0;
        }

        ti_frame_len.apply();
        ti_ether_type.apply();
        ti_ip_proto.apply();
        ti_l4_src_port.apply();
        ti_l4_dst_port.apply();
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
