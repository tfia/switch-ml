#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "header.p4"
#define metadata_t kmeans_metadata_t
#include "parser.p4"

control SwitchIngress(
    inout header_t hdr,
    inout kmeans_metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action ai_set_default_features() {
        ig_md.dist_c1 = 0;
        ig_md.dist_c2 = 0;
        ig_md.dist_c3 = 0;
    }

    action ai_drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action ai_forward(portid_t egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    action ai_accumulate_distance(bit<32> d1, bit<32> d2, bit<32> d3) {
        ig_md.dist_c1 = ig_md.dist_c1 + d1;
        ig_md.dist_c2 = ig_md.dist_c2 + d2;
        ig_md.dist_c3 = ig_md.dist_c3 + d3;
    }

    table ti_f_frame_len {
        key = { ig_md.f_frame_len : exact; }
        actions = { ai_accumulate_distance; NoAction; }
        size = 65536;
        default_action = NoAction;
    }
    table ti_f_l4_src_port {
        key = { ig_md.f_l4_src_port : exact; }
        actions = { ai_accumulate_distance; NoAction; }
        size = 65536; 
        default_action = NoAction;
    }
    table ti_f_l4_dst_port {
        key = { ig_md.f_l4_dst_port : exact; }
        actions = { ai_accumulate_distance; NoAction; }
        size = 65536;
        default_action = NoAction;
    }

    action ai_init_min() {
        ig_md.min_dist = ig_md.dist_c1;
        ig_md.classification = 1;
    }

    action ai_update_min_c2() {
        ig_md.min_dist = ig_md.dist_c2;
        ig_md.classification = 2;
    }

    action ai_update_min_c3() {
        ig_md.min_dist = ig_md.dist_c3;
        ig_md.classification = 3;
    }

    // --- Tables to update min_dist and classification ---
    table ti_update_min_c2 {
        key = { ig_md.delta_sign : exact; }
        actions = { ai_update_min_c2; NoAction; }
        size = 2;
        const entries = {
            (1w1) : ai_update_min_c2();
        }
        default_action = NoAction;
    }

    table ti_update_min_c3 {
        key = { ig_md.delta_sign : exact; }
        actions = { ai_update_min_c3; NoAction; }
        size = 2;
        const entries = {
            (1w1) : ai_update_min_c3();
        }
        default_action = NoAction;
    }
    // --- End of tables to update min_dist and classification ---

    table ti_forward {
        key = {
            ig_md.classification : exact; 
        }
        actions = {
            ai_forward;
            ai_drop;
            NoAction;
        }
        size = 256;
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
            ig_md.f_frame_len = hdr.ipv4.total_len;
        }

        if (hdr.tcp.isValid()) {
            ig_md.f_l4_src_port = hdr.tcp.src_port;
            ig_md.f_l4_dst_port = hdr.tcp.dst_port;
        } else if (hdr.udp.isValid()) {
            ig_md.f_l4_src_port = hdr.udp.src_port;
            ig_md.f_l4_dst_port = hdr.udp.dst_port;
        } else {
            ig_md.f_l4_src_port = 0;
            ig_md.f_l4_dst_port = 0;
        }

        ti_f_frame_len.apply();
        ti_f_l4_src_port.apply();
        ti_f_l4_dst_port.apply();

        ai_init_min();

        ig_md.delta = ig_md.dist_c2 - ig_md.min_dist;
        ig_md.delta_sign = ig_md.delta[31:31];
        ti_update_min_c2.apply();

        ig_md.delta = ig_md.dist_c3 - ig_md.min_dist;
        ig_md.delta_sign = ig_md.delta[31:31];
        ti_update_min_c3.apply();
        
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.identification[3:0] = ig_md.min_dist[3:0];
            hdr.ipv4.identification[7:4] = ig_md.delta[3:0];
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
