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

        action ai_select_1(bit<14> feature_val_1){
            ig_md.action_select_1 = feature_val_1 ;

        }

        action ai_select_2(bit<14> feature_val_2){
            ig_md.action_select_2 = feature_val_2 ;
        }

        action ai_select_3(bit<14> feature_val_3){
            ig_md.action_select_3 = feature_val_3;
        }

        table ti_feature_1 {
            key = {
                hdr.ipv4.protocol: range;
            }
            actions = {
                NoAction;
                ai_select_1;
            }
            size = 1024;
        }

        table ti_feature_2 {
            key = {
                hdr.tcp.src_port: range;
            }
            actions = {
                NoAction;
                ai_select_2;
            }
            size = 1024;
        }

        table ti_feature_3 {
            key = {
                hdr.tcp.dst_port: range;
            }
            actions = {
                NoAction;
                ai_select_3;
            }
            size = 1024;
        }

        table ti_ipv4_forward {
            key = {
                ig_md.action_select_1: range;
                ig_md.action_select_2: range;
                ig_md.action_select_3: range;
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
            if (hdr.ipv4.isValid()) {
                ti_feature_1.apply();
                if (hdr.ipv4.protocol == IP_PROTOCOLS_TCP) {
                    ti_feature_2.apply();
                    ti_feature_3.apply();
                } else { // not TCP, feature 2 and 3 not valid
                    ig_md.action_select_2 = 1;
                    ig_md.action_select_3 = 1;
                }
                ti_ipv4_forward.apply();
            }
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
