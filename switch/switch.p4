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

        action upload() {
            ig_tm_md.ucast_egress_port = 64;
        }

        action ai_forward(portid_t egress_port){
            ig_tm_md.ucast_egress_port = egress_port;
        }

        table ti_forward{
            key = {
                ig_intr_md.ingress_port: exact;
            }
            actions = {
                ai_forward;
                ai_drop;
            }
            size = 1024;
            default_action = ai_drop;
        }

        apply {
            ti_forward.apply();
            if (hdr.ipv4.isValid()) {
                if (hdr.tcp.isValid()) {
                    ig_tm_md.ucast_egress_port = 64;
                    hdr.tcp.setInvalid();
                    hdr.ipv4.setInvalid();
                    hdr.upload.setValid();
                    hdr.upload.arp_mac = hdr.ethernet.src_mac;
                    hdr.upload.src_ip = hdr.ipv4.src_ip;
                    hdr.upload.dst_ip = hdr.ipv4.dst_ip;
                    hdr.ethernet.ether_type = 16w0x0866;
                    ig_tm_md.bypass_egress = 1;
                }
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
    apply {
        /* Egress 不做任何处理 */
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
