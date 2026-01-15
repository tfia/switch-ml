#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "header.p4"
#include "parser.p4"

// ------------------------------------------------------------
// SVM (3-class one-vs-one) stage-friendly
//   - 3 features: frame_len, src_port, dst_port
//   - 3 hyperplanes: h0(0v1), h1(0v2), h2(1v2)
//   - 3 feature tables: svm_f0_tbl, svm_f3_tbl, svm_f4_tbl (exact)
//   - 1 vote table: svm_vote_fwd_tbl, key=sign_vec(3) -> (cls, port)
// Anti-opt:
//   - AFTER vote table, write (sign_vec, cls, score low bits) into ipv4.identification
//     (in apply block, not in action) to avoid Tofino action condition restriction.
// ------------------------------------------------------------

control SwitchIngress(
    inout header_t hdr,
    inout metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    // ========== Features (same as naive_bayes) ==========
    bit<16> f0_frame_len;
    bit<16> f3_src_port;
    bit<16> f4_dst_port;

    // ========== 3 hyperplane scores (signed int) ==========
    int<32> score_h0;
    int<32> score_h1;
    int<32> score_h2;

    // pack: [2]=h2 [1]=h1 [0]=h0 (1 means negative)
    bit<3> sign_vec;

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    // 这里只做“写 classification + 转发端口”，不做任何 if/条件
    action svm_set_class_and_forward(bit<8> cls, portid_t port) {
        ig_md.classification = cls;
        ig_tm_md.ucast_egress_port = port;
    }

    action add_only(bit<32> d0, bit<32> d1, bit<32> d2) {
        score_h0 = score_h0 |+| (int<32>)d0;
        score_h1 = score_h1 |+| (int<32>)d1;
        score_h2 = score_h2 |+| (int<32>)d2;
    }

    action init_and_add_hp_scores(bit<32> d0, bit<32> d1, bit<32> d2) {
        score_h0 = 0;
        score_h1 = 0;
        score_h2 = 0;
        add_only(d0, d1, d2);
    }

    action add_hp_scores(bit<32> d0, bit<32> d1, bit<32> d2) {
        add_only(d0, d1, d2);
    }

    // ========== 3 Feature tables (exact) ==========
    table svm_f0_tbl  {
        key = { f0_frame_len : exact; }
        actions = { init_and_add_hp_scores; }
        default_action = init_and_add_hp_scores(0,0,0);
        size = 131072;
    }

    table svm_f3_tbl  {
        key = { f3_src_port : exact; }
        actions = { add_hp_scores; }
        default_action = add_hp_scores(0,0,0);
        size = 131072;
    }

    table svm_f4_tbl  {
        key = { f4_dst_port : exact; }
        actions = { add_hp_scores; }
        default_action = add_hp_scores(0,0,0);
        size = 131072;
    }

    // ========== vote table ==========
    table svm_vote_fwd_tbl {
        key = { sign_vec : exact; }
        actions = { svm_set_class_and_forward; drop; }
        size = 8;
        default_action = drop();
    }

    apply {
        // ===== Feature extraction =====
        if (hdr.ipv4.isValid()) {
            f0_frame_len = hdr.ipv4.total_len;
        } else if (hdr.ipv6.isValid()) {
            f0_frame_len = hdr.ipv6.payload_len + 40;
        } else if (hdr.arp.isValid()) {
            f0_frame_len = 28;
        } else {
            f0_frame_len = 0;
        }

        if (hdr.tcp.isValid()) {
            f3_src_port = hdr.tcp.src_port;
            f4_dst_port = hdr.tcp.dst_port;
        } else if (hdr.udp.isValid()) {
            f3_src_port = hdr.udp.src_port;
            f4_dst_port = hdr.udp.dst_port;
        } else {
            f3_src_port = 0;
            f4_dst_port = 0;
        }

        // ===== apply 3 feature tables =====
        svm_f0_tbl.apply();
        svm_f3_tbl.apply();
        svm_f4_tbl.apply();

        // ===== build sign_vec =====
        sign_vec =
            ((bit<32>)score_h2)[31:31] ++
            ((bit<32>)score_h1)[31:31] ++
            ((bit<32>)score_h0)[31:31];

        // ===== vote + forward (sets ig_md.classification & egress port) =====
        svm_vote_fwd_tbl.apply();

        // ===== anti-opt (in apply, NOT in action) =====
        // 强制使用 ig_md.classification（来自 action 参数 cls）
        // layout 16 bits:
        // [15:13] sign_vec(3)
        // [12:10] cls(3)   (ig_md.classification[2:0])
        // [ 9: 5] score_h0[4:0]
        // [ 4: 0] score_h1[4:0]
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.identification =
                sign_vec ++
                ig_md.classification[2:0] ++
                ((bit<32>)score_h0)[4:0] ++
                ((bit<32>)score_h1)[4:0];
        }
    }
}

control SwitchEgress(
    inout header_t hdr,
    inout egress_metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md)
{
    apply { }
}

Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;