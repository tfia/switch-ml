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

    // ========== Features ==========
    bit<16> f0_frame_len;
    // bit<8>  f2_ip_proto;
    bit<16> f3_src_port;
    bit<16> f4_dst_port;

    // ========== Costs (smaller is better), 3 classes ==========
    bit<32> score_c0;
    bit<32> score_c1;
    bit<32> score_c2;

    bit<32> min_cost;
    bit<1>  diff_sign;
    bit<32> diff32;

    // ====== Tunables (must match controller) ======
    // controller 用 SCALE=1000, COST_CUTOFF=30 => DEFAULT_COST=30000
    const bit<32> DEFAULT_COST = 30000;

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action ipv4_forward(portid_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action nop() { }

    // 命中后累加 3 个类的 cost（越小越好）
    action add_scores(bit<32> v0, bit<32> v1, bit<32> v2) {
        score_c0 = score_c0 |+| v0;
        score_c1 = score_c1 |+| v1;
        score_c2 = score_c2 |+| v2;
    }

    // ===== One table per feature =====
    // 注意：default_action 不是 0，而是同一个 DEFAULT_COST（对所有类相同）：
    // 缺失表项 -> 加同一个常数 -> argmin 比较中常数抵消，不会造成“偏某类”
    table f0_tbl {
        key = { f0_frame_len : exact; }
        actions = { add_scores; }
        default_action = add_scores(DEFAULT_COST, DEFAULT_COST, DEFAULT_COST);
        size = 131072;     // 你的统计里 ~1890，留余量
    }
    // table f2_tbl {
    //     key = { f2_ip_proto : exact; }
    //     actions = { add_scores; }
    //     default_action = add_scores(DEFAULT_COST, DEFAULT_COST, DEFAULT_COST);
    //     size = 131072;      // 8-bit
    // }
    table f3_tbl {
        key = { f3_src_port : exact; }
        actions = { add_scores; }
        default_action = add_scores(DEFAULT_COST, DEFAULT_COST, DEFAULT_COST);
        size = 131072;    // 16-bit
    }
    table f4_tbl {
        key = { f4_dst_port : exact; }
        actions = { add_scores; }
        default_action = add_scores(DEFAULT_COST, DEFAULT_COST, DEFAULT_COST);
        size = 131072;    // 16-bit
    }
    
    // ===== argmin (strictly smaller only), for 3 classes =====
    action update_min_c1() { min_cost = score_c1; ig_md.classification = 1; }
    action update_min_c2() { min_cost = score_c2; ig_md.classification = 2; }

    // diff32 = score_cX - min_cost
    // 若 score_cX < min_cost => diff32 为负 => 符号位=1 => 更新（严格小于）
    table t_upd_c1 {
        key = { diff_sign : exact; }
        actions = { update_min_c1; nop; }
        const entries = { 1 : update_min_c1(); }
        default_action = nop();
        size = 2;
    }
    table t_upd_c2 {
        key = { diff_sign : exact; }
        actions = { update_min_c2; nop; }
        const entries = { 1 : update_min_c2(); }
        default_action = nop();
        size = 2;
    }

    // ===== Forwarding =====
    table ipv4_exact {
        key = { ig_md.classification : exact; }
        actions = { ipv4_forward; drop; }
        size = 256;
        default_action = drop();
    }

    apply {
        // init per packet
        score_c0 = 0;
        score_c1 = 0;
        score_c2 = 0;

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

        // if (hdr.ipv4.isValid()) {
        //     f2_ip_proto = hdr.ipv4.protocol;
        // } else if (hdr.ipv6.isValid()) {
        //     f2_ip_proto = hdr.ipv6.nxt_hdr;
        // } else {
        //     f2_ip_proto = 0;
        // }

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

        // ===== Apply feature tables (3 features) =====
        f0_tbl.apply();
        // f2_tbl.apply();
        f3_tbl.apply();
        f4_tbl.apply();

        // ===== argmin (3 classes) =====
        min_cost = score_c0;
        ig_md.classification = 0;

        diff32 = (bit<32>)score_c1 - (bit<32>)min_cost;
        diff_sign = diff32[31:31];
        t_upd_c1.apply();

        diff32 = (bit<32>)score_c2 - (bit<32>)min_cost;
        diff_sign = diff32[31:31];
        t_upd_c2.apply();

        if (hdr.ipv4.isValid()) {
            hdr.ipv4.identification[3:0] = min_cost[3:0];
            hdr.ipv4.identification[7:4] = diff32[3:0];
        }

        ipv4_exact.apply();
    }
}

control SwitchEgress(
    inout header_t hdr,
    inout egress_metadata_t eg_md,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;