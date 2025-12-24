#!/usr/bin/env python3
"""Generate control-plane C header from decision tree model text.

Input format (models/decision_tree.txt) contains:
- feature = [np.float64(...), ...];  (possibly empty [])
- rules:  when <pred> and <pred> ... then <class>;

We unify src_port/dst_port across TCP/UDP as L4 ports.
We convert float thresholds like 44.5 to integer boundaries by floor().
Each discretization bin is an inclusive integer range:
  [0..t0], [t0+1..t1], ..., [t_last+1..MAX]
We always append MAX as the last threshold so every value is covered.

Outputs a C header that defines:
- DT_NUM_FEATURES, DT_NUM_RULES
- threshold arrays (already sorted, int)
- per-rule feature-id start/end arrays, and class label

The controller maps class->egress_port separately.
"""

from __future__ import annotations

import argparse
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


_FEATURE_ORDER = [
    "frame_len",
    "ether_type",
    "ip_proto",
    "src_port",
    "dst_port",
]

_MAX_RAW: Dict[str, int] = {
    "frame_len": 0xFFFF,
    "ether_type": 0xFFFF,
    "ip_proto": 0xFF,
    "src_port": 0xFFFF,
    "dst_port": 0xFFFF,
}


@dataclass(frozen=True)
class Bins:
    feature: str
    # list of (raw_low, raw_high, id)
    bins: List[Tuple[int, int, int]]


def _parse_threshold_list(rhs: str) -> List[float]:
    # rhs looks like: [np.float64(94.0), np.float64(335.5), ...]
    # or: []
    nums = re.findall(r"np\.float64\(([-+]?\d*\.?\d+)\)", rhs)
    return [float(x) for x in nums]


def parse_model_text(text: str) -> tuple[Dict[str, List[float]], List[tuple[str, int]]]:
    thresholds: Dict[str, List[float]] = {}
    rules: List[tuple[str, int]] = []

    # Feature threshold lines
    feat_re = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(\[.*\])\s*;\s*$")
    rule_re = re.compile(r"^\s*when\s+(.*?)\s+then\s+(\d+)\s*;\s*$")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        m = feat_re.match(line)
        if m:
            name, rhs = m.group(1), m.group(2)
            thresholds[name] = _parse_threshold_list(rhs)
            continue

        m = rule_re.match(line)
        if m:
            cond, cls = m.group(1), int(m.group(2))
            rules.append((cond, cls))
            continue

    return thresholds, rules


def _floored_sorted_thresholds(vals: List[float], max_raw: int) -> List[int]:
    ints = [int(math.floor(v)) for v in vals]
    ints = sorted(set(ints))
    if not ints:
        ints = []
    # ensure all in range
    ints = [v for v in ints if 0 <= v <= max_raw]
    if not ints or ints[-1] != max_raw:
        ints.append(max_raw)
    return ints


def build_bins(feature: str, float_thresholds: List[float]) -> tuple[List[int], Bins]:
    max_raw = _MAX_RAW[feature]
    thresholds = _floored_sorted_thresholds(float_thresholds, max_raw)

    bins: List[Tuple[int, int, int]] = []
    low = 0
    for idx, high in enumerate(thresholds):
        if low > high:
            continue
        bins.append((low, high, idx))
        if high == max_raw:
            break
        low = high + 1

    # if thresholds ended early (shouldn't), add catch-all
    if not bins or bins[-1][1] != max_raw:
        bins.append((low, max_raw, len(bins)))

    return thresholds, Bins(feature=feature, bins=bins)


_PRED_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*(<=|>)\s*([-+]?\d*\.?\d+)\b")


def parse_rule_bounds(cond: str) -> Dict[str, Tuple[int, int]]:
    # Start with full ranges.
    bounds: Dict[str, Tuple[int, int]] = {
        f: (0, _MAX_RAW[f]) for f in _FEATURE_ORDER
    }

    # Split by 'and' but keep regex-driven parse.
    for name, op, num_s in _PRED_RE.findall(cond):
        if name not in bounds:
            # Ignore unknown feature predicates.
            continue
        val_f = float(num_s)
        hi_floor = int(math.floor(val_f))
        lo_new, hi_new = bounds[name]

        if op == "<=":
            hi_new = min(hi_new, hi_floor)
        else:  # '>'
            lo_new = max(lo_new, hi_floor + 1)

        # clamp
        lo_new = max(0, min(lo_new, _MAX_RAW[name]))
        hi_new = max(0, min(hi_new, _MAX_RAW[name]))
        bounds[name] = (lo_new, hi_new)

    return bounds


def raw_bounds_to_id_range(bins: Bins, raw_lo: int, raw_hi: int) -> Tuple[int, int]:
    if raw_lo > raw_hi:
        # Empty range; caller should avoid generating such rules.
        return (1, 0)

    ids: List[int] = []
    for lo, hi, fid in bins.bins:
        if hi < raw_lo:
            continue
        if lo > raw_hi:
            break
        # overlap
        ids.append(fid)

    if not ids:
        return (1, 0)
    return (min(ids), max(ids))


def c_array_u64(name: str, values: List[int]) -> str:
    inner = ", ".join(str(v) for v in values)
    return f"static const uint64_t {name}[] = {{{inner}}};\n#define {name.upper()}_LEN ((int)(sizeof({name})/sizeof({name}[0])))\n"


def generate_header(thresholds: Dict[str, List[float]], rules: List[tuple[str, int]]) -> str:
    # Build bins for all required features, even if absent in model file.
    threshold_ints: Dict[str, List[int]] = {}
    bins_by_feature: Dict[str, Bins] = {}

    for feat in _FEATURE_ORDER:
        floats = thresholds.get(feat, [])
        ints, bins = build_bins(feat, floats)
        threshold_ints[feat] = ints
        bins_by_feature[feat] = bins

    # Convert each rule.
    starts: List[List[int]] = []
    ends: List[List[int]] = []
    classes: List[int] = []

    for cond, cls in rules:
        raw_bounds = parse_rule_bounds(cond)
        s_row: List[int] = []
        e_row: List[int] = []

        ok = True
        for feat in _FEATURE_ORDER:
            lo, hi = raw_bounds[feat]
            s, e = raw_bounds_to_id_range(bins_by_feature[feat], lo, hi)
            if s > e:
                ok = False
                break
            s_row.append(s)
            e_row.append(e)

        if not ok:
            continue

        starts.append(s_row)
        ends.append(e_row)
        classes.append(cls)

    # Emit C header.
    out: List[str] = []
    out.append("#pragma once\n")
    out.append("#include <stdint.h>\n\n")
    out.append(f"#define DT_NUM_FEATURES {len(_FEATURE_ORDER)}\n")
    out.append(f"#define DT_NUM_RULES {len(starts)}\n\n")

    out.append("// Feature thresholds (inclusive upper bounds). Always includes MAX as last entry.\n")
    out.append(c_array_u64("dt_thres_frame_len", threshold_ints["frame_len"]))
    out.append(c_array_u64("dt_thres_ether_type", threshold_ints["ether_type"]))
    out.append(c_array_u64("dt_thres_ip_proto", threshold_ints["ip_proto"]))
    out.append(c_array_u64("dt_thres_l4_src_port", threshold_ints["src_port"]))
    out.append(c_array_u64("dt_thres_l4_dst_port", threshold_ints["dst_port"]))
    out.append("\n")

    def emit_2d_int(name: str, rows: List[List[int]]) -> None:
        out.append(f"static const int {name}[DT_NUM_RULES][DT_NUM_FEATURES] = {{\n")
        for r in rows:
            inner = ", ".join(str(x) for x in r)
            out.append(f"    {{{inner}}},\n")
        out.append("};\n\n")

    emit_2d_int("dt_rule_f_id_start", starts)
    emit_2d_int("dt_rule_f_id_end", ends)

    out.append("static const uint8_t dt_rule_class[DT_NUM_RULES] = {\n    ")
    out.append(", ".join(str(c) for c in classes))
    out.append("\n};\n")

    out.append("\n// Feature order used by dt_rule_f_id_* rows:\n")
    out.append("// 0: frame_len, 1: ether_type, 2: ip_proto, 3: l4_src_port, 4: l4_dst_port\n")

    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="models/decision_tree.txt")
    ap.add_argument("--output", default="ctrl/decision_tree_rules.h")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    text = in_path.read_text(encoding="utf-8")
    thresholds, rules = parse_model_text(text)

    header = generate_header(thresholds, rules)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(header, encoding="utf-8")

    m = re.search(r"^#define\s+DT_NUM_RULES\s+(\d+)\s*$", header, re.MULTILINE)
    num_rules = int(m.group(1)) if m else -1
    print(f"Wrote {out_path} (DT_NUM_RULES={num_rules})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
