#!/usr/bin/env python3
"""Generate a k-means model C header from models/kmeans.txt.

Expected input lines:
  centre point : ( 124,6,2048,47915,4046,);

The 5 values in the file are assumed to be ordered as:
  (frame_len, ip_proto, ether_type, l4_src_port, l4_dst_port)

But the P4/control-plane feature order used by this repo is:
  (frame_len, ether_type, ip_proto, l4_src_port, l4_dst_port)

So we swap columns 1 and 2 when generating the C array.

Output header defines:
  KM_NUM_FEATURES, KM_NUM_CLASSES, km_centers[][]
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import List


KM_NUM_FEATURES = 5


def parse_centers(text: str) -> List[List[int]]:
    centers: List[List[int]] = []
    # capture "( 1,2,3,4,5,)" allowing whitespace
    pat = re.compile(
        r"centre\s+point\s*:\s*\(\s*"  # prefix
        r"(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*\)\s*;\s*",
        re.IGNORECASE,
    )

    for line in text.splitlines():
        m = pat.search(line)
        if not m:
            continue
        vals = [int(m.group(i)) for i in range(1, 6)]
        centers.append(vals)

    return centers


def reorder_to_repo_feature_order(center_model_order: List[int]) -> List[int]:
    # model: [frame_len, ip_proto, ether_type, src, dst]
    # repo : [frame_len, ether_type, ip_proto, src, dst]
    if len(center_model_order) != KM_NUM_FEATURES:
        raise ValueError("center must have 5 values")
    frame_len, ip_proto, ether_type, src, dst = center_model_order
    return [frame_len, ether_type, ip_proto, src, dst]


def generate_header(centers_model: List[List[int]]) -> str:
    centers_repo = [reorder_to_repo_feature_order(c) for c in centers_model]

    out: List[str] = []
    out.append("#pragma once\n")
    out.append("#include <stdint.h>\n\n")
    out.append(f"#define KM_NUM_FEATURES {KM_NUM_FEATURES}\n")
    out.append(f"#define KM_NUM_CLASSES {len(centers_repo)}\n\n")
    out.append("// Feature order in km_centers rows:\n")
    out.append("//   0: frame_len\n")
    out.append("//   1: ether_type\n")
    out.append("//   2: ip_proto\n")
    out.append("//   3: l4_src_port\n")
    out.append("//   4: l4_dst_port\n")
    out.append("// Parsed from models/kmeans.txt which is assumed ordered as:\n")
    out.append("//   (frame_len, ip_proto, ether_type,\n")
    out.append("//    l4_src_port, l4_dst_port)\n\n")

    out.append("static const int km_centers[KM_NUM_CLASSES][KM_NUM_FEATURES] = {\n")
    for c in centers_repo:
        out.append("    {" + ", ".join(str(x) for x in c) + "},\n")
    out.append("};\n")

    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="models/kmeans.txt")
    ap.add_argument("--output", default="ctrl/kmeans_model_generated.h")
    args = ap.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    centers = parse_centers(in_path.read_text(encoding="utf-8"))
    if not centers:
        raise SystemExit(f"No centers parsed from {in_path}")

    header = generate_header(centers)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(header, encoding="utf-8")

    print(f"Wrote {out_path} (KM_NUM_CLASSES={len(centers)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
