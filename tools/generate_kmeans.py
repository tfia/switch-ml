#!/usr/bin/env python3
"""Generate a k-means model C header from models/kmeans.txt.

Expected input lines:
  centre point : ( 66,6352,49372,);

The 3 values in the file are assumed to be ordered as:
  (frame_len, l4_src_port, l4_dst_port)

This order matches the P4/control-plane feature order.

Output header defines:
  KM_NUM_FEATURES, KM_NUM_CLASSES, km_centers[][]
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import List


KM_NUM_FEATURES = 3

def parse_centers(text: str) -> List[List[int]]:
    centers: List[List[int]] = []
    # capture "( 1,2,3,)" allowing whitespace
    pat = re.compile(
        r"centre\s+point\s*:\s*\(\s*"  # prefix
        r"(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*\)\s*;\s*",
        re.IGNORECASE,
    )

    for line in text.splitlines():
        m = pat.search(line)
        if not m:
            continue
        vals = [int(m.group(i)) for i in range(1, 4)]
        centers.append(vals)

    return centers


def generate_header(centers: List[List[int]]) -> str:
    out: List[str] = []
    out.append("#pragma once\n")
    out.append("#include <stdint.h>\n\n")
    out.append(f"#define KM_NUM_FEATURES {KM_NUM_FEATURES}\n")
    out.append(f"#define KM_NUM_CLASSES {len(centers)}\n\n")
    out.append("// Feature order in km_centers rows:\n")
    out.append("//   0: frame_len\n")
    out.append("//   1: l4_src_port\n")
    out.append("//   2: l4_dst_port\n\n")

    out.append("static const int km_centers[KM_NUM_CLASSES][KM_NUM_FEATURES] = {\n")
    for c in centers:
        out.append("    {" + ", ".join(str(x) for x in c) + "},\n")
    out.append("};\n")

    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="models/kmeans.txt")
    ap.add_argument("--output", default="ctrl/kmeans_model.h")
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
