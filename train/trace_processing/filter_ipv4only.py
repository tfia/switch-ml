#!/usr/bin/env python3
"""Filter ipv4only datasets to three features + label.

- Keep columns 1 (frame_len), 4 (src_port), 5 (dst_port), and the label column.
- Drop rows whose label is 1 or 2; keep labels 0, 3, 4.
"""
import argparse
from pathlib import Path

import pandas as pd


def process_file(src_path: Path, dst_path: Path, chunk_size: int = 1_000_000) -> tuple[int, int]:
    """Stream filter a CSV file and write the result.

    Returns a tuple of (rows_read, rows_written).
    """
    keep_cols = [0, 3, 4, 5]
    labels_keep = {0, 3, 4}

    dst_path.parent.mkdir(parents=True, exist_ok=True)

    rows_in = 0
    rows_out = 0
    first_chunk = True

    for chunk in pd.read_csv(src_path, header=None, chunksize=chunk_size):
        rows_in += len(chunk)
        filtered = chunk.loc[:, keep_cols]
        filtered = filtered[filtered.iloc[:, 3].isin(labels_keep)]
        rows_out += len(filtered)

        if filtered.empty:
            continue

        filtered.to_csv(dst_path, mode="w" if first_chunk else "a", header=False, index=False)
        first_chunk = False

    return rows_in, rows_out


def main() -> None:
    parser = argparse.ArgumentParser(description="Filter ipv4only train/test datasets")
    parser.add_argument("--train-in", default="train_data_ipv4only.csv", help="Path to input train CSV")
    parser.add_argument("--test-in", default="test_data_ipv4only.csv", help="Path to input test CSV")
    parser.add_argument("--train-out", default="train_data_ipv4only_3.csv", help="Path for filtered train CSV")
    parser.add_argument("--test-out", default="test_data_ipv4only_3.csv", help="Path for filtered test CSV")
    parser.add_argument("--chunk-size", type=int, default=1_000_000, help="Rows per chunk for streaming")
    args = parser.parse_args()

    for label, src, dst in (
        ("train", Path(args.train_in), Path(args.train_out)),
        ("test", Path(args.test_in), Path(args.test_out)),
    ):
        if not src.exists():
            print(f"Skipping {label}: {src} not found")
            continue

        rows_in, rows_out = process_file(src, dst, chunk_size=args.chunk_size)
        print(f"{label}: kept {rows_out} of {rows_in} rows -> {dst}")


if __name__ == "__main__":
    main()
