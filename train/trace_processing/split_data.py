import os
import glob
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split


def parse_args():
    parser = argparse.ArgumentParser(description="Merge labeled CSVs and split into train/test for 5-feature schema")
    parser.add_argument("--input_dir", default="csv_files_filtered", help="Directory containing *-labeled.csv files")
    parser.add_argument("--output_prefix", default="new", help="Prefix for output files; leave empty to use legacy names train_data_filtered.csv / test_data_filtered.csv")
    parser.add_argument("--test_size", type=float, default=0.2, help="Test set ratio (default 0.2)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    return parser.parse_args()


def list_labeled_files(csv_dir):
    pattern = os.path.join(csv_dir, "*-labeled.csv")
    return sorted(glob.glob(pattern))

def fast_hex_convert(series):
    """
    快速转换包含十六进制字符串的列。
    先尝试向量化转换为数字，失败的（十六进制）再用apply处理。
    """
    # 1. 尝试直接转换为数字，无法转换的（如0x...）会变成NaN
    numeric = pd.to_numeric(series, errors="coerce")

    # 2. 找到转换失败的行（即十六进制字符串）
    mask = numeric.isna()

    if mask.any():
        # 3. 仅对这些行使用Python循环进行转换
        # 注意：这里处理空字符串或异常值为-1
        numeric[mask] = series[mask].apply(lambda x: int(str(x), 0) if isinstance(x, str) and x.strip() != "" else -1)

    # 4. 填充剩余NaN为-1，并转换为int32以节省内存
    return numeric.fillna(-1).astype(np.int32)


if __name__ == "__main__":
    args = parse_args()

    all_files = list_labeled_files(args.input_dir)
    if not all_files:
        raise SystemExit(f"未找到 labeled CSV: {args.input_dir} 下没有 *-labeled.csv")

    print("正在读取CSV文件...")
    li = []
    for filename in all_files:
        # 读取为字符串类型，避免读取时的类型推断开销
        df = pd.read_csv(filename, header=None, dtype=str, low_memory=False)
        li.append(df)

    print("正在合并数据...")
    df = pd.concat(li, axis=0, ignore_index=True)
    # 释放列表内存
    del li

    print("正在转换数据类型...")
    # 期望列布局（5个特征 + 1个标签）：
    # 0: frame_len, 1: ip_proto_bucket, 2: eth.type, 3: src_port, 4: dst_port, 5: label
    if df.shape[1] < 6:
        raise SystemExit(f"列数不足，期望至少6列(含标签)，实际 {df.shape[1]}")

    # 列索引 2 是 eth.type（十六进制形式如 0x0800），其余为数值或空
    hex_cols = [2]

    for col in df.columns:
        if col in hex_cols:
            df[col] = fast_hex_convert(df[col])
        else:
            # 其他列直接转换为数字，无法解析的填充为 -1
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(-1).astype(np.int32)

    print(f"总数据量: {len(df)} 行")

    # 划分训练集和测试集
    print("正在划分数据集...")
    train_df, test_df = train_test_split(df, test_size=args.test_size, random_state=args.seed)

    # 保存到文件
    if args.output_prefix == "":
        # 保持与旧脚本一致的默认命名
        train_path = "train_data_filtered.csv"
        test_path = "test_data_filtered.csv"
    else:
        train_path = f"train_data_{args.output_prefix}.csv"
        test_path = f"test_data_{args.output_prefix}.csv"
    print("正在保存文件...")
    train_df.to_csv(train_path, index=False, header=False)
    test_df.to_csv(test_path, index=False, header=False)

    print(f"数据集划分完成！\n  训练集: {train_path}\n  测试集: {test_path}")