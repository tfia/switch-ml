#!/usr/bin/env python3
import pandas as pd
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
train_file = os.path.join(script_dir, 'train_data_ipv4only.csv')
test_file = os.path.join(script_dir, 'test_data_ipv4only.csv')
chunk_size = 500000

feature_cols = ['frame_len','ip_proto','ether_type','src_port','dst_port']
label_col = 'label'
all_cols = feature_cols + [label_col]

feature_display = {
    'frame_len': 'Packet Size',
    'ip_proto': 'IP Protocol (bucketed)',
    'ether_type': 'Ether Type',
    'src_port': 'Src Port (TCP/UDP)',
    'dst_port': 'Dst Port (TCP/UDP)',
}
class_display = {
    0: 'Static devices',
    1: 'Sensors',
    2: 'Audio',
    3: 'Video',
    4: 'Other',
}

unique_values = {c: set() for c in feature_cols}
class_counts = {i: 0 for i in range(5)}

def process(path):
    if not os.path.exists(path):
        print(f"Warning: {path} not found.")
        return
    print(f"Processing {path}...")
    for idx, chunk in enumerate(pd.read_csv(path, names=all_cols, chunksize=chunk_size)):
        if (idx+1) % 10 == 0:
            print(f"  Processed {(idx+1)*chunk_size} rows...")
        chunk.dropna(inplace=True)
        labels = chunk[label_col].astype(int)
        vc = labels.value_counts()
        for cls, cnt in vc.items():
            if cls in class_counts:
                class_counts[cls] += cnt
        for col in feature_cols:
            unique_values[col].update(chunk[col].unique())
    print(f"Finished {path}")

def main():
    process(train_file)
    process(test_file)

    feature_stats = [(feature_display[c], len(unique_values[c])) for c in feature_cols]
    class_stats = [(class_display[k], class_counts[k]) for k in sorted(class_counts.keys())]

    print("\n" + "="*60)
    print(f"{'Feature Unique Values':<30} | {'Class Num. Packets':<30}")
    print("-"*60)
    max_rows = max(len(feature_stats), len(class_stats))
    for i in range(max_rows):
        left = f"{feature_stats[i][0]} {feature_stats[i][1]}" if i < len(feature_stats) else ""
        right = f"{class_stats[i][0]} {class_stats[i][1]:,}" if i < len(class_stats) else ""
        print(f"{left:<30} | {right:<30}")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()
