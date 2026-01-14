import pandas as pd
import numpy as np
import os

# Configuration
script_dir = os.path.dirname(os.path.abspath(__file__))
train_file = os.path.join(script_dir, 'train_data.csv')
test_file = os.path.join(script_dir, 'test_data.csv')
chunk_size = 500000

# Column definitions
feature_cols = [
    'frame_len', 'eth_type', 'ip_proto', 'ip_flags', 
    'ipv6_nxt', 'ipv6_opt', 'tcp_srcport', 'tcp_dstport', 
    'tcp_flags', 'udp_srcport', 'udp_dstport'
]
label_col = 'label'
all_cols = feature_cols + [label_col]

# Display names mapping
feature_display_names = {
    'frame_len': 'Packet Size',
    'eth_type': 'Ether Type',
    'ip_proto': 'IPv4 Protocol',
    'ip_flags': 'IPv4 Flags',
    'ipv6_nxt': 'IPv6 Next',
    'ipv6_opt': 'IPv6 Options',
    'tcp_srcport': 'TCP Src Port',
    'tcp_dstport': 'TCP Dst Port',
    'tcp_flags': 'TCP Flags',
    'udp_srcport': 'UDP Src Port',
    'udp_dstport': 'UDP Dst Port'
}

class_display_names = {
    0: 'Static devices',
    1: 'Sensors',
    2: 'Audio',
    3: 'Video',
    4: 'Other'
}

# Initialize aggregators
unique_values = {col: set() for col in feature_cols}
class_counts = {i: 0 for i in range(5)}

def process_file(filepath):
    if not os.path.exists(filepath):
        print(f"Warning: {filepath} not found.")
        return

    print(f"Processing {filepath}...")
    chunk_count = 0
    # Read without header, provide column names
    # Optimize with dtypes
    dtypes = {col: 'float32' for col in feature_cols} # Use float to handle potential NaNs or floats
    dtypes[label_col] = 'float32'

    for chunk in pd.read_csv(filepath, names=all_cols, chunksize=chunk_size, dtype=dtypes):
        chunk_count += 1
        if chunk_count % 10 == 0:
            print(f"  Processed {chunk_count * chunk_size} rows...")
            
        # Drop NaNs if any
        chunk.dropna(inplace=True)
        
        # Convert label to int for counting
        labels = chunk[label_col].astype(int)
        
        # Update class counts
        counts = labels.value_counts()
        for cls, count in counts.items():
            if cls in class_counts:
                class_counts[cls] += count
        
        # Update unique values for features
        for col in feature_cols:
            # Drop NaNs and convert to int for unique counting (assuming features are essentially discrete/int)
            # If features are continuous floats, unique count might be huge. 
            # The user example shows "Packet Size 1467", "TCP Src Port 65536". These look like discrete values.
            vals = chunk[col].unique()
            unique_values[col].update(vals)
    print(f"Finished {filepath}")

# Process both files
try:
    # process_file(train_file)
    process_file(test_file)
except Exception as e:
    print(f"Error occurred: {e}")
finally:
    # Prepare data for printing
    feature_stats = []
    for col in feature_cols:
        feature_stats.append((feature_display_names[col], len(unique_values[col])))

    class_stats = []
    for cls_id in sorted(class_counts.keys()):
        class_stats.append((class_display_names[cls_id], class_counts[cls_id]))

    # Print formatted table
    print("\n" + "="*60)
    print(f"{'Feature Unique Values':<30} | {'Class Num. Packets':<30}")
    print("-" * 60)

    max_rows = max(len(feature_stats), len(class_stats))

    for i in range(max_rows):
        # Left column (Features)
        if i < len(feature_stats):
            f_name, f_count = feature_stats[i]
            left_str = f"{f_name} {f_count}"
        else:
            left_str = ""
        
        # Right column (Classes)
        if i < len(class_stats):
            c_name, c_count = class_stats[i]
            # Format number with commas
            right_str = f"{c_name} {c_count:,}"
        else:
            right_str = ""
        
        print(f"{left_str:<30} | {right_str:<30}")

    print("="*60 + "\n")
