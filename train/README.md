# 数据集处理与模型训练

本目录下包含用于数据预处理、模型训练以及生成上板测试用的 PCAP 文件的脚本。

## 1. 数据预处理 (`trace_processing`)

在 `trace_processing` 目录下执行以下步骤：

### 1.1 特征抽取与标注
提取原始 PCAP 中的 IPv4 数据包特征（5 特征），并根据 MAC 地址进行标注：
```bash
sudo bash set_features_ipv4only.sh replacement_numeric
```

### 1.2 划分数据集
将生成的 CSV 文件汇总，并按 2:8 比例划分为测试集和训练集：
```bash
python split_data.py --input_dir csv_files_ipv4only --output_prefix ipv4only
```

### 1.3 数据裁剪 (适配 Naive Bayes/KMeans)
将 5 特征进一步裁剪为 3 特征 (FrameLen, SrcPort, DstPort) 以适配硬件资源限制：
```bash
python filter_ipv4only.py
```
> 输出文件：`train_data_ipv4only_3.csv` 和 `test_data_ipv4only_3.csv`

## 2. 模型训练 (\`IoT_ML\`)

在 `IoT_ML` 目录下执行以下训练脚本。训练结果会直接输出到 `../../models/` 目录供交换机使用。

### Decision Tree
```bash
python iot_decisiontree.py -i ../trace_processing/train_data_ipv4only.csv \\
                           -o ../../models/decision_tree.txt \\
                           -t ../trace_processing/test_data_ipv4only.csv
```

### K-Means (带可视化)
```bash
python iot_kmeans_map_plot.py -i ../trace_processing/train_data_ipv4only.csv \\
                              -o ../../models/kmeans.txt \\
                              -t ../trace_processing/test_data_ipv4only.csv
```

### Naive Bayes & SVM
执行类似命令运行 `iot_naivebayes.py` 或 `iot_svm.py` 即可。

## 3. 重放测试数据生成

从原始大量 PCAP 中按比例采样（例如 20%），生成用于分类测试的小型 PCAP 文件：

```bash
cd trace_processing
bash group_pcaps_by_class_ipv4only.sh replacement_numeric original_files pcap_by_class_ipv4only src 0.2 12345
```