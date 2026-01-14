#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#################################################################################
#
# Copyright (c) 2019 Zhaoqi Xiong, Noa Zilberman
# All rights reserved.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#
#################################################################################

import argparse
import numpy as np
import pandas as pd

from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from scipy.optimize import linear_sum_assignment

import matplotlib.pyplot as plt

# ----------------------------- utils: 3D dot plotting -----------------------------

from sklearn.decomposition import PCA  # 不用也行，这里只是示例保留
from mpl_toolkits.mplot3d import Axes3D  # noqa: F401

def reservoir_sample_rows(csv_path, chunksize, sample_n, feature_cols=(0,1,2), label_col=3, seed=42):
    """流式水库抽样：从超大 CSV 中均匀随机抽 sample_n 行，返回 X(float64), y(int/float)."""
    rng = np.random.default_rng(seed)
    X_buf, y_buf = [], []
    seen = 0
    for chunk in read_chunks(csv_path, chunksize):
        X = chunk.iloc[:, list(feature_cols)].values.astype(np.float64)
        y = chunk.iloc[:, label_col].values
        for i in range(X.shape[0]):
            seen += 1
            if len(X_buf) < sample_n:
                X_buf.append(X[i])
                y_buf.append(y[i])
            else:
                j = rng.integers(0, seen)
                if j < sample_n:
                    X_buf[j] = X[i]
                    y_buf[j] = y[i]
    return np.array(X_buf, dtype=np.float64), np.array(y_buf)

def _label_to_int_colors(vals):
    """把离散标签映射为 0..K-1，便于 matplotlib 用离散 colormap。"""
    uniq = np.unique(vals)
    m = {v:i for i, v in enumerate(uniq)}
    return np.array([m[v] for v in vals], dtype=int), uniq

def plot_3d_scatter_true_label(X3, y_true, centres3, out_path, title):
    """3D散点：真实label着色 + 中心点叠加。"""
    c_int, uniq = _label_to_int_colors(y_true)

    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection="3d")

    ax.scatter(X3[:,0], X3[:,1], X3[:,2], c=c_int, s=4, alpha=0.35)
    ax.scatter(centres3[:,0], centres3[:,1], centres3[:,2], marker="x", s=160, linewidths=2, c="black")

    for i in range(centres3.shape[0]):
        ax.text(centres3[i,0], centres3[i,1], centres3[i,2], f"C{i}", color="black")

    ax.set_title(title)
    ax.set_xlabel("f0 (scaled)")
    ax.set_ylabel("f1 (scaled)")
    ax.set_zlabel("f2 (scaled)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=220)
    plt.close(fig)
    print(f"Saved: {out_path}")

def _sphere_mesh(center, radius, n=30):
    """生成球面网格点，用于 plot_surface。"""
    u = np.linspace(0, 2*np.pi, n)
    v = np.linspace(0, np.pi, n)
    x = center[0] + radius * np.outer(np.cos(u), np.sin(v))
    y = center[1] + radius * np.outer(np.sin(u), np.sin(v))
    z = center[2] + radius * np.outer(np.ones_like(u), np.cos(v))
    return x, y, z

def plot_3d_spheres_mapped_with_true_scatter(
    X3, y_true, pred_cluster,
    centres3, train_mapping,
    out_path,
    title,
    inner_q=0.50,
    outer_q=0.90
):
    """
    画“已map完”的球体范围：
    - 先按 pred_cluster 把点分到各中心，算到中心距离分位数作为半径（inner_q/outer_q）
    - 球体颜色按 apply_mapping(pred_cluster, train_mapping) 后的类别决定
    - 再叠加真实label散点（真实label着色）
    """
    # 真实label颜色
    c_true, uniq_true = _label_to_int_colors(y_true)

    # 映射后的类别（用于给每个中心/球体着色）
    mapped_label_per_cluster = apply_mapping(np.arange(centres3.shape[0]), train_mapping)
    # 给 mapped label 转成离散颜色索引
    c_mapped, uniq_mapped = _label_to_int_colors(mapped_label_per_cluster)

    fig = plt.figure(figsize=(12, 9))
    ax = fig.add_subplot(111, projection="3d")

    # 叠加真实label散点
    ax.scatter(X3[:,0], X3[:,1], X3[:,2], c=c_true, s=4, alpha=0.30)

    # 对每个 cluster 计算半径并画两层球
    for k in range(centres3.shape[0]):
        idx = np.where(pred_cluster == k)[0]
        if idx.size < 20:
            continue

        # 距离（在 scaled 空间）
        d = np.linalg.norm(X3[idx] - centres3[k], axis=1)
        r_in = np.quantile(d, inner_q)
        r_out = np.quantile(d, outer_q)

        # 颜色：用 mapped label 的离散颜色索引来选 colormap
        # 这里用 tab10；你也可以换其他离散色图
        color = plt.cm.tab10(c_mapped[k] % 10)

        # 外球（更淡）
        xs, ys, zs = _sphere_mesh(centres3[k], r_out, n=28)
        ax.plot_surface(xs, ys, zs, color=color, alpha=0.10, linewidth=0, antialiased=True)

        # 内球（更深）
        xs, ys, zs = _sphere_mesh(centres3[k], r_in, n=28)
        ax.plot_surface(xs, ys, zs, color=color, alpha=0.20, linewidth=0, antialiased=True)

        # 中心点
        ax.scatter(centres3[k,0], centres3[k,1], centres3[k,2], marker="x", s=180, linewidths=2, c="black")
        ax.text(centres3[k,0], centres3[k,1], centres3[k,2],
                f"C{k}->L{mapped_label_per_cluster[k]}\n(r{int(inner_q*100)}={r_in:.2f}, r{int(outer_q*100)}={r_out:.2f})",
                color="black")

    ax.set_title(title)
    ax.set_xlabel("f0 (scaled)")
    ax.set_ylabel("f1 (scaled)")
    ax.set_zlabel("f2 (scaled)")
    plt.tight_layout()
    plt.savefig(out_path, dpi=220)
    plt.close(fig)
    print(f"Saved: {out_path}")

# ----------------------------- utils: 2D dot plotting -----------------------------

from sklearn.decomposition import PCA

def reservoir_sample_rows(csv_path, chunksize, sample_n, feature_cols=(0,1,2), label_col=3, seed=42):
    """
    流式水库抽样：从超大 CSV 中均匀随机抽 sample_n 行，返回 X(float64), y(float64)
    """
    rng = np.random.default_rng(seed)
    X_buf = []
    y_buf = []
    seen = 0

    for chunk in read_chunks(csv_path, chunksize):
        X = chunk.iloc[:, list(feature_cols)].values.astype(np.float64)
        y = chunk.iloc[:, label_col].values

        for i in range(X.shape[0]):
            seen += 1
            if len(X_buf) < sample_n:
                X_buf.append(X[i])
                y_buf.append(y[i])
            else:
                j = rng.integers(0, seen)  # [0, seen-1]
                if j < sample_n:
                    X_buf[j] = X[i]
                    y_buf[j] = y[i]

    return np.array(X_buf, dtype=np.float64), np.array(y_buf)

def make_pca2d_plots(
    train_csv, test_csv, chunksize,
    centres_original_rounded,
    pred_train_sat, pred_test_sat,
    y_train_true, y_test_true,
    train_mapping_sat,
    sample_n_train=50000, sample_n_test=50000,
    seed=42
):
    """
    - 从 train/test 各采样 sample_n 点
    - PCA(2D) 在 “train+test 采样点” 上 fit_transform（保证同一坐标系）
    - 画两类图：
        1) 按真实标签着色
        2) 按 截断预测簇 / 映射后类别 着色，并叠加中心点
    注意：pred_train_sat/pred_test_sat 需要是“全量”的预测数组，
          这里会对采样点再取对应位置的预测值（所以我们用水库抽样时也要记 index）。
    """
    # 由于水库抽样没保留原始行号，简单起见：这里重新对“采样出来的点”跑一次预测函数
    # （K=3 很快），保证颜色和点对应。
    Xtr_s, ytr_s = reservoir_sample_rows(train_csv, chunksize, sample_n_train, seed=seed)
    Xte_s, yte_s = reservoir_sample_rows(test_csv,  chunksize, sample_n_test,  seed=seed+1)

    # 截断预测（在采样点上重算）
    pred_tr = predict_with_centres_original_scale_int32_sat(Xtr_s, centres_original_rounded)
    pred_te = predict_with_centres_original_scale_int32_sat(Xte_s, centres_original_rounded)

    # 映射后的类别（固定训练 mapping）
    pred_tr_m = apply_mapping(pred_tr, train_mapping_sat)
    pred_te_m = apply_mapping(pred_te, train_mapping_sat)

    # PCA 2D：同一坐标系
    X_all = np.vstack([Xtr_s, Xte_s])
    pca = PCA(n_components=2, random_state=0)
    Z_all = pca.fit_transform(X_all)
    Ztr = Z_all[:len(Xtr_s)]
    Zte = Z_all[len(Xtr_s):]

    # 中心点投影到 PCA 平面
    centres = np.asarray(centres_original_rounded, dtype=np.float64)
    Zc = pca.transform(centres)

    def scatter(ax, Z, c, title):
        # 不指定颜色，让 matplotlib 自动分配；点太多时用小点+alpha
        ax.scatter(Z[:,0], Z[:,1], c=c, s=3, alpha=0.35)
        ax.set_title(title)
        ax.set_xlabel("PC1")
        ax.set_ylabel("PC2")

    # 1) 真实标签着色
    fig1, axes1 = plt.subplots(1, 2, figsize=(12, 5))
    scatter(axes1[0], Ztr, ytr_s, "TRAIN sample: colored by TRUE label")
    scatter(axes1[1], Zte, yte_s, "TEST sample: colored by TRUE label")
    fig1.tight_layout()
    fig1.savefig("pca2d_true_label.png", dpi=200)
    print("Saved: pca2d_true_label.png")

    # 2) 截断预测（映射后类别）着色 + 叠加中心点
    fig2, axes2 = plt.subplots(1, 2, figsize=(12, 5))
    scatter(axes2[0], Ztr, pred_tr_m, "TRAIN sample: colored by PRED (mapped, INT32-sat)")
    scatter(axes2[1], Zte, pred_te_m, "TEST sample: colored by PRED (mapped, INT32-sat)")

    # 叠加中心（黑色叉号）
    for ax in axes2:
        ax.scatter(Zc[:,0], Zc[:,1], marker="x", s=120, linewidths=2, c="black")
        for i in range(Zc.shape[0]):
            ax.text(Zc[i,0], Zc[i,1], f"C{i}", fontsize=10, color="black")

    fig2.tight_layout()
    fig2.savefig("pca2d_pred_mapped_sat.png", dpi=200)
    print("Saved: pca2d_pred_mapped_sat.png")


# ----------------------------- utils: mapping -----------------------------

def compute_mapping_hungarian(y_true, y_pred):
    """
    Compute a single mapping dict: pred_cluster -> true_label
    that maximizes #correct matches on the given (y_true, y_pred).
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    true_labels = np.unique(y_true)
    pred_labels = np.unique(y_pred)

    cm = np.zeros((len(true_labels), len(pred_labels)), dtype=int)
    for i, t_lab in enumerate(true_labels):
        for j, p_lab in enumerate(pred_labels):
            cm[i, j] = np.sum((y_true == t_lab) & (y_pred == p_lab))

    # Hungarian: maximize cm => minimize cost = max - cm
    cost = cm.max() - cm
    row_ind, col_ind = linear_sum_assignment(cost)

    mapping = {pred_labels[col]: true_labels[row] for row, col in zip(row_ind, col_ind)}
    return mapping

def apply_mapping(y_pred, mapping):
    y_pred = np.asarray(y_pred)
    return np.array([mapping.get(p, p) for p in y_pred])

def print_metrics(title, y_true, y_pred_mapped):
    print(title)
    print(accuracy_score(y_true, y_pred_mapped))
    print("\tPrecision: %1.3f" % precision_score(y_true, y_pred_mapped, average="weighted"))
    print("\tRecall: %1.3f" % recall_score(y_true, y_pred_mapped, average="weighted"))
    print("\tF1: %1.3f\n" % f1_score(y_true, y_pred_mapped, average="weighted"))
    print("\tConfusion matrix:\n")
    print(confusion_matrix(y_true, y_pred_mapped))


# ----------------------------- distance/predict -----------------------------

def predict_with_centres_original_scale(X_original, centres_original_rounded):
    """Predict cluster by nearest (rounded) centre in ORIGINAL feature scale."""
    X = np.asarray(X_original, dtype=np.float64)
    centres = np.asarray(centres_original_rounded, dtype=np.float64)
    distances = ((X[:, None, :] - centres[None, :, :]) ** 2).sum(axis=2)
    return distances.argmin(axis=1)

INT32_MAX = np.int64(2147483647)

def predict_with_centres_original_scale_int32_sat(X_original, centres_original_rounded):
    """
    Simulate hardware (int32 limitation + LUT-squared saturation):
    - Round features to integer
    - Each squared component saturates to INT32_MAX if exceeds
    - Sum of components also saturates to INT32_MAX (saturating add)
    """
    X_int = np.rint(np.asarray(X_original, dtype=np.float64)).astype(np.int64)  # (N,3)
    C_int = np.rint(np.asarray(centres_original_rounded, dtype=np.float64)).astype(np.int64)  # (K,3)

    n = X_int.shape[0]
    k = C_int.shape[0]
    dists = np.empty((n, k), dtype=np.int64)

    for ci in range(k):
        diff = X_int - C_int[ci]     # (N,3)
        sq = diff * diff             # int64
        sq = np.minimum(sq, INT32_MAX)

        dist = sq[:, 0]
        dist = np.minimum(dist + sq[:, 1], INT32_MAX)
        dist = np.minimum(dist + sq[:, 2], INT32_MAX)

        dists[:, ci] = dist

    return dists.argmin(axis=1)


# ----------------------------- plotting -----------------------------

def cluster_label_crosstab(y_true, y_pred, mapping=None, row_order=None, col_order=None):
    """
    counts[row, col] where:
      - row: cluster id (before mapping) OR mapped label (after mapping)
      - col: true label
    """
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)

    if mapping is None:
        row_vals = y_pred
        row_names = np.unique(row_vals) if row_order is None else row_order
        row_tick = [f"cluster {v}" for v in row_names]
    else:
        row_vals = apply_mapping(y_pred, mapping)
        row_names = np.unique(row_vals) if row_order is None else row_order
        row_tick = [f"label {v}" for v in row_names]

    col_names = np.unique(y_true) if col_order is None else col_order
    col_tick = [f"true {v}" for v in col_names]

    r_index = {v: i for i, v in enumerate(row_names)}
    c_index = {v: j for j, v in enumerate(col_names)}

    counts = np.zeros((len(row_names), len(col_names)), dtype=int)
    for rv, tv in zip(row_vals, y_true):
        if rv in r_index and tv in c_index:
            counts[r_index[rv], c_index[tv]] += 1

    return counts, row_tick, col_tick

def plot_train_test_distributions_fixed_mapping(
    y_train_true, y_train_pred,
    y_test_true, y_test_pred,
    train_mapping,
    fig_path
):
    """
    2x2 stacked bars:
      TRAIN before/after, TEST before/after
    mapping is FIXED from training set.
    """
    # consistent orders
    all_true_labels = np.unique(np.concatenate([np.unique(y_train_true), np.unique(y_test_true)]))
    all_pred_clusters = np.unique(np.concatenate([np.unique(y_train_pred), np.unique(y_test_pred)]))

    # mapped labels order = true label order (to keep stable)
    mapped_label_order = all_true_labels

    fig, axes = plt.subplots(2, 2, figsize=(12, 9))

    def stacked_bar(ax, counts, x_ticks, legend_ticks, title):
        bottom = np.zeros(counts.shape[0], dtype=int)
        x = np.arange(counts.shape[0])
        for j in range(counts.shape[1]):
            ax.bar(x, counts[:, j], bottom=bottom, label=legend_ticks[j])
            bottom += counts[:, j]
        ax.set_xticks(x)
        ax.set_xticklabels(x_ticks, rotation=30, ha="right")
        ax.set_title(title)
        ax.legend()

    # TRAIN before
    c1, x1, leg = cluster_label_crosstab(
        y_train_true, y_train_pred,
        mapping=None,
        row_order=all_pred_clusters,
        col_order=all_true_labels
    )
    stacked_bar(axes[0, 0], c1, x1, leg, "TRAIN: true-label distribution per cluster (before mapping)")

    # TRAIN after (fixed mapping)
    c2, x2, leg = cluster_label_crosstab(
        y_train_true, y_train_pred,
        mapping=train_mapping,
        row_order=mapped_label_order,
        col_order=all_true_labels
    )
    train_acc_fixed = accuracy_score(y_train_true, apply_mapping(y_train_pred, train_mapping))
    stacked_bar(axes[0, 1], c2, x2, leg, f"TRAIN: after FIXED mapping (acc={train_acc_fixed:.4f})")

    # TEST before
    c3, x3, leg = cluster_label_crosstab(
        y_test_true, y_test_pred,
        mapping=None,
        row_order=all_pred_clusters,
        col_order=all_true_labels
    )
    stacked_bar(axes[1, 0], c3, x3, leg, "TEST: true-label distribution per cluster (before mapping)")

    # TEST after (same fixed mapping)
    c4, x4, leg = cluster_label_crosstab(
        y_test_true, y_test_pred,
        mapping=train_mapping,
        row_order=mapped_label_order,
        col_order=all_true_labels
    )
    test_acc_fixed = accuracy_score(y_test_true, apply_mapping(y_test_pred, train_mapping))
    stacked_bar(axes[1, 1], c4, x4, leg, f"TEST: after FIXED mapping (acc={test_acc_fixed:.4f})")

    fig.tight_layout()
    fig.savefig(fig_path, dpi=200)
    print(f"\nSaved distribution plot to: {fig_path}")


# ----------------------------- main pipeline -----------------------------

def read_chunks(path, chunksize):
    for chunk in pd.read_csv(path, chunksize=chunksize):
        chunk = chunk.apply(pd.to_numeric, downcast="float", errors="coerce")
        chunk.dropna(inplace=True)
        if len(chunk) == 0:
            continue
        yield chunk

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", required=True, help="path to training dataset csv")
    parser.add_argument("-o", required=True, help="path to output model file")
    parser.add_argument("-t", required=True, help="path to test dataset csv")
    args = parser.parse_args()

    input_file = args.i
    outputfile = args.o
    testfile = args.t

    chunk_size = 200000
    kmeans = MiniBatchKMeans(n_clusters=3, random_state=9, batch_size=chunk_size, n_init=5)
    scaler = StandardScaler()

    print(f"Training incrementally on {input_file}...")

    # Pass 1: scaler
    chunk_idx = 0
    for chunk in read_chunks(input_file, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        scaler.partial_fit(X_chunk)
        chunk_idx += 1
        if chunk_idx % 20 == 0:
            print(f"Scaler pass chunk {chunk_idx}...")

    # Pass 2: kmeans on scaled features
    chunk_idx = 0
    for chunk in read_chunks(input_file, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        X_chunk = scaler.transform(X_chunk)
        kmeans.partial_fit(X_chunk)
        chunk_idx += 1
        if chunk_idx % 10 == 0:
            print(f"Processed training chunk {chunk_idx}...")

    print("Training complete.")

    # Output centres (inverse transform + round)
    centres_scaled = kmeans.cluster_centers_
    centres_original = scaler.inverse_transform(centres_scaled)
    centres_original_rounded = np.rint(centres_original)

    # ----------------- EVAL 1: scaled + kmeans.predict -----------------
    print(f"\nCalculating metrics on TRAIN (scaled + kmeans.predict) ...")
    train_predictions = []
    Y_train_true = []
    for chunk in read_chunks(input_file, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        Y_chunk = chunk.iloc[:, 3].values
        pred_chunk = kmeans.predict(scaler.transform(X_chunk))
        train_predictions.extend(pred_chunk)
        Y_train_true.extend(Y_chunk)

    Predict_Y = np.array(train_predictions)
    Y = np.array(Y_train_true)

    train_mapping_scaled = compute_mapping_hungarian(Y, Predict_Y)
    Predict_Y_aligned = apply_mapping(Predict_Y, train_mapping_scaled)
    print("TRAIN mapping (scaled/kmeans.predict):", train_mapping_scaled)
    print_metrics("Training dataset results (scaled + FIXED mapping):", Y, Predict_Y_aligned)

    print(f"\nCalculating metrics on TEST (scaled + kmeans.predict, FIXED train mapping) ...")
    test_predictions = []
    Y_test_true = []
    for chunk in read_chunks(testfile, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        Y_chunk = chunk.iloc[:, 3].values
        pred_chunk = kmeans.predict(scaler.transform(X_chunk))
        test_predictions.extend(pred_chunk)
        Y_test_true.extend(Y_chunk)

    Predict_Yt = np.array(test_predictions)
    Yt = np.array(Y_test_true)

    Predict_Yt_aligned = apply_mapping(Predict_Yt, train_mapping_scaled)
    print_metrics("Test dataset results (scaled + FIXED train mapping):", Yt, Predict_Yt_aligned)

    # ----------------- EVAL 2: output centres, original scale, no sat -----------------
    print("\nEvaluating on TRAIN with output model centres (original scale, no sat) ...")
    train_predictions_out = []
    Y_train_true_out = []
    for chunk in read_chunks(input_file, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        Y_chunk = chunk.iloc[:, 3].values
        pred_chunk = predict_with_centres_original_scale(X_chunk, centres_original_rounded)
        train_predictions_out.extend(pred_chunk)
        Y_train_true_out.extend(Y_chunk)

    Predict_Y_out = np.array(train_predictions_out)
    Y_out = np.array(Y_train_true_out)

    train_mapping_out = compute_mapping_hungarian(Y_out, Predict_Y_out)
    Predict_Y_out_aligned = apply_mapping(Predict_Y_out, train_mapping_out)
    print("TRAIN mapping (output centres, no sat):", train_mapping_out)
    print_metrics("Training dataset results (output centres, no sat, FIXED mapping):", Y_out, Predict_Y_out_aligned)

    print("\nEvaluating on TEST with output model centres (original scale, no sat, FIXED train mapping) ...")
    test_predictions_out = []
    Y_test_true_out = []
    for chunk in read_chunks(testfile, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        Y_chunk = chunk.iloc[:, 3].values
        pred_chunk = predict_with_centres_original_scale(X_chunk, centres_original_rounded)
        test_predictions_out.extend(pred_chunk)
        Y_test_true_out.extend(Y_chunk)

    Predict_Yt_out = np.array(test_predictions_out)
    Yt_out = np.array(Y_test_true_out)

    Predict_Yt_out_aligned = apply_mapping(Predict_Yt_out, train_mapping_out)
    print_metrics("Test dataset results (output centres, no sat, FIXED train mapping):", Yt_out, Predict_Yt_out_aligned)

    # ----------------- EVAL 3: output centres + INT32 sat (HW sim) -----------------
    print("\nEvaluating on TRAIN with output centres + INT32-saturated distance (HW sim) ...")
    train_predictions_sat = []
    Y_train_true_sat = []
    for chunk in read_chunks(input_file, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        Y_chunk = chunk.iloc[:, 3].values
        pred_chunk = predict_with_centres_original_scale_int32_sat(X_chunk, centres_original_rounded)
        train_predictions_sat.extend(pred_chunk)
        Y_train_true_sat.extend(Y_chunk)

    Predict_Y_sat = np.array(train_predictions_sat)
    Y_sat = np.array(Y_train_true_sat)

    train_mapping_sat = compute_mapping_hungarian(Y_sat, Predict_Y_sat)
    Predict_Y_sat_aligned = apply_mapping(Predict_Y_sat, train_mapping_sat)
    print("TRAIN mapping (output centres, INT32-sat):", train_mapping_sat)
    print_metrics("Training dataset results (output centres, INT32-sat, FIXED mapping):", Y_sat, Predict_Y_sat_aligned)

    print("\nEvaluating on TEST with output centres + INT32-saturated distance (HW sim, FIXED train mapping) ...")
    test_predictions_sat = []
    Y_test_true_sat = []
    for chunk in read_chunks(testfile, chunk_size):
        X_chunk = chunk.iloc[:, 0:3].values
        Y_chunk = chunk.iloc[:, 3].values
        pred_chunk = predict_with_centres_original_scale_int32_sat(X_chunk, centres_original_rounded)
        test_predictions_sat.extend(pred_chunk)
        Y_test_true_sat.extend(Y_chunk)

    Predict_Yt_sat = np.array(test_predictions_sat)
    Yt_sat = np.array(Y_test_true_sat)

    Predict_Yt_sat_aligned = apply_mapping(Predict_Yt_sat, train_mapping_sat)
    print_metrics("Test dataset results (output centres, INT32-sat, FIXED train mapping):", Yt_sat, Predict_Yt_sat_aligned)

    # ----------------- Write model -----------------
    print(f"\nWriting model to {outputfile} ...")
    with open(outputfile, "w+") as model:
        for i in range(len(centres_original_rounded)):
            model.write("centre point : ( ")
            for j in range(3):
                model.write(str(int(centres_original_rounded[i][j])) + ",")
            model.write(");\n")
    print("Done writing model.")

    # ----------------- Plot (choose which prediction to visualize) -----------------
    # Usually you want the HW-sim one, because it's closest to switch behavior:
    fig_path = "cluster_label_distribution_fixed_mapping.png"
    plot_train_test_distributions_fixed_mapping(
        y_train_true=Y_sat, y_train_pred=Predict_Y_sat,
        y_test_true=Yt_sat, y_test_pred=Predict_Yt_sat,
        train_mapping=train_mapping_sat,
        fig_path=fig_path
    )

    make_pca2d_plots(
    train_csv=input_file,
    test_csv=testfile,
    chunksize=chunk_size,
    centres_original_rounded=centres_original_rounded,
    pred_train_sat=Predict_Y_sat,   # 这两个参数目前没用到（保留接口）
    pred_test_sat=Predict_Yt_sat,
    y_train_true=Y_sat,
    y_test_true=Yt_sat,
    train_mapping_sat=train_mapping_sat,
    sample_n_train=50000,
    sample_n_test=50000,
    seed=42
    )

    # ===== 3D visualization (sample) =====
    sample_n_train = 40000
    sample_n_test  = 40000

    # 采样（原尺度）
    Xtr_s, ytr_s = reservoir_sample_rows(input_file, chunk_size, sample_n_train, seed=123)
    Xte_s, yte_s = reservoir_sample_rows(testfile,  chunk_size, sample_n_test,  seed=456)

    # 转到 scaled 3D 空间用于画图
    Xtr_3 = scaler.transform(Xtr_s)
    Xte_3 = scaler.transform(Xte_s)
    centres_3 = centres_scaled  # kmeans.cluster_centers_ 就在 scaled 空间

    # 用“INT32-sat + 输出中心（原尺度）”给采样点分簇（贴近硬件）
    pred_tr_sat = predict_with_centres_original_scale_int32_sat(Xtr_s, centres_original_rounded)
    pred_te_sat = predict_with_centres_original_scale_int32_sat(Xte_s, centres_original_rounded)

    # 1) 3D散点：按真实label着色（train/test 各一张更清晰；这里给你合并画一张 train）
    plot_3d_scatter_true_label(
        X3=Xtr_3,
        y_true=ytr_s,
        centres3=centres_3,
        out_path="scatter3d_true_label_train.png",
        title="3D scatter (TRAIN sample) colored by TRUE label (scaled space)"
    )

    plot_3d_scatter_true_label(
        X3=Xte_3,
        y_true=yte_s,
        centres3=centres_3,
        out_path="scatter3d_true_label_test.png",
        title="3D scatter (TEST sample) colored by TRUE label (scaled space)"
    )

    # 2) 3D球体：已map完（用训练mapping固定），球体范围=簇内距离分位数；叠加真实label散点
    plot_3d_spheres_mapped_with_true_scatter(
        X3=Xtr_3,
        y_true=ytr_s,
        pred_cluster=pred_tr_sat,
        centres3=centres_3,
        train_mapping=train_mapping_sat,
        out_path="spheres3d_mapped_range_true_scatter_train.png",
        title="TRAIN: mapped spheres (r50/r90) + TRUE-label scatter (scaled space, INT32-sat assignment)"
    )

    plot_3d_spheres_mapped_with_true_scatter(
        X3=Xte_3,
        y_true=yte_s,
        pred_cluster=pred_te_sat,
        centres3=centres_3,
        train_mapping=train_mapping_sat,
        out_path="spheres3d_mapped_range_true_scatter_test.png",
        title="TEST: mapped spheres (r50/r90) + TRUE-label scatter (scaled space, INT32-sat assignment)"
    )


if __name__ == "__main__":
    main()