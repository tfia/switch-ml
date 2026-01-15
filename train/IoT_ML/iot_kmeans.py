#!/usr/bin/env python
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

import numpy as np
import pandas as pd
import argparse
from sklearn.cluster import MiniBatchKMeans
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from scipy.optimize import linear_sum_assignment

parser = argparse.ArgumentParser()

# Add argument
parser.add_argument('-i', required=True, help='path to dataset')
parser.add_argument('-o', required=True, help='path to outputfile')
parser.add_argument('-t', required=True, help='path to testfile')

args = parser.parse_args()

input_file = args.i
outputfile = args.o
testfile = args.t

# Initialize MiniBatchKMeans for incremental learning on three features
# Using random_state=9 to match original script's seed
chunk_size = 200000
kmeans = MiniBatchKMeans(n_clusters=3, random_state=9, batch_size=chunk_size, n_init=5)
scaler = StandardScaler()

print(f"Training incrementally on {input_file}...")
chunk_idx = 0

# First pass: partial fit scaler on three kept features, then kmeans
for chunk in pd.read_csv(input_file, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)
    X_chunk = chunk.iloc[:, 0:3].values
    scaler.partial_fit(X_chunk)
    chunk_idx += 1
    if chunk_idx % 20 == 0:
        print(f"Scaler pass chunk {chunk_idx}...")

chunk_idx = 0
for chunk in pd.read_csv(input_file, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)
    X_chunk = chunk.iloc[:, 0:3].values
    X_chunk = scaler.transform(X_chunk)
    kmeans.partial_fit(X_chunk)
    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed training chunk {chunk_idx}...")

print("Training complete.")


def predict_with_centres_original_scale(X_original, centres_original_rounded):
    """Predict cluster by nearest (rounded) centre in ORIGINAL feature scale."""
    X = np.asarray(X_original, dtype=np.float64)
    centres = np.asarray(centres_original_rounded, dtype=np.float64)
    distances = ((X[:, None, :] - centres[None, :, :]) ** 2).sum(axis=2)
    return distances.argmin(axis=1)


# ====== NEW: int32-saturated distance (simulate LUT square overflow -> INT32_MAX) ======
INT32_MAX = np.int64(2147483647)

def predict_with_centres_original_scale_int32_sat(X_original, centres_original_rounded):
    """
    Simulate hardware: only int32 supported.
    - diff computed on integerized features
    - squared component saturates to INT32_MAX if overflow (or exceeds INT32_MAX)
    - sum of 3 components also saturates to INT32_MAX (int32 add overflow behavior)
    """
    # Hardware side usually uses integers for ports/lengths, so round to nearest int.
    X_int = np.rint(np.asarray(X_original, dtype=np.float64)).astype(np.int64)  # (N,3)
    C_int = np.rint(np.asarray(centres_original_rounded, dtype=np.float64)).astype(np.int64)  # (K,3)

    n = X_int.shape[0]
    k = C_int.shape[0]
    dists = np.empty((n, k), dtype=np.int64)

    # K is small (3), loop over centres to keep memory low.
    for ci in range(k):
        diff = X_int - C_int[ci]                 # (N,3) int64
        # square in int64 (simulate LUT output, then saturate to INT32_MAX)
        sq = diff * diff                         # (N,3) int64, safe here
        sq = np.minimum(sq, INT32_MAX)

        # saturated addition in int32 domain
        dist = sq[:, 0]
        dist = np.minimum(dist + sq[:, 1], INT32_MAX)
        dist = np.minimum(dist + sq[:, 2], INT32_MAX)

        dists[:, ci] = dist

    return dists.argmin(axis=1)


# Helper to align cluster labels to arbitrary true labels using Hungarian algorithm
def align_labels(y_true, y_pred):
    true_labels = np.unique(y_true)
    pred_labels = np.unique(y_pred)

    # Build contingency matrix with explicit label ordering
    cm = np.zeros((len(true_labels), len(pred_labels)), dtype=int)
    for i, t_lab in enumerate(true_labels):
        for j, p_lab in enumerate(pred_labels):
            cm[i, j] = np.sum((y_true == t_lab) & (y_pred == p_lab))

    cost = cm.max() - cm
    row_ind, col_ind = linear_sum_assignment(cost)
    mapping = {pred_labels[col]: true_labels[row] for row, col in zip(row_ind, col_ind)}
    return np.array([mapping.get(p, p) for p in y_pred])


# Evaluation on Training Set (with alignment for metrics only)
print(f"Calculating metrics on training set {input_file}...")
train_predictions = []
Y_train_true = []
chunk_idx = 0

for chunk in pd.read_csv(input_file, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values

    X_chunk = scaler.transform(X_chunk)
    pred_chunk = kmeans.predict(X_chunk)
    train_predictions.extend(pred_chunk)
    Y_train_true.extend(Y_chunk)

    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed training evaluation chunk {chunk_idx}...")

Predict_Y = np.array(train_predictions)
Y = np.array(Y_train_true)

# Align cluster labels to true labels for fair metric reporting
Predict_Y_aligned = align_labels(Y, Predict_Y)

print("Training dataset results:")
print(accuracy_score(Y, Predict_Y_aligned))
print("\tPrecision: %1.3f" % precision_score(Y, Predict_Y_aligned, average='weighted'))
print("\tRecall: %1.3f" % recall_score(Y, Predict_Y_aligned, average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Y, Predict_Y_aligned, average='weighted'))
print("\tConfusion matrix (aligned):\n")
print(confusion_matrix(Y, Predict_Y_aligned))


# Evaluation with OUTPUT centres (inverse-transformed + rounded to int)
print("\nEvaluating with output model centres (inverse-transformed + rounded ints) on training set...")
centres_scaled = kmeans.cluster_centers_
centres_original = scaler.inverse_transform(centres_scaled)
centres_original_rounded = np.rint(centres_original)

train_predictions_out = []
Y_train_true_out = []
chunk_idx = 0

for chunk in pd.read_csv(input_file, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values

    pred_chunk = predict_with_centres_original_scale(X_chunk, centres_original_rounded)
    train_predictions_out.extend(pred_chunk)
    Y_train_true_out.extend(Y_chunk)

    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed output-model training evaluation chunk {chunk_idx}...")

Predict_Y_out = np.array(train_predictions_out)
Y_out = np.array(Y_train_true_out)
Predict_Y_out_aligned = align_labels(Y_out, Predict_Y_out)

print("Training dataset results (output model centres, aligned):")
print(accuracy_score(Y_out, Predict_Y_out_aligned))
print("\tPrecision: %1.3f" % precision_score(Y_out, Predict_Y_out_aligned, average='weighted'))
print("\tRecall: %1.3f" % recall_score(Y_out, Predict_Y_out_aligned, average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Y_out, Predict_Y_out_aligned, average='weighted'))
print("\tConfusion matrix (aligned):\n")
print(confusion_matrix(Y_out, Predict_Y_out_aligned))


# Evaluation on Test Set (with alignment learned per set)
print(f"Predicting on test set {testfile}...")
test_predictions = []
Y_test_true = []
chunk_idx = 0

for chunk in pd.read_csv(testfile, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values

    X_chunk = scaler.transform(X_chunk)
    pred_chunk = kmeans.predict(X_chunk)
    test_predictions.extend(pred_chunk)
    Y_test_true.extend(Y_chunk)

    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed test chunk {chunk_idx}...")

Predict_Yt = np.array(test_predictions)
Yt = np.array(Y_test_true)

# Align using test confusion matrix
Predict_Yt_aligned = align_labels(Yt, Predict_Yt)

print("Test dataset results (aligned clusters):")
print(accuracy_score(Yt, Predict_Yt_aligned))
print("\tPrecision: %1.3f" % precision_score(Yt, Predict_Yt_aligned, average='weighted'))
print("\tRecall: %1.3f" % recall_score(Yt, Predict_Yt_aligned, average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Yt, Predict_Yt_aligned, average='weighted'))
print(confusion_matrix(Yt, Predict_Yt_aligned))


# Evaluation with OUTPUT centres on Test Set
print("\nEvaluating with output model centres (inverse-transformed + rounded ints) on test set...")
test_predictions_out = []
Y_test_true_out = []
chunk_idx = 0

for chunk in pd.read_csv(testfile, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values

    pred_chunk = predict_with_centres_original_scale(X_chunk, centres_original_rounded)
    test_predictions_out.extend(pred_chunk)
    Y_test_true_out.extend(Y_chunk)

    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed output-model test evaluation chunk {chunk_idx}...")

Predict_Yt_out = np.array(test_predictions_out)
Yt_out = np.array(Y_test_true_out)
Predict_Yt_out_aligned = align_labels(Yt_out, Predict_Yt_out)

print("Test dataset results (output model centres, aligned):")
print(accuracy_score(Yt_out, Predict_Yt_out_aligned))
print("\tPrecision: %1.3f" % precision_score(Yt_out, Predict_Yt_out_aligned, average='weighted'))
print("\tRecall: %1.3f" % recall_score(Yt_out, Predict_Yt_out_aligned, average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Yt_out, Predict_Yt_out_aligned, average='weighted'))
print(confusion_matrix(Yt_out, Predict_Yt_out_aligned))


# ====== NEW: Evaluation with OUTPUT centres + INT32 truncation/saturation on Test Set ======
print("\nEvaluating with output model centres + INT32-saturated distance (HW truncation simulation) on test set...")
test_predictions_sat = []
Y_test_true_sat = []
chunk_idx = 0

for chunk in pd.read_csv(testfile, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values

    pred_chunk = predict_with_centres_original_scale_int32_sat(X_chunk, centres_original_rounded)
    test_predictions_sat.extend(pred_chunk)
    Y_test_true_sat.extend(Y_chunk)

    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed INT32-sat test evaluation chunk {chunk_idx}...")

Predict_Yt_sat = np.array(test_predictions_sat)
Yt_sat = np.array(Y_test_true_sat)
Predict_Yt_sat_aligned = align_labels(Yt_sat, Predict_Yt_sat)

print("Test dataset results (output model centres, INT32-saturated distance, aligned):")
print(accuracy_score(Yt_sat, Predict_Yt_sat_aligned))  # <- 你要的“额外的截断测试集模型准确率”
print("\tPrecision: %1.3f" % precision_score(Yt_sat, Predict_Yt_sat_aligned, average='weighted'))
print("\tRecall: %1.3f" % recall_score(Yt_sat, Predict_Yt_sat_aligned, average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Yt_sat, Predict_Yt_sat_aligned, average='weighted'))
print(confusion_matrix(Yt_sat, Predict_Yt_sat_aligned))


# Output the model in a text file
centre = centres_original_rounded

print(f"Writing model to {outputfile}...")
model = open(outputfile, "w+")
for i in range(len(centre)):
    model.write("centre point : ( ")
    for j in range(3):
        model.write(str(int(centre[i][j])) + ",")
    model.write(");\n")

model.close()
print("Done.")