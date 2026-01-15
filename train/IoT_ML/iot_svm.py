#!/usr/bin/env python
#################################################################################
#
# Copyright (c) 2019 Zhaoqi Xiong, Noa Zilberman
# All rights reserved.
#
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
from sklearn import svm
from sklearn.metrics import *
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.multiclass import OneVsOneClassifier
from sklearn.naive_bayes import GaussianNB
import pydotplus

parser = argparse.ArgumentParser()

# Add argument
parser.add_argument('-i', required=True, help='path to training set')
parser.add_argument('-o', required=True, help='path to outputfile')
parser.add_argument('-t', required=True, help='path to test set')
args = parser.parse_args()

input = args.i
outputfile = args.o
test=args.t

class_names=['smart-static','video','else']
feature_names=['frame_len','src_port','dst_port']

# Use SGDClassifier with OneVsOneClassifier for incremental learning
# Note: OneVsOneClassifier does not support partial_fit directly in a streaming fashion easily
# without custom implementation. However, given the memory constraint, we can simulate it
# by training individual binary classifiers.

# But to keep it simple and memory efficient, we will use SGDClassifier which defaults to One-Vs-Rest (5 hyperplanes).
# WAIT: The user's controller expects 10 hyperplanes (One-Vs-One).
# We MUST implement One-Vs-One training.

# Custom One-Vs-One training with SGD
from itertools import combinations
classes = [0, 1, 2]
pairs = list(combinations(classes, 2)) # [(0,1), (0,2), (1,2)] -> 3 pairs
classifiers = {}

for pair in pairs:
    classifiers[pair] = SGDClassifier(loss='hinge', random_state=8, alpha=0.0001, max_iter=1000, tol=1e-3)

# Incremental scaler to normalize features (helps SGD/SVM)
scaler = StandardScaler()

print(f"Training One-vs-One incrementally on {input}...")
chunk_size = 200000
chunk_idx = 0

for chunk in pd.read_csv(input, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)
    if chunk.empty:
        continue
    # labels are in column 3, features in 0..2
    labels = chunk.iloc[:, 3].astype(int)
    mask = labels.isin([0, 3, 4])
    if not mask.any():
        continue
    chunk = chunk.loc[mask].copy()
    # Map original labels -> new labels: 0->0, 3->1, 4->2
    chunk.iloc[:, 3] = labels[mask].replace({0: 0, 3: 1, 4: 2}).values

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values.astype(int)

    # Update scaler then transform current chunk
    try:
        scaler.partial_fit(X_chunk)
        X_chunk = scaler.transform(X_chunk)
    except Exception:
        pass

    # Train each binary classifier with relevant data
    for pair in pairs:
        c1, c2 = pair
        # Filter data for this pair
        mask_pair = (Y_chunk == c1) | (Y_chunk == c2)
        if np.any(mask_pair):
            X_pair = X_chunk[mask_pair]
            Y_pair = Y_chunk[mask_pair]
            classifiers[pair].partial_fit(X_pair, Y_pair, classes=[c1, c2])
            
    chunk_idx += 1
    print(f"Processed chunk {chunk_idx} ({chunk_idx * chunk_size} rows)...")

print("Training complete.")

# Calculate Training Accuracy
print(f"Calculating accuracy on training set {input} in chunks...")
train_predictions = []
Y_train_all = []
# Reset chunk_idx for reporting
chunk_idx = 0

for chunk in pd.read_csv(input, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)
    if chunk.empty:
        continue
    labels = chunk.iloc[:, 3].astype(int)
    mask = labels.isin([0, 3, 4])
    if not mask.any():
        continue
    chunk = chunk.loc[mask].copy()
    chunk.iloc[:, 3] = labels[mask].replace({0: 0, 3: 1, 4: 2}).values

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values.astype(int)

    # Apply scaler if available
    try:
        X_chunk = scaler.transform(X_chunk)
    except Exception:
        pass

    # Vectorized prediction on chunk
    votes = np.zeros((len(X_chunk), len(classes)))
    for pair in pairs:
        pair_preds = classifiers[pair].predict(X_chunk).astype(int)
        votes[np.arange(len(X_chunk)), pair_preds] += 1

    batch_preds = np.argmax(votes, axis=1)
    train_predictions.extend(batch_preds)
    Y_train_all.extend(Y_chunk)
    
    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed training evaluation chunk {chunk_idx}...")

Predict_Y_train = np.array(train_predictions)
Y_train = np.array(Y_train_all)

print("Training dataset")
print(accuracy_score(Y_train, Predict_Y_train))
print("\tPrecision: %1.3f" % precision_score(Y_train, Predict_Y_train, average='weighted', zero_division=0))
print("\tRecall: %1.3f" % recall_score(Y_train, Predict_Y_train, average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Y_train, Predict_Y_train, average='weighted'))

# Testing
print(f"Predicting on test set {test} in chunks...")

predictions = []
Y_t_all = []
chunk_size = 200000
chunk_idx = 0

for chunk in pd.read_csv(test, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)
    if chunk.empty:
        continue
    labels = chunk.iloc[:, 3].astype(int)
    mask = labels.isin([0, 3, 4])
    if not mask.any():
        continue
    chunk = chunk.loc[mask].copy()
    chunk.iloc[:, 3] = labels[mask].replace({0: 0, 3: 1, 4: 2}).values

    X_chunk = chunk.iloc[:, 0:3].values
    Y_chunk = chunk.iloc[:, 3].values.astype(int)

    # Apply scaler if available
    try:
        X_chunk = scaler.transform(X_chunk)
    except Exception:
        pass

    # Vectorized prediction on chunk
    votes = np.zeros((len(X_chunk), len(classes)))
    for pair in pairs:
        pair_preds = classifiers[pair].predict(X_chunk).astype(int)
        votes[np.arange(len(X_chunk)), pair_preds] += 1

    batch_preds = np.argmax(votes, axis=1)
    predictions.extend(batch_preds)
    Y_t_all.extend(Y_chunk)
    
    chunk_idx += 1
    if chunk_idx % 5 == 0:
        print(f"Processed test chunk {chunk_idx}...")

Predict_Yt = np.array(predictions)
Y_t = np.array(Y_t_all)

print("test dataset")
print(accuracy_score(Y_t, Predict_Yt))
#print("\tBrier: %1.3f" % (clf_score))
print("\tPrecision: %1.3f" % precision_score(Y_t, Predict_Yt,average='weighted', zero_division=0))
print("\tRecall: %1.3f" % recall_score(Y_t, Predict_Yt,average='weighted'))
print("\tF1: %1.3f\n" % f1_score(Y_t, Predict_Yt,average='weighted'))

# output

print("Writing model to file...")
model = open(outputfile,"w+")

# Iterate over pairs in the order they were created to ensure consistent output
# pairs = [(0,1), (0,2), (0,3), (0,4), (1,2), (1,3), (1,4), (2,3), (2,4), (3,4)]
for pair in pairs:
    clf_pair = classifiers[pair]
    model.write("hyperplane = ")
    if hasattr(clf_pair, 'coef_'):
        # SGDClassifier coef_ is shape (1, n_features) for binary
        coe = clf_pair.coef_[0]
        intr = clf_pair.intercept_[0]
        for j in range(3):
            model.write(str(coe[j]) + "x"+str(j)+ "+ ")
        model.write(str(intr)+";\n")
    else:
        # classifier not trained — write zero hyperplane
        model.write("0x0 + 0x1 + 0x2 + 0;\n")

model.close()
print("Done.")
