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
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

parser = argparse.ArgumentParser()

# Add argument
parser.add_argument('-i', required=True, help='path to dataset')
parser.add_argument('-o', required=True, help='path to outputfile')
parser.add_argument('-t', required=True, help='path to testfile')
args = parser.parse_args()

# extract argument
input_file = args.i
outputfile = args.o
testfile = args.t

class_names=['smart-static','video','else']
feature_names=['frame_len','src_port','dst_port']

# Initialize GaussianNB
clf = GaussianNB()
# We keep only 3 classes: smart-static(0), video(3->1), else(4->2)
classes = [0, 1, 2]
chunk_size = 200000

print(f"Training incrementally on {input_file}...")
chunk_idx = 0
for chunk in pd.read_csv(input_file, chunksize=chunk_size):
    chunk = chunk.apply(pd.to_numeric, downcast='float', errors='coerce')
    chunk.dropna(inplace=True)
    if chunk.empty:
        continue
    # Filter to only labels 0 (smart-static), 3 (video), 4 (else)
    labels = chunk.iloc[:, 3].astype(int)
    mask = labels.isin([0, 3, 4])
    if not mask.any():
        continue
    chunk = chunk.loc[mask].copy()
    # Map original labels -> new labels: 0->0, 3->1, 4->2
    chunk.iloc[:, 3] = labels[mask].replace({0: 0, 3: 1, 4: 2}).values

    X_chunk = chunk.iloc[:, [0, 1, 2]].values
    Y_chunk = chunk.iloc[:, 3].values.astype(int)

    clf.partial_fit(X_chunk, Y_chunk, classes=classes)
    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed training chunk {chunk_idx}...")

print("Training complete.")

# Evaluation on Training Set
print(f"Calculating accuracy on training set {input_file}...")
train_predictions = []
Y_train_true = []
chunk_idx = 0

for chunk in pd.read_csv(input_file, chunksize=chunk_size):
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

    X_chunk = chunk.iloc[:, [0, 1, 2]].values
    Y_chunk = chunk.iloc[:, 3].values.astype(int)

    pred_chunk = clf.predict(X_chunk)
    train_predictions.extend(pred_chunk)
    Y_train_true.extend(Y_chunk)
    
    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed training evaluation chunk {chunk_idx}...")

# Convert to numpy arrays
Predict_Y_train = np.array(train_predictions)
Y_train = np.array(Y_train_true)

print("Training dataset results:")
print("Accuracy: %1.3f" % accuracy_score(Y_train, Predict_Y_train))
print("Precision: %1.3f" % precision_score(Y_train, Predict_Y_train, average='weighted', zero_division=0))
print("Recall: %1.3f" % recall_score(Y_train, Predict_Y_train, average='weighted', zero_division=0))
print("F1: %1.3f" % f1_score(Y_train, Predict_Y_train, average='weighted', zero_division=0))
print("Confusion matrix:\n")
print(confusion_matrix(Y_train, Predict_Y_train))

# Evaluation on Test Set
print(f"Predicting on test set {testfile}...")
predictions = []
Y_true = []
chunk_idx = 0

for chunk in pd.read_csv(testfile, chunksize=chunk_size):
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

    X_chunk = chunk.iloc[:, [0, 1, 2]].values
    Y_chunk = chunk.iloc[:, 3].values.astype(int)

    pred_chunk = clf.predict(X_chunk)
    predictions.extend(pred_chunk)
    Y_true.extend(Y_chunk)
    
    chunk_idx += 1
    if chunk_idx % 10 == 0:
        print(f"Processed test chunk {chunk_idx}...")

# Convert to numpy arrays
Predict_Yt = np.array(predictions)
Yt = np.array(Y_true)

print("Test dataset results:")
print("Accuracy: %1.3f" % accuracy_score(Yt, Predict_Yt))
print("Precision: %1.3f" % precision_score(Yt, Predict_Yt, average='weighted', zero_division=0))
print("Recall: %1.3f" % recall_score(Yt, Predict_Yt, average='weighted', zero_division=0))
print("F1: %1.3f" % f1_score(Yt, Predict_Yt, average='weighted', zero_division=0))
print("Confusion matrix:\n")
print(confusion_matrix(Yt, Predict_Yt))

# Output the model in a text file
print(f"Writing model to {outputfile}...")
with open(outputfile, "w+") as model:
    # clf.theta_ contains means, clf.var_ contains variances
    # Shape is (n_classes, n_features)
    # Ensure we map correctly using clf.classes_
    
    for i, class_label in enumerate(clf.classes_):
        model.write(f"class {int(class_label)}: \n")
        for j in range(3):
            mean = clf.theta_[i][j]
            var = clf.var_[i][j]
            model.write(f"feature {j} ({feature_names[j]}), average value: {mean}, standard error: {var};\n")

print("Done.")
