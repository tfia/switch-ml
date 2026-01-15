#!/bin/bash
# Run all four models (NB, DT, SVM-OvO, KMeans) on 5-feature datasets.
# Usage: ./run_all_models.sh <train_csv> <test_csv> [output_dir]
# Defaults: train=../trace_processing/train_data_new.csv, test=../trace_processing/test_data_new.csv, out=models_5feat

set -euo pipefail

TRAIN=${1:-"train_data_filtered.csv"}
TEST=${2:-"test_data_filtered.csv"}
OUTDIR=${3:-"models_5feat_filtered"}

# Paths to model scripts (now located in ../iisy_sw/IoT_ML relative to this script)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODEL_DIR="$SCRIPT_DIR/../iisy_sw/IoT_ML"

mkdir -p "$OUTDIR"

log() { echo "[$(date '+%H:%M:%S')] $*"; }

log "Training Naive Bayes..."
python "$MODEL_DIR/iot_naivebayes.py" -i "$TRAIN" -o "$OUTDIR/naive_bayes_model.txt" -t "$TEST"

log "Training Decision Tree..."
python "$MODEL_DIR/iot_decisiontree.py" -i "$TRAIN" -o "$OUTDIR/decisiontree_model.txt" -t "$TEST"

log "Training SVM (OvO SGD)..."
python "$MODEL_DIR/iot_svm.py" -i "$TRAIN" -o "$OUTDIR/svm_model.txt" -t "$TEST"

log "Training KMeans..."
python "$MODEL_DIR/iot_kmeans.py" -i "$TRAIN" -o "$OUTDIR/kmeans_model.txt" -t "$TEST"

log "All models finished. Outputs in $OUTDIR"
