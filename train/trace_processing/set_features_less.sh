#!/bin/bash
#################################################################################
#
# Copyright (c) 2019 Noa Zilberman
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
#
# Description: this file takes as input a folder with pcap files, and converts them
# to CSV files. It extracts just specific features form the file, e.g., frame len,
# Ether type, IP protocols etc.
#
# You will need python and tshark installed to run this code
#

FILES=$(find original_files/ -type f)
TARGET='csv_files_new'

echo "Usage: ./set_features_less.sh <substitution file> [per_class_target]"

# Create target dir if missing
mkdir -p "$TARGET"

for file in $FILES; do
    ofile_base=$(basename "${file}")
    ofile="${ofile_base%.*}"
    
    # Check if output file already exists (Resume capability)
    if [ -f "${TARGET}/${ofile}-labeled.csv" ]; then
        echo "Skipping ${file} (already processed)"
        continue
    fi

    echo "Processing ${file}..."
    
    rm -f tmp
    # Extract five features:
    # - frame_len
    # - ip.proto (bucketed: TCP=6, UDP=17, ICMP/ICMPv6=1, IGMP=2, OTHER=0)
    # - eth.type (raw, supports ALL EtherTypes)
    # - src_port (tcp.srcport if present else udp.srcport)
    # - dst_port (tcp.dstport if present else udp.dstport)
    # Keep eth.src as last column for labeling.
    # No EtherType filtering - captures all frame types for maximum diversity
    tshark -o tcp.analyze_sequence_numbers:TRUE \
      -r ${file} \
      -Tfields -E occurrence=f -E separator=, \
      -e frame.len -e ip.len -e ipv6.plen -e eth.type -e ip.proto -e ipv6.nxt -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e eth.src | \
      awk -F, 'BEGIN {OFS=","} {
      # Use frame.len directly if available (includes all layers)
      len=$1;
      if (len=="") {
        # Fallback: compute from IP layer
        if ($2!="") len=$2;             # IPv4 total length
        else if ($3!="") len=$3+40;     # IPv6 payload + 40 bytes header
        else if ($4=="0x0806") len=28;  # ARP
        else len=64;                     # Default for other types
      }

      # Map protocol to 5 buckets (ip.proto for IPv4, ipv6.nxt for IPv6)
      proto=$5; if (proto=="" && $6!="") proto=$6;
      pb=0;                 # OTHER default
      if (proto==6) pb=6;   # TCP
      else if (proto==17) pb=17;  # UDP
      else if (proto==1 || proto==58) pb=1;    # ICMP/ICMPv6
      else if (proto==2) pb=2;    # IGMP

      # Ports: prefer TCP, else UDP, else 0
      sport=$7; dport=$8; usport=$9; udport=$10;
      if (sport=="" && usport!="") sport=usport;
      if (dport=="" && udport!="") dport=udport;
      if (sport=="") sport=0;
      if (dport=="") dport=0;

      # Output: len, proto_bucket, eth.type, src_port, dst_port, eth.src
      printf "%s,%s,%s,%s,%s,%s\n", len, pb, $4, sport, dport, $11;
    }' > ${ofile}.csv
    
    # Label rows using MAC->class mapping file
    python3 label_csv.py ${ofile}.csv "$1" "${TARGET}/${ofile}-labeled.csv"
    
    rm ${ofile}.csv
done

# Optional: build a single balanced dataset across all labeled CSVs
if [ -n "$2" ]; then
  echo "Building balanced merged dataset with per-class target: $2"
  python3 balance_export.py "${TARGET}" "${TARGET}/balanced_all.csv" --per_class_target "$2"
else
  echo "Tip: provide per_class_target to create balanced_all.csv, e.g., ./set_features_less.sh mapping.txt 2000000"
fi
