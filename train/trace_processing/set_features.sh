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
TARGET='csv_files'

echo "Usage: ./set_features.py <substitution file>"

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
    tshark -r ${file} -Tfields -E occurrence=f -E separator=, -e ip.len -e ipv6.plen -e eth.type -e ip.proto -e ip.flags -e ipv6.nxt -e ipv6.opt -e tcp.srcport -e tcp.dstport -e tcp.flags -e udp.srcport -e udp.dstport  -e eth.src | awk -F, 'BEGIN {OFS=","} {
      len=0;
      if ($1!="") len=$1;
      else if ($2!="") len=$2+40;
      else if ($3=="0x0806") len=28;
      
      printf "%s", len;
      for (i=3; i<=13; i++) printf ",%s", $i;
      printf "\n";
    }' > ${ofile}.csv
    
    # Use Python script for efficient labeling instead of slow shell loop
    python3 label_csv.py ${ofile}.csv "$1" "${TARGET}/${ofile}-labeled.csv"
    
    rm ${ofile}.csv
done
