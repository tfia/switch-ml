#pragma once
#include <stdint.h>

#define KM_NUM_FEATURES 5
#define KM_NUM_CLASSES 5

// Feature order in km_centers rows:
//   0: frame_len
//   1: ether_type
//   2: ip_proto
//   3: l4_src_port
//   4: l4_dst_port
// Parsed from models/kmeans.txt which is assumed ordered as:
//   (frame_len, ip_proto, ether_type,
//    l4_src_port, l4_dst_port)

static const int km_centers[KM_NUM_CLASSES][KM_NUM_FEATURES] = {
    {124, 2048, 6, 47915, 4046},
    {1462, 2048, 6, 30264, 16525},
    {66, 2048, 6, 6352, 49372},
    {286, 2048, 17, 25781, 14700},
    {121, 2048, 4, 667, 1672},
};
