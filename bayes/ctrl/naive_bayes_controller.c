#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <arpa/inet.h>   // htonl/ntohl

#include "headers.h"
#include "switch_config.h"

#define NUM_CLASSES   3
#define NUM_FEATURES  3
#define MAX_LINE_LEN  1024

// ===== Must match P4 constants / your design choices =====
static const double VAR_EPS          = 1e-9;
static const double COST_SCALE       = 1000.0;
static const double COST_CUTOFF      = 30.0;
static const uint32_t DEFAULT_COST_Q = 30000;  // DEFAULT_COST=30000 in P4

// ------------------ model structs ------------------
typedef struct {
  double mean;
  double variance; // model file says "standard error", here we use it as variance
} FeatureParams;

typedef struct {
  FeatureParams features[NUM_FEATURES];
} ClassParams;

typedef struct {
  int port;
} ClassAction;

static ClassParams  model[NUM_CLASSES];
static ClassAction  actions[NUM_CLASSES];

typedef struct {
  const char *name;
  const char *table_name;   // BFRT table name
  const char *match_field;  // BFRT key field name
  int bit_width;
} FeatureDef;

// Align to your P4:
//   f0_tbl key: f0_frame_len (16)
//   f3_tbl key: f3_src_port  (16)
//   f4_tbl key: f4_dst_port  (16)
static FeatureDef feature_defs[NUM_FEATURES] = {
  {"frame_len", "SwitchIngress.f0_tbl", "f0_frame_len", 16}, // feature 0
  {"src_port",  "SwitchIngress.f3_tbl", "f3_src_port",  16}, // feature 1
  {"dst_port",  "SwitchIngress.f4_tbl", "f4_dst_port",  16}, // feature 2
};

// ------------------ BFRT check macro ------------------
#ifndef P4_CHECK
#define P4_CHECK(x) do { \
  bf_status_t __s = (x); \
  if (__s != BF_SUCCESS) { \
    printf("BFRT error %d at %s:%d\n", __s, __FILE__, __LINE__); \
    exit(1); \
  } \
} while(0)
#endif

// ------------------ cost computation ------------------
static inline uint32_t calculate_cost(double x, double mu, double var) {
  if (var < 0) var = 0;
  var = var + VAR_EPS;

  double dx = x - mu;
  double cost = 0.5 * log(2.0 * M_PI * var) + (dx * dx) / (2.0 * var);

  if (!isfinite(cost)) cost = COST_CUTOFF + 1000.0;

  double qd = cost * COST_SCALE;
  if (qd < 0) qd = 0;
  if (qd > 4294967295.0) qd = 4294967295.0;
  return (uint32_t) llround(qd);
}

// ------------------ BYTE_STREAM helpers (32-bit) ------------------
// IMPORTANT: v0..v2 are BYTE_STREAM(32). Must use set_value_ptr/get_value_ptr.
static inline void set_u32_bytestream_be(bf_rt_table_data_hdl *data,
                                        bf_rt_id_t field_id,
                                        uint32_t v) {
  uint32_t be = htonl(v);
  P4_CHECK(bf_rt_data_field_set_value_ptr(data, field_id, (uint8_t*)&be, sizeof(be)));
}

static inline int get_u32_bytestream_be(bf_rt_table_data_hdl *data,
                                        bf_rt_id_t field_id,
                                        uint32_t *out) {
  uint8_t buf[4] = {0};
  size_t  sz = sizeof(buf);
  bf_status_t s = bf_rt_data_field_get_value_ptr(data, field_id, sz, buf);
  if (s != BF_SUCCESS || sz != 4) return -1;
  uint32_t be = *(uint32_t*)buf;
  *out = ntohl(be);
  return 0;
}

static inline void dump_u32_as_hex_bytes(uint32_t v) {
  uint32_t be = htonl(v);
  uint8_t *p = (uint8_t*)&be;
  printf("%02X %02X %02X %02X", p[0], p[1], p[2], p[3]);
}

// ------------------ model/action loading ------------------
// Expect model file like:
// class 0:
// feature 0 (frame_len), average value: ..., standard error: ...;
// feature 1 (src_port),  average value: ..., standard error: ...;
// feature 2 (dst_port),  average value: ..., standard error: ...;
int load_model(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) { perror("Failed to open model file"); return -1; }

  char line[MAX_LINE_LEN];
  int current_class = -1;

  // init defaults (optional)
  for (int c = 0; c < NUM_CLASSES; c++) {
    for (int f = 0; f < NUM_FEATURES; f++) {
      model[c].features[f].mean = 0.0;
      model[c].features[f].variance = 0.0;
    }
  }

  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "class", 5) == 0) {
      if (sscanf(line, "class %d:", &current_class) == 1) {
        continue;
      } else {
        current_class = -1;
        continue;
      }
    }

    if (strncmp(line, "feature", 7) == 0 &&
        current_class >= 0 && current_class < NUM_CLASSES) {

      int feat_idx = -1;
      double avg = 0.0, var = 0.0;

      char *avg_ptr = strstr(line, "average value:");
      char *var_ptr = strstr(line, "standard error:");
      if (!avg_ptr || !var_ptr) continue;

      if (sscanf(line, "feature %d,", &feat_idx) != 1) continue;
      if (sscanf(avg_ptr, "average value: %lf,", &avg) != 1) continue;
      if (sscanf(var_ptr, "standard error: %lf;", &var) != 1) continue;

      if (feat_idx < 0 || feat_idx >= NUM_FEATURES) continue;

      model[current_class].features[feat_idx].mean = avg;
      model[current_class].features[feat_idx].variance = var;
    }
  }

  fclose(fp);
  return 0;
}

int load_actions(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) { perror("Failed to open action file"); return -1; }

  for (int c = 0; c < NUM_CLASSES; c++) actions[c].port = 0;

  char line[MAX_LINE_LEN];
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "class", 5) == 0) {
      int cls = -1, port = -1;
      if (sscanf(line, "class %d: [%d]", &cls, &port) == 2) {
        if (cls >= 0 && cls < NUM_CLASSES) actions[cls].port = port;
      }
    }
  }

  fclose(fp);
  return 0;
}

// ------------------ port / switchd setup ------------------
static void port_setup(const bf_rt_target_t *dev_tgt,
                       const switch_port_t *port_list,
                       const uint8_t port_count) {
  for (unsigned int idx = 0; idx < port_count; idx++) {
    bf_pal_front_port_handle_t port_hdl;
    P4_CHECK(bf_pm_port_str_to_hdl_get(dev_tgt->dev_id, port_list[idx].fp_port, &port_hdl));
    P4_CHECK(bf_pm_port_add(dev_tgt->dev_id, &port_hdl, BF_SPEED_10G, BF_FEC_TYP_NONE));
    P4_CHECK(bf_pm_port_enable(dev_tgt->dev_id, &port_hdl));
    printf("Port %s is enabled successfully!\n", port_list[idx].fp_port);
  }
}

static void switchd_setup(bf_switchd_context_t *switchd_ctx, const char *prog) {
  char conf_file[256];
  char bf_sysfs_fname[128] = "/sys/class/bf/bf0/device";
  FILE *fd;

  switchd_ctx->install_dir = strdup(getenv("SDE_INSTALL"));
  sprintf(conf_file, "%s/share/p4/targets/tofino/%s.conf", getenv("SDE_INSTALL"), prog);
  switchd_ctx->conf_file = conf_file;

  switchd_ctx->running_in_background = 1;
  switchd_ctx->dev_sts_thread = 1;
  switchd_ctx->dev_sts_port = 7777;

  strncat(bf_sysfs_fname, "/dev_add", sizeof(bf_sysfs_fname) - 1 - strlen(bf_sysfs_fname));
  printf("bf_sysfs_fname %s\n", bf_sysfs_fname);
  fd = fopen(bf_sysfs_fname, "r");
  if (fd != 0) {
    printf("kernel mode packet driver present, forcing kpkt option!\n");
    switchd_ctx->kernel_pkt = 1;
    fclose(fd);
  }

  P4_CHECK(bf_switchd_lib_init(switchd_ctx));
  printf("\nbf_switchd is initialized correctly!\n");
}

// ------------------ program one feature table ------------------
static void program_feature_table(const bf_rt_info_hdl *bfrt_info,
                                  bf_rt_session_hdl *session,
                                  bf_rt_target_t *dev_tgt,
                                  int feat_idx) {
  assert(feat_idx >= 0 && feat_idx < NUM_FEATURES);

  const char *table_name = feature_defs[feat_idx].table_name;

  const bf_rt_table_hdl *table = NULL;
  bf_rt_table_key_hdl  *key  = NULL;
  bf_rt_table_data_hdl *data = NULL;

  bf_rt_id_t kid_match;
  bf_rt_id_t aid_action;
  bf_rt_id_t did_v[NUM_CLASSES];

  P4_CHECK(bf_rt_table_from_name_get(bfrt_info, table_name, &table));
  P4_CHECK(bf_rt_table_key_allocate(table, &key));
  P4_CHECK(bf_rt_table_data_allocate(table, &data));

  P4_CHECK(bf_rt_key_field_id_get(table, feature_defs[feat_idx].match_field, &kid_match));
  P4_CHECK(bf_rt_action_name_to_id(table, "SwitchIngress.add_scores", &aid_action));

  // v0..v2 are BYTE_STREAM(32)
  P4_CHECK(bf_rt_data_field_id_with_action_get(table, "v0", aid_action, &did_v[0]));
  P4_CHECK(bf_rt_data_field_id_with_action_get(table, "v1", aid_action, &did_v[1]));
  P4_CHECK(bf_rt_data_field_id_with_action_get(table, "v2", aid_action, &did_v[2]));

  printf("Table %s: action_id=%lu did_v0=%lu did_v1=%lu did_v2=%lu\n",
         table_name,
         (unsigned long)aid_action,
         (unsigned long)did_v[0], (unsigned long)did_v[1], (unsigned long)did_v[2]);

  const int max_val = (1 << feature_defs[feat_idx].bit_width) - 1;
  int count = 0;

  for (int val = 0; val <= max_val; val++) {
    uint32_t c[NUM_CLASSES];

    for (int cls = 0; cls < NUM_CLASSES; cls++) {
      c[cls] = calculate_cost((double)val,
                              model[cls].features[feat_idx].mean,
                              model[cls].features[feat_idx].variance);
    }

    // Skip entries that are useless for all classes (>= default for every class)
    if (c[0] >= DEFAULT_COST_Q && c[1] >= DEFAULT_COST_Q && c[2] >= DEFAULT_COST_Q) {
      continue;
    }

    P4_CHECK(bf_rt_table_key_reset(table, &key));
    P4_CHECK(bf_rt_key_field_set_value(key, kid_match, (uint64_t)val));

    P4_CHECK(bf_rt_table_action_data_reset(table, aid_action, &data));
    set_u32_bytestream_be(data, did_v[0], c[0]);
    set_u32_bytestream_be(data, did_v[1], c[1]);
    set_u32_bytestream_be(data, did_v[2], c[2]);

    bf_status_t st = bf_rt_table_entry_add(table, session, dev_tgt, key, data);
    if (st == BF_ALREADY_EXISTS) st = bf_rt_table_entry_mod(table, session, dev_tgt, key, data);
    if (st != BF_SUCCESS) {
      printf("Warning: add/mod failed table=%s key=%d st=%d\n", table_name, val, st);
      continue;
    }

    // Print + readback verify first 10 entries we actually install
    if (count < 10) {
      printf("Programming %s: key=%d (0x%04X) -> costs=[%u,%u,%u]\n",
             table_name, val, val, c[0], c[1], c[2]);
      printf("  bytes(v0) = "); dump_u32_as_hex_bytes(c[0]); printf("\n");

      bf_rt_table_data_hdl *rd = NULL;
      P4_CHECK(bf_rt_table_data_allocate(table, &rd));
      bf_status_t gs = bf_rt_table_entry_get(table, session, dev_tgt, key, rd, 1);
      if (gs != BF_SUCCESS) {
        printf("  Readback entry_get FAILED st=%d\n", gs);
      } else {
        uint32_t rv[NUM_CLASSES] = {0};
        int ok = 1;
        for (int cls = 0; cls < NUM_CLASSES; cls++) {
          if (get_u32_bytestream_be(rd, did_v[cls], &rv[cls]) != 0) ok = 0;
        }
        if (!ok) {
          printf("  Readback parse FAILED (BYTE_STREAM get)\n");
        } else {
          printf("  Readback ok: [%u,%u,%u]\n", rv[0], rv[1], rv[2]);
        }
      }
      if (rd) P4_CHECK(bf_rt_table_data_deallocate(rd));
    }

    count++;
  }

  printf("Installed %d entries for %s (%s)\n", count, table_name, feature_defs[feat_idx].name);

  P4_CHECK(bf_rt_table_key_deallocate(key));
  P4_CHECK(bf_rt_table_data_deallocate(data));

  // flush to HW
  P4_CHECK(bf_rt_session_complete_operations(session));
}

// ------------------ program forwarding table ------------------
static void program_forwarding_table(const bf_rt_info_hdl *bfrt_info,
                                     bf_rt_session_hdl *session,
                                     bf_rt_target_t *dev_tgt) {
  const bf_rt_table_hdl *table = NULL;
  bf_rt_table_key_hdl  *key  = NULL;
  bf_rt_table_data_hdl *data = NULL;

  bf_rt_id_t kid_class;
  bf_rt_id_t aid_forward;
  bf_rt_id_t did_port;

  P4_CHECK(bf_rt_table_from_name_get(bfrt_info, "SwitchIngress.ipv4_exact", &table));
  P4_CHECK(bf_rt_table_key_allocate(table, &key));
  P4_CHECK(bf_rt_table_data_allocate(table, &data));

  P4_CHECK(bf_rt_key_field_id_get(table, "ig_md.classification", &kid_class));
  P4_CHECK(bf_rt_action_name_to_id(table, "SwitchIngress.ipv4_forward", &aid_forward));
  P4_CHECK(bf_rt_data_field_id_with_action_get(table, "port", aid_forward, &did_port));

  for (int c = 0; c < NUM_CLASSES; c++) {
    int port = actions[c].port;

    P4_CHECK(bf_rt_table_key_reset(table, &key));
    P4_CHECK(bf_rt_key_field_set_value(key, kid_class, (uint64_t)c));

    P4_CHECK(bf_rt_table_action_data_reset(table, aid_forward, &data));
    P4_CHECK(bf_rt_data_field_set_value(data, did_port, (uint64_t)port));

    bf_status_t st = bf_rt_table_entry_add(table, session, dev_tgt, key, data);
    if (st == BF_ALREADY_EXISTS) st = bf_rt_table_entry_mod(table, session, dev_tgt, key, data);
    P4_CHECK(st);

    printf("Class %d -> Port %d\n", c, port);
  }

  P4_CHECK(bf_rt_table_key_deallocate(key));
  P4_CHECK(bf_rt_table_data_deallocate(data));
  P4_CHECK(bf_rt_session_complete_operations(session));
}

// ------------------ main ------------------
int main(int argc, char **argv) {
  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session = NULL;
  const bf_rt_info_hdl *bfrt_info = NULL;

  bf_switchd_context_t *switchd_ctx =
      (bf_switchd_context_t*)calloc(1, sizeof(bf_switchd_context_t));
  if (!switchd_ctx) { printf("Cannot allocate switchd context\n"); return -1; }

#ifndef P4_PROG_NAME
  const char *P4_PROG_NAME = "naive_bayes";
#endif

  switchd_setup(switchd_ctx, P4_PROG_NAME);

  dev_tgt.dev_id  = 0;
  dev_tgt.pipe_id = 0xFFFF; // all pipes

  port_setup(&dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));

  if (load_model("./naive_bayes_model.txt") != 0) return -1;
  if (load_actions("./action.txt") != 0) return -1;

  P4_CHECK(bf_rt_info_get(dev_tgt.dev_id, P4_PROG_NAME, &bfrt_info));
  P4_CHECK(bf_rt_session_create(&session));

  printf("Installing Naive Bayes(cost) rules for %d features, %d classes...\n",
         NUM_FEATURES, NUM_CLASSES);
  printf("COST_SCALE=%.0f, COST_CUTOFF=%.1f, DEFAULT_COST_Q=%u\n",
         COST_SCALE, COST_CUTOFF, DEFAULT_COST_Q);

  // program 3 feature tables: f0, f3, f4
  for (int f = 0; f < NUM_FEATURES; f++) {
    program_feature_table(bfrt_info, session, &dev_tgt, f);
  }

  // program class->port forwarding
  program_forwarding_table(bfrt_info, session, &dev_tgt);

  P4_CHECK(bf_rt_session_complete_operations(session));
  P4_CHECK(bf_rt_session_destroy(session));

  printf("Done.\n");
  while (1) sleep(10);
  return 0;
}