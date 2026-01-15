#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>

#include "headers.h"
#include "switch_config.h"

#define NUM_CLASSES     3
#define NUM_FEATURES    3
#define NUM_HYPERPLANES 3
#define MAX_LINE_LEN    4096

// ---------- Quantization ----------
static const double SCALE = 10.0;   // 保留 1 位小数且避免 int32 溢出

typedef struct {
  double w[NUM_FEATURES];
  double b;
} Hyperplane;

typedef struct { int port; } ClassAction;

static Hyperplane hyperplanes[NUM_HYPERPLANES];
static ClassAction actions[NUM_CLASSES];

// 与 P4 一致：3 个 feature 的 key field 名 + bit width + table 名
typedef struct {
  const char *match_field;
  int bit_width;
  const char *table_name;
} FeatureDef;

// 注意：fid=0/1/2 对应模型 x0/x1/x2 的顺序：
//   x0 = f0_frame_len
//   x1 = f3_src_port
//   x2 = f4_dst_port
static FeatureDef feature_defs[NUM_FEATURES] = {
  { "f0_frame_len", 16, "SwitchIngress.svm_f0_tbl" },
  { "f3_src_port",  16, "SwitchIngress.svm_f3_tbl" },
  { "f4_dst_port",  16, "SwitchIngress.svm_f4_tbl" },
};

// -------------------- utils --------------------
static inline int32_t clamp_i32(double x) {
  if (x > 2147483647.0) return 2147483647;
  if (x < -2147483648.0) return (int32_t)0x80000000;
  return (int32_t)llround(x);
}

static inline uint32_t i32_to_u32_twos(int32_t v) {
  union { int32_t s; uint32_t u; } x;
  x.s = v;
  return x.u;
}

static void skip_spaces(char **p) {
  while (**p == ' ' || **p == '\t') (*p)++;
}

static int vec_all_zero_u32(const uint32_t *v, int n) {
  for (int i = 0; i < n; i++) if (v[i] != 0) return 0;
  return 1;
}

// -------------------- parse model --------------------
// line example:
// hyperplane = 74.67051x0+ 4.123206x1+ -13.258104x2+ -2420.5953;
static int load_svm_model(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("Failed to open SVM model file");
    return -1;
  }

  char line[MAX_LINE_LEN];
  int hp = 0;

  while (fgets(line, sizeof(line), fp) && hp < NUM_HYPERPLANES) {
    if (strncmp(line, "hyperplane", 10) != 0) continue;

    char *p = strchr(line, '=');
    if (!p) continue;
    p++;
    skip_spaces(&p);

    for (int i = 0; i < NUM_FEATURES; i++) hyperplanes[hp].w[i] = 0.0;
    hyperplanes[hp].b = 0.0;

    for (int t = 0; t < NUM_FEATURES; t++) {
      skip_spaces(&p);
      double w = strtod(p, &p);
      skip_spaces(&p);
      if (*p != 'x') {
        fprintf(stderr, "Model parse error (expect 'x') at hp=%d: %s\n", hp, line);
        fclose(fp);
        return -1;
      }
      p++; // skip 'x'
      int idx = (int)strtol(p, &p, 10);
      if (idx < 0 || idx >= NUM_FEATURES) {
        fprintf(stderr, "Model parse error (bad feature idx=%d) at hp=%d\n", idx, hp);
        fclose(fp);
        return -1;
      }
      hyperplanes[hp].w[idx] = w;

      skip_spaces(&p);
      if (*p == '+') p++; // optional '+'
    }

    skip_spaces(&p);
    double b = strtod(p, &p);
    hyperplanes[hp].b = b;

    hp++;
  }

  fclose(fp);

  if (hp != NUM_HYPERPLANES) {
    fprintf(stderr, "Model file has %d hyperplanes, expected %d\n", hp, NUM_HYPERPLANES);
    return -1;
  }

  printf("Loaded %d hyperplanes from %s\n", hp, filename);
  for (int h = 0; h < NUM_HYPERPLANES; h++) {
    printf("  hp%d: w=[%.6f %.6f %.6f], b=%.6f\n",
           h, hyperplanes[h].w[0], hyperplanes[h].w[1], hyperplanes[h].w[2], hyperplanes[h].b);
  }
  return 0;
}

// -------------------- parse action --------------------
static int load_actions(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    perror("Failed to open action file");
    return -1;
  }

  for (int i = 0; i < NUM_CLASSES; i++) actions[i].port = 0;

  char line[MAX_LINE_LEN];
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "class", 5) != 0) continue;
    int cls, port;
    if (sscanf(line, "class %d: [%d]", &cls, &port) == 2) {
      if (cls >= 0 && cls < NUM_CLASSES) actions[cls].port = port;
    }
  }

  fclose(fp);

  for (int c = 0; c < NUM_CLASSES; c++) {
    printf("Action: class %d -> port %d\n", c, actions[c].port);
  }
  return 0;
}

// -------------------- switchd/ports (copy naive style) --------------------
static void port_setup(const bf_rt_target_t *dev_tgt,
                       const switch_port_t *port_list,
                       const uint8_t port_count)
{
  bf_status_t bf_status;
  for (unsigned int idx = 0; idx < port_count; idx++) {
    bf_pal_front_port_handle_t port_hdl;
    bf_status = bf_pm_port_str_to_hdl_get(dev_tgt->dev_id, port_list[idx].fp_port, &port_hdl);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_pm_port_add(dev_tgt->dev_id, &port_hdl, BF_SPEED_10G, BF_FEC_TYP_NONE);
    assert(bf_status == BF_SUCCESS);
    bf_status = bf_pm_port_enable(dev_tgt->dev_id, &port_hdl);
    assert(bf_status == BF_SUCCESS);
    printf("Port %s is enabled successfully!\n", port_list[idx].fp_port);
  }
}

static void switchd_setup(bf_switchd_context_t *switchd_ctx, const char *prog)
{
  char conf_file[256];
  char bf_sysfs_fname[128] = "/sys/class/bf/bf0/device";
  FILE *fd;

  switchd_ctx->install_dir = strdup(getenv("SDE_INSTALL"));
  sprintf(conf_file, "%s%s%s%s",
          getenv("SDE_INSTALL"), "/share/p4/targets/tofino/", prog, ".conf");
  switchd_ctx->conf_file = conf_file;
  switchd_ctx->running_in_background = 1;
  switchd_ctx->dev_sts_thread = 1;
  switchd_ctx->dev_sts_port = 7777;

  strncat(bf_sysfs_fname, "/dev_add",
          sizeof(bf_sysfs_fname) - 1 - strlen(bf_sysfs_fname));
  printf("bf_sysfs_fname %s\n", bf_sysfs_fname);
  fd = fopen(bf_sysfs_fname, "r");
  if (fd != 0) {
    printf("kernel mode packet driver present, forcing kpkt option!\n");
    switchd_ctx->kernel_pkt = 1;
    fclose(fd);
  }

  assert(bf_switchd_lib_init(switchd_ctx) == BF_SUCCESS);
  printf("\nbf_switchd is initialized correctly!\n");
}

// -------------------- emit exact entry (pure C) --------------------
static void emit_exact_entry(const bf_rt_table_hdl *table,
                             bf_rt_session_hdl *session,
                             bf_rt_target_t *dev_tgt,
                             bf_rt_table_key_hdl **key,
                             bf_rt_table_data_hdl **data,
                             bf_rt_id_t kid_match,
                             bf_rt_id_t aid_action,
                             const bf_rt_id_t *did,
                             int val,
                             const uint32_t *v,
                             int *installed)
{
  // 全 0 不下发，走 default_action（要求 P4 default_action 已设为加 0）
  if (vec_all_zero_u32(v, NUM_HYPERPLANES)) return;

  // reset 需要传 **hdl
  bf_rt_table_key_reset(table, key);
  bf_rt_key_field_set_value(*key, kid_match, (uint64_t)val);

  bf_rt_table_action_data_reset(table, aid_action, data);
  for (int h = 0; h < NUM_HYPERPLANES; h++) {
    bf_rt_data_field_set_value(*data, did[h], (uint64_t)v[h]);
  }

  bf_status_t s2 = bf_rt_table_entry_add(table, session, dev_tgt, *key, *data);
  if (s2 == BF_ALREADY_EXISTS) {
    s2 = bf_rt_table_entry_mod(table, session, dev_tgt, *key, *data);
  }
  if (s2 == BF_SUCCESS) (*installed)++;
  else {
    printf("  WARN: entry add/mod failed (st=%d) val=%d\n", s2, val);
  }
}

// -------------------- program SVM feature table (EXACT) --------------------
static void program_svm_feature_table(const bf_rt_info_hdl *bfrt_info,
                                      bf_rt_session_hdl *session,
                                      bf_rt_target_t *dev_tgt,
                                      int fid)
{
  const char *table_name = feature_defs[fid].table_name;

  const bf_rt_table_hdl *table = NULL;
  bf_status_t st = bf_rt_table_from_name_get(bfrt_info, table_name, &table);
  if (st != BF_SUCCESS) {
    printf("Warning: table %s not found\n", table_name);
    return;
  }

  bf_rt_table_key_hdl  *key  = NULL;
  bf_rt_table_data_hdl *data = NULL;
  bf_rt_table_key_allocate(table, &key);
  bf_rt_table_data_allocate(table, &data);

  bf_rt_id_t kid_match;
  bf_rt_key_field_id_get(table, feature_defs[fid].match_field, &kid_match);

  // f0 用 init_and_add_hp_scores，其它用 add_hp_scores
  const char *action_name = (fid == 0)
      ? "SwitchIngress.init_and_add_hp_scores"
      : "SwitchIngress.add_hp_scores";

  bf_rt_id_t aid_action;
  bf_rt_action_name_to_id(table, action_name, &aid_action);

  bf_rt_id_t did[NUM_HYPERPLANES];
  for (int h = 0; h < NUM_HYPERPLANES; h++) {
    char fn[8];
    snprintf(fn, sizeof(fn), "d%d", h);
    bf_rt_data_field_id_with_action_get(table, fn, aid_action, &did[h]);
  }

  const int max_val = (int)((1u << feature_defs[fid].bit_width) - 1u);

  uint32_t cur_vec[NUM_HYPERPLANES];
  int installed = 0;

  // exact：逐值插入（可跳过全 0，走 default_action）
  for (int val = 0; val <= max_val; val++) {
    for (int h = 0; h < NUM_HYPERPLANES; h++) {
      double w = hyperplanes[h].w[fid];
      double b = hyperplanes[h].b;

      double z;
      if (fid == 0) {
        // merge intercept into f0
        z = (w * (double)val + b) * SCALE;
      } else {
        z = (w * (double)val) * SCALE;
      }

      int32_t q = clamp_i32(z);
      cur_vec[h] = i32_to_u32_twos(q);
    }

    emit_exact_entry(table, session, dev_tgt,
                     &key, &data,
                     kid_match, aid_action, did,
                     val, cur_vec, &installed);
  }

  printf("Installed %d EXACT entries for %s (domain=%d)\n",
         installed, table_name, max_val + 1);
}

// -------------------- vote mapping: sign_vec -> class --------------------
static int predict_class_from_sign(uint32_t sign_vec) {
  // sign_vec bit: [2]=h2 [1]=h1 [0]=h0
  // 约定：
  //   h0: 0v1  score>=0 -> 0, score<0 -> 1
  //   h1: 0v2  score>=0 -> 0, score<0 -> 2
  //   h2: 1v2  score>=0 -> 1, score<0 -> 2
  int votes[NUM_CLASSES] = {0,0,0};

  int s0 = (sign_vec >> 0) & 1; // h0
  int s1 = (sign_vec >> 1) & 1; // h1
  int s2 = (sign_vec >> 2) & 1; // h2

  votes[s0 ? 1 : 0]++; // h0: 0 vs 1
  votes[s1 ? 2 : 0]++; // h1: 0 vs 2
  votes[s2 ? 2 : 1]++; // h2: 1 vs 2

  int best = 0;
  for (int c = 1; c < NUM_CLASSES; c++) {
    if (votes[c] > votes[best]) best = c;
    else if (votes[c] == votes[best] && c < best) best = c; // tie -> smaller id
  }
  return best;
}

// -------------------- program svm_vote_fwd_tbl --------------------
static void program_svm_vote_fwd_table(const bf_rt_info_hdl *bfrt_info,
                                       bf_rt_session_hdl *session,
                                       bf_rt_target_t *dev_tgt)
{
  const bf_rt_table_hdl *table = NULL;
  bf_status_t st = bf_rt_table_from_name_get(bfrt_info,
                                            "SwitchIngress.svm_vote_fwd_tbl",
                                            &table);
  if (st != BF_SUCCESS) {
    printf("Error: table SwitchIngress.svm_vote_fwd_tbl not found (st=%d)\n", st);
    return;
  }

  bf_rt_table_key_hdl  *key  = NULL;
  bf_rt_table_data_hdl *data = NULL;

  st = bf_rt_table_key_allocate(table, &key);
  if (st != BF_SUCCESS) { printf("Error: key_allocate st=%d\n", st); return; }

  st = bf_rt_table_data_allocate(table, &data);
  if (st != BF_SUCCESS) { printf("Error: data_allocate st=%d\n", st); return; }

  bf_rt_id_t kid_sign = 0;
  st = bf_rt_key_field_id_get(table, "sign_vec", &kid_sign);
  if (st != BF_SUCCESS) { printf("Error: key_field_id_get(sign_vec) st=%d\n", st); return; }

  bf_rt_id_t aid_set = 0;
  st = bf_rt_action_name_to_id(table,
                               "SwitchIngress.svm_set_class_and_forward",
                               &aid_set);
  if (st != BF_SUCCESS) { printf("Error: action_name_to_id(svm_set_class_and_forward) st=%d\n", st); return; }

  bf_rt_id_t did_cls = 0, did_port = 0;
  st = bf_rt_data_field_id_with_action_get(table, "cls", aid_set, &did_cls);
  if (st != BF_SUCCESS) { printf("Error: data_field_id_get(cls) st=%d\n", st); return; }

  st = bf_rt_data_field_id_with_action_get(table, "port", aid_set, &did_port);
  if (st != BF_SUCCESS) { printf("Error: data_field_id_get(port) st=%d\n", st); return; }

  printf("Installing svm_vote_fwd_tbl entries...\n");

  for (uint32_t s = 0; s < 8; s++) {
    int cls  = predict_class_from_sign(s);
    int port = actions[cls].port;   // 这里就是 dev_port=2/3/4（你日志已证明）

    // reset key/data（注意：reset 需要传 &key / &data）
    st = bf_rt_table_key_reset(table, &key);
    if (st != BF_SUCCESS) { printf("Error: key_reset st=%d\n", st); return; }

    st = bf_rt_key_field_set_value(key, kid_sign, (uint64_t)s);
    if (st != BF_SUCCESS) { printf("Error: key_set(sign_vec=%u) st=%d\n", s, st); return; }

    st = bf_rt_table_action_data_reset(table, aid_set, &data);
    if (st != BF_SUCCESS) { printf("Error: action_data_reset st=%d\n", st); return; }

    st = bf_rt_data_field_set_value(data, did_cls,  (uint64_t)cls);
    if (st != BF_SUCCESS) { printf("Error: data_set(cls=%d) st=%d\n", cls, st); return; }

    st = bf_rt_data_field_set_value(data, did_port, (uint64_t)port);
    if (st != BF_SUCCESS) { printf("Error: data_set(port=%d) st=%d\n", port, st); return; }

    bf_status_t s2 = bf_rt_table_entry_add(table, session, dev_tgt, key, data);
    if (s2 == BF_ALREADY_EXISTS) s2 = bf_rt_table_entry_mod(table, session, dev_tgt, key, data);

    printf("  sign_vec=%u (b2b1b0=%u%u%u) -> cls=%d -> dev_port=%d (st=%d)\n",
           s, (s>>2)&1, (s>>1)&1, (s>>0)&1, cls, port, s2);
  }
}

// -------------------- main --------------------
int main(int argc, char **argv) {
  bf_rt_target_t dev_tgt;
  bf_rt_session_hdl *session = NULL;
  const bf_rt_info_hdl *bfrt_info = NULL;

  bf_switchd_context_t *switchd_ctx =
      (bf_switchd_context_t *)calloc(1, sizeof(bf_switchd_context_t));
  if (!switchd_ctx) {
    printf("Cannot allocate switchd context\n");
    return -1;
  }

#ifndef P4_PROG_NAME
  const char *P4_PROG_NAME = "svm";
#endif

  // ---- init switchd ----
  switchd_setup(switchd_ctx, P4_PROG_NAME);

  dev_tgt.dev_id  = 0;
  dev_tgt.pipe_id = 0xFFFF;

  // ---- ports ----
  port_setup(&dev_tgt, PORT_LIST, ARRLEN(PORT_LIST));

  // ---- load model/actions ----
  if (load_svm_model("./svm_model.txt") != 0) return -1;
  if (load_actions("./action.txt") != 0) return -1;

  // ---- BF-RT info ----
  bf_status_t st = bf_rt_info_get(dev_tgt.dev_id, P4_PROG_NAME, &bfrt_info);
  if (st != BF_SUCCESS) {
    printf("Failed to get bfrt_info for %s\n", P4_PROG_NAME);
    return -1;
  }

  bf_rt_session_create(&session);

  printf("Installing SVM rules: %d features, %d hyperplanes, scale=%.1f\n",
         NUM_FEATURES, NUM_HYPERPLANES, SCALE);

  // 1) 3 feature tables (EXACT)
  for (int f = 0; f < NUM_FEATURES; f++) {
    program_svm_feature_table(bfrt_info, session, &dev_tgt, f);
  }

  // 2) sign_vec -> (class, port)
  program_svm_vote_fwd_table(bfrt_info, session, &dev_tgt);

  bf_rt_session_complete_operations(session);
  bf_rt_session_destroy(session);

  printf("Done.\n");
  while (1) sleep(10);
  return 0;
}