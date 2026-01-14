#!/usr/bin/env bash
set -euo pipefail

MAP_FILE="${1:?Usage: $0 <replacement_numeric> [input_dir] [output_dir] [mode:src|both] [keep_ratio:0.2] [seed]}"
IN_DIR="${2:-original_files}"
OUT_DIR="${3:-pcap_by_class_20pct}"
MODE="${4:-src}"            # src | both
KEEP_RATIO="${5:-0.2}"      # 每类保留比例，比如 0.2
SEED="${6:-0}"              # 0=随机；非0=可复现

python3 - "$MAP_FILE" "$IN_DIR" "$OUT_DIR" "$MODE" "$KEEP_RATIO" "$SEED" <<'PY'
import os, sys, time, random, re, subprocess, tempfile, math
from typing import Dict, Optional, Tuple, List

MAP_FILE, IN_DIR, OUT_DIR, MODE, KEEP_RATIO, SEED = sys.argv[1:]
KEEP_RATIO = float(KEEP_RATIO)
if not (0.0 < KEEP_RATIO < 1.0):
    raise SystemExit("KEEP_RATIO must be in (0,1), e.g. 0.2")

CLASS_NAMES = ['smart-static','sensor','audio','video','else']  # 0..4
NCLASS = 5

# ============== 与 set_features_ipv4only.sh 对齐的过滤条件 ==============
PROTO_OK = {1, 2, 6, 17}  # ICMP, IGMP, TCP, UDP
VLAN_ETYPES = {0x8100, 0x88A8, 0x9100}

seed = int(SEED)
rng = random.Random(seed if seed != 0 else time.time_ns())

def mac_str_to_bytes(mac: str) -> bytes:
    mac = mac.strip().lower().replace('-',':')
    mac = mac.replace(':','')
    return bytes.fromhex(mac)

# MAC -> label
mac2lab: Dict[bytes, int] = {}
with open(MAP_FILE, 'r', encoding='utf-8') as f:
    for raw in f:
        line = raw.split('#',1)[0].strip()
        if not line or '/' not in line:
            continue
        mac_s, lab_s = line.split('/',1)
        mac_s, lab_s = mac_s.strip(), lab_s.strip()
        if lab_s not in {'0','1','2','3','4'}:
            continue
        try:
            mac2lab[mac_str_to_bytes(mac_s)] = int(lab_s)
        except Exception:
            continue

def list_pcaps(root: str):
    out = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            lf = fn.lower()
            if lf.endswith('.pcap') or lf.endswith('.pcapng'):
                out.append(os.path.join(dirpath, fn))
    return out

files = list_pcaps(IN_DIR)
if not files:
    print(f"ERROR: no pcap/pcapng found in {IN_DIR}", file=sys.stderr)
    sys.exit(1)

# disk workload estimate
file_sizes = []
total_disk = 0
for p in files:
    try: sz = os.path.getsize(p)
    except: sz = 0
    file_sizes.append(sz)
    total_disk += sz

pairs = list(zip(files, file_sizes))
rng.shuffle(pairs)
files, file_sizes = zip(*pairs)

os.makedirs(OUT_DIR, exist_ok=True)

from scapy.utils import RawPcapReader, PcapWriter
try:
    from scapy.utils import RawPcapNgReader  # type: ignore
except Exception:
    RawPcapNgReader = None

def open_reader(path: str):
    low = path.lower()
    if low.endswith('.pcap'):
        return RawPcapReader(path), None
    if low.endswith('.pcapng') and RawPcapNgReader is not None:
        return RawPcapNgReader(path), None
    tmp = tempfile.NamedTemporaryFile(prefix="pcapng2pcap_", suffix=".pcap", delete=False)
    tmp.close()
    subprocess.run(["tshark","-n","-r",path,"-F","pcap","-w",tmp.name],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return RawPcapReader(tmp.name), tmp.name

def ethertype_and_l3off(pkt: bytes) -> Tuple[Optional[int], Optional[int]]:
    if len(pkt) < 14:
        return None, None
    et = int.from_bytes(pkt[12:14], 'big')
    off = 14
    while et in VLAN_ETYPES:
        if len(pkt) < off + 4:
            return None, None
        et = int.from_bytes(pkt[off+2:off+4], 'big')
        off += 4
    return et, off

def eligible(pkt: bytes) -> bool:
    et, ipoff = ethertype_and_l3off(pkt)
    if et != 0x0800 or ipoff is None:
        return False
    if len(pkt) < ipoff + 20:
        return False
    v_ihl = pkt[ipoff]
    if (v_ihl >> 4) != 4:
        return False
    ihl = (v_ihl & 0x0F) * 4
    if ihl < 20 or len(pkt) < ipoff + ihl:
        return False
    proto = pkt[ipoff + 9]
    return proto in PROTO_OK

def classify(pkt: bytes) -> int:
    if len(pkt) < 12:
        return 4
    dst = pkt[0:6]
    src = pkt[6:12]
    if MODE == 'src':
        return mac2lab.get(src, 4)
    if src in mac2lab:
        return mac2lab[src]
    if dst in mac2lab:
        return mac2lab[dst]
    return 4

# ---------------- Reservoir per class ----------------
# pool[c] 存储被选中的 packet bytes（会占内存：20% 的量）
pool: List[List[bytes]] = [[] for _ in range(NCLASS)]
seen = [0]*NCLASS  # 过滤后、按类计数

def maybe_take(c: int, pkt: bytes):
    """
    动态目标 k=floor(KEEP_RATIO * seen[c]) 的 reservoir sampling：
    - seen 递增后 k 可能增大：先补满到 k
    - 达到 k 后：对第 i 个元素（1-based），以 k/i 概率替换池中随机一个
    """
    seen[c] += 1
    i = seen[c]
    k = int(math.floor(KEEP_RATIO * i))
    if k <= 0:
        return
    if len(pool[c]) < k:
        pool[c].append(pkt)
        return
    # reservoir replace with prob k/i
    if rng.random() < (k / float(i)):
        j = rng.randrange(len(pool[c]))
        pool[c][j] = pkt

def fmt_bytes(n: float) -> str:
    units = ['B','KiB','MiB','GiB','TiB']
    i = 0
    while n >= 1024 and i < len(units)-1:
        n /= 1024.0
        i += 1
    return f"{n:.2f}{units[i]}" if i else f"{int(n)}B"

def fmt_time(sec: float) -> str:
    if sec < 0 or math.isinf(sec) or math.isnan(sec):
        return "?"
    sec = int(sec)
    h = sec // 3600
    m = (sec % 3600) // 60
    s = sec % 60
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def progress_line(i: int, total: int, cur_file: str, processed_disk: int, total_disk: int, t0: float):
    now = time.time()
    elapsed = now - t0
    frac = processed_disk / total_disk if total_disk > 0 else (i/total)
    rate = processed_disk / elapsed if elapsed > 0 else 0.0
    remain = max(total_disk - processed_disk, 0)
    eta = remain / rate if rate > 0 else float('inf')

    bar_w = 26
    filled = int(bar_w * frac)
    bar = "█"*filled + "░"*(bar_w-filled)

    fn = os.path.basename(cur_file)
    if len(fn) > 48:
        fn = fn[:20] + "..." + fn[-25:]

    # 显示每类：seen 与 当前pool大小（大约是 20%）
    usage = " ".join([f"{CLASS_NAMES[c]}:{len(pool[c])}/{seen[c]}" for c in range(NCLASS)])

    msg = (f"[{bar}] {frac*100:6.2f}%  "
           f"{i}/{total}  "
           f"read {fmt_bytes(processed_disk)}/{fmt_bytes(total_disk)}  "
           f"speed {fmt_bytes(rate)}/s  "
           f"elapsed {fmt_time(elapsed)}  ETA {fmt_time(eta)}  "
           f"file {fn}  |  {usage}")
    sys.stderr.write("\r" + msg + " " * 5)
    sys.stderr.flush()

t0 = time.time()
processed_disk = 0
total_files = len(files)
progress_line(0, total_files, files[0], 0, total_disk, t0)

# -------- pass: build reservoirs --------
for idx, (path, fsz) in enumerate(zip(files, file_sizes), start=1):
    reader, tmp_conv = open_reader(path)
    try:
        for pkt, meta in reader:
            if not eligible(pkt):
                continue
            c = classify(pkt)
            maybe_take(c, pkt)
    finally:
        reader.close()
        if tmp_conv:
            try: os.unlink(tmp_conv)
            except: pass

    processed_disk += int(fsz)
    progress_line(idx, total_files, path, processed_disk, total_disk, t0)

sys.stderr.write("\n")
sys.stderr.flush()

# -------- write outputs --------
out_paths = [os.path.join(OUT_DIR, f"{CLASS_NAMES[i]}.pcap") for i in range(NCLASS)]
writers = [PcapWriter(out_paths[i], append=False, sync=False) for i in range(NCLASS)]
try:
    for c in range(NCLASS):
        for pkt in pool[c]:
            writers[c].write(pkt)
finally:
    for w in writers:
        w.close()

print("DONE. Outputs:", file=sys.stderr)
for c in range(NCLASS):
    print(f"  {out_paths[c]}  kept={len(pool[c])} / seen={seen[c]}  (~{KEEP_RATIO*100:.1f}%)", file=sys.stderr)
PY