# CluBox4PDP — An Adaptive Anti-DDoS Method with Programmable Data Plane

> **Authors**: HankTheSniper (H4nkDASn1p3r)
>
> **Keywords**: DDoS Detection, Programmable Data Plane, Online Clustering, P4, DPDK, DBSCAN, Bounding Box

---

## Table of Contents

1. [Overview](#overview)
2. [Project Architecture](#project-architecture)
3. [Core Algorithm: CluBox](#core-algorithm-clubox)
4. [Repository Structure](#repository-structure)
5. [Subsystem 1: CluBox4PDP — DPDK Real-Time Detection](#subsystem-1-clubox4pdp--dpdk-real-time-detection)
6. [Subsystem 2: CSVFlowSimu — Offline Simulation & Validation](#subsystem-2-csvflowsimu--offline-simulation--validation)
7. [Key Design Decisions](#key-design-decisions)
8. [Build & Run](#build--run)
9. [Evaluation & Baselines](#evaluation--baselines)
10. [Output Artifacts](#output-artifacts)

---

## Overview

**CluBox4PDP** is an adaptive, flow-feature-based DDoS detection system designed for programmable data planes (P4/DPDK). Unlike traditional IP-identity-based approaches (heavy-hitter detection on source/destination IPs), CluBox4PDP operates on **flow behavioral features** — primarily **maximum packet length** and **maximum inter-arrival time (IAT)** — making it inherently robust against IP spoofing and distributed attacks.

### Key Innovations

| Aspect | Traditional Methods | CluBox4PDP |
|--------|-------------------|------------|
| **Detection Basis** | IP identity (heavy-hitter counting) | Flow behavioral features (pkt_len, IAT) |
| **Spoofing Resistance** | ❌ Fails under IP spoofing | ✅ Immune to IP spoofing |
| **Clustering** | None or offline | Online density-based clustering (DBSCAN → bounding boxes) |
| **Adaptivity** | Static thresholds | Dynamic reclustering on concept drift |
| **Classifier** | Rule-based | Combined spatial Decision Tree + meta Logistic Regression |
| **Target Platform** | Software/NetFlow | Programmable data plane (P4/DPDK) |

### Threat Model

The system targets **volumetric DDoS attacks** characterized by:
- **Large packets** (amplification/UDP flood style, 1100–1440 bytes)
- **Low inter-arrival times** (high-rate bursts, 50–800 µs between packets)

These two features form a 2D feature space where attack flows naturally cluster separately from benign traffic (which exhibits smaller packets and much larger IATs of 5,000–200,000 µs).

---

## Project Architecture

The project follows a two-phase research methodology:

```
┌─────────────────────────────────────────────────────────────────┐
│                     CluBox4PDP Project                          │
│                                                                 │
│  ┌──────────────────────┐          ┌──────────────────────────┐ │
│  │   CSVFlowSimu/        │          │   CluBox4PDP/             │ │
│  │   (Phase 1: Offline)  │  ────▶   │   (Phase 2: Online)       │ │
│  │                       │          │                          │ │
│  │  • Algorithm design   │          │  • DPDK real-time engine  │ │
│  │  • Parameter tuning   │          │  • Double-buffered model  │ │
│  │  • Feature validation │          │  • Pcap replay support    │ │
│  │  • Classifier training│          │  • Deployment-ready C code│ │
│  └──────────────────────┘          └──────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow (Online System)

```
PCAP File / NIC
      │
      ▼
┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  Dissector   │────▶│  Pseudo-Flow      │────▶│  Feature Extraction │
│  (Ethernet/  │     │  Table            │     │  (Max Pkt Len,      │
│   IP/TCP/UDP)│     │  (DPDK Hash)      │     │   Max IAT)          │
└─────────────┘     └──────────────────┘     └───────────────────┘
                                                      │
                                    ┌─────────────────▼─────────────────┐
                                    │   Per-Flow Box Classification      │
                                    │   checkPointBoxFloat() → box_id    │
                                    │   (Data Plane — fast path)         │
                                    └─────────────────┬─────────────────┘
                                                      │
                                    ┌─────────────────▼─────────────────┐
                                    │   Window Accumulation              │
                                    │   SAMPLE_WINDOW = 5000 flows       │
                                    │   Double buffer (slot 0/1)         │
                                    └─────────────────┬─────────────────┘
                                                      │
                                    ┌─────────────────▼─────────────────┐
                                    │   Control Plane (master core)      │
                                    │   • Check outlier rate             │
                                    │   • Trigger reclustering if needed │
                                    │   • Box scoring (DT + LR)          │
                                    │   • Update data plane model        │
                                    └──────────────────────────────────┘
```

---

## Core Algorithm: CluBox

### 1. Density-Based Clustering (FlowDBScan)

The algorithm is a **Manhattan-distance DBSCAN** variant optimized for online operation:

- **Distance metric**: Manhattan distance with early termination (`ESP = 20.0`)
- **MinPts**: 10 (minimum neighbors for core point)
- **Cluster representation**: Axis-aligned bounding boxes (not arbitrary shapes)
- **Output**: Each cluster becomes a **box** defined by `[min_f0, max_f0, min_f1, max_f1]`

```
Algorithm: FlowDBScanFloatPro (Optimized)
─────────────────────────────────────────
1. Compute all-pairs Manhattan distances (O(n²) but n=SAMPLE_WINDOW≈5000)
2. Pre-compute neighbor lists per point
3. BFS expansion from core points using explicit stack
4. For each cluster, compute axis-aligned bounding box
5. Ensure minimum box dimension (prevent degenerate boxes)
```

### 2. Feature Transformation

Raw features are transformed for better clustering behavior:

| Raw Feature | Transformation | Purpose |
|-------------|---------------|---------|
| Max Packet Length | `12.77 × x^0.3` | Compress range, normalize variance |
| Max IAT | `75 × log₁₀(x + 1)` | Log-scale for wide IAT range |

After clustering, boxes are **inverse-transformed** back to raw feature space for classification.

### 3. Box Classification (Two-Stage)

Each box is classified as benign or malicious using a **combined two-component classifier**:

#### Spatial Classifier (Decision Tree)

```c
// Key rule: UDP flood attack has max_IAT ≤ 5µs
if (box.max_IAT <= 5.00f)
    return 1.0f;  // malicious
return 0.0f;      // benign
```

#### Meta Classifier (Logistic Regression)

Uses 4 standardized features:
- `box_ratio` — fraction of window flows falling in this box
- `box_ratio²` — squared term (nonlinearity)
- `box_volume` — axis-aligned box volume in feature space
- `delta_points` — change in flow count from previous window

Combined score: `spatial_score + meta_score ≥ BOX_EVAL_THRESHOLD (1.0)` → **malicious**

### 4. Adaptive Reclustering

The system detects **concept drift** via outlier monitoring:

- If `outlier_count > SAMPLE_WINDOW × OUTLIER_THRESHOLD_RATE (8%)` → trigger reclustering
- Uses **double buffering**: one box model active for data plane, one being updated by control plane
- Box models are swapped atomically via DPDK ring message

### 5. Box Lifecycle Management

In the offline simulator (CSVFlowSimu), boxes have a **life counter** (`BOX_LIVES = 20`):
- Boxes with zero flows in a window lose one life
- Boxes at zero lives are deleted
- Boxes with sufficient flows regain full life
- This prevents stale clusters from accumulating

---

## Repository Structure

```
CluBox4PDP/
│
├── README.md                          # This document
├── CluBox4PDP An Adaptive Anti DDoS   # Research paper (PDF)
│   Methodwith Programmable Data
│   Plane.pdf
│
├── CluBox4PDP/                        # Phase 2: DPDK Online Detection System
│   ├── meson.build                    # Meson build configuration
│   ├── meson_options.txt              # Build options (pcap rate-limit)
│   │
│   ├── main.c                         # Entry point: port init, control plane loop
│   ├── clubox.h                       # CluBox clustering API & inline helpers
│   ├── clubox.c                       # CluBox clustering implementation
│   ├── pseudo_flow.h                  # Pseudo-flow table & feature extraction
│   ├── pseudo_flow.c                  # Flow management (DPDK hash table)
│   ├── dissectors.h                   # Packet dissector API
│   ├── dissectors.c                   # Ethernet/IP/TCP/UDP header parsing
│   ├── box_classifier.h               # Box classification interface
│   ├── box_classifier.c               # DT spatial + LR meta classifier
│   ├── stack.h                        # Sequential stack (for BFS clustering)
│   │
│   ├── gen_ddos_pcap.py               # Generate DDoS simulation PCAP
│   ├── gen_benign_pcap.py             # Generate benign-only PCAP
│   ├── train_classifier.py            # Train DT & LR from cluster_boxes CSV
│   ├── compare_baselines.py           # Compare vs Poseidon/Jaqen/ACC-Turbo
│   ├── calc_drop_reject.py            # Calculate rejection & drop rates
│   ├── plot_flow_comparison.py        # 1×4 flow comparison visualization
│   ├── plot_linerate_main.py          # Throughput comparison plot
│   └── plot_throughput_clubox.py      # Single-run throughput + latency plot
│
└── CSVFlowSimu/                       # Phase 1: Offline Simulation & Validation
    ├── main.c                         # Simulator entry point
    │
    ├── clubox/                        # Clustering library (Windows-compatible)
    │   ├── clubox.h                   # Full CluBox API (DBSCAN variants)
    │   ├── clubox.c                   # FlowDBScan*, box ops, classifier
    │   └── stack.h                    # Sequential stack (2M capacity)
    │
    ├── simu/                          # Traffic simulation framework
    │   ├── simu.h                     # Data loading, sampling, slicing API
    │   └── simu.c                     # CSV parsing, sampling, slice management
    │
    └── data/                          # Data processing pipeline
        ├── data_original/             # Raw CSV flow data
        │   └── heads_space_delete.py  # CSV header cleaner
        ├── clean_samples.py           # Feature extraction & sampling
        ├── data_processed/            # Processed CSV files
        └── result/                    # Visualization & analysis
            ├── cm/
            │   └── draw_cm.py         # Confusion matrix visualization
            ├── draw_label_points.py   # Ground truth scatter plots
            └── purity.py              # Cluster purity analysis
```

---

## Subsystem 1: CluBox4PDP — DPDK Real-Time Detection

### Overview

The production-ready online detection system built on **DPDK** (Data Plane Development Kit). It processes packets at line rate, extracts flow features from the first 3 packets of each flow, classifies flows using the CluBox bounding-box model, and adaptively reclusters when traffic patterns change.

### Key Components

#### Packet Dissector (`dissectors.c`)
- Parses Ethernet (including VLAN), IPv4, IPv6, TCP, and UDP headers
- Extracts 5-tuple flow key: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Supports pcap timestamp extraction via DPDK dynamic fields

#### Pseudo-Flow Table (`pseudo_flow.c`)
- DPDK `rte_hash` based flow table (configurable size, default 64K entries)
- Maintains per-flow state: 3 packet lengths, 3 timestamps
- **Feature extraction** from first 3 packets of each flow:
  - `feature[0]` = max packet length among first 3 packets
  - `feature[1]` = max inter-arrival time among first 3 packets
- Completed flows are immediately removed to allow re-sampling on pcap replay
- Aged flows (>5 seconds timeout) are flushed with partial data

#### Double-Buffered Window System
- Two sample buffers (`feature_sample_flat[0]` and `[1]`) collect 5,000 flows each
- When a buffer fills, the data plane signals the control plane via `feature_ring`
- The control plane processes one buffer while the data plane fills the other
- `processing_lock` prevents race conditions between reclustering and classification

#### Control Plane (`main.c`)
- Polls `feature_ring` for completed windows
- On recluster signal: runs `CluBoxFloat()` → box scoring → swaps active model
- On stats-only signal: maps flows to existing boxes → updates statistics
- Outputs per-window CSV files:
  - `sample_clusters_N.csv` — per-flow box assignments
  - `cluster_boxes_N.csv` — per-box features, scores, labels
  - `timing.csv` — clustering & evaluation latency
  - `results.csv` — confusion matrix & throughput

### Configuration Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SAMPLE_WINDOW` | 5000 | Flows per evaluation window |
| `FEATURE_DIM` | 2 | (max_pkt_len, max_IAT) |
| `PKT_COUNT` | 3 | Packets to observe per flow |
| `ESP` | 20.0 | Epsilon for DBSCAN distance |
| `MINPTS` | 10 | Minimum points for core |
| `MAX_CLUSTER` | 50 | Maximum boxes |
| `OUTLIER_THRESHOLD_RATE` | 8% | Trigger reclustering |
| `BOX_EVAL_THRESHOLD` | 1.0 | Malicious score threshold |

---

## Subsystem 2: CSVFlowSimu — Offline Simulation & Validation

### Overview

A Windows-based offline simulator for rapid algorithm prototyping, parameter tuning, and classifier training. It reads CSV flow data, simulates time-sliced traffic patterns, applies the CluBox algorithm, and evaluates detection performance.

### Key Differences from Online System

| Aspect | CSVFlowSimu (Offline) | CluBox4PDP (Online) |
|--------|----------------------|---------------------|
| Platform | Windows (MSVC/MinGW) | Linux + DPDK |
| Data Source | Pre-collected CSV files | Live NIC / PCAP replay |
| Clustering Trigger | Fixed interval (5,000 flows) | Adaptive (outlier rate > 8%) |
| Box Lifecycle | Life counter + deletion | Replace on recluster |
| Feature Norm | `12.77 × x^0.3` / `75 × log₁₀(x+1)` | Same transform, applied per-window |
| Memory Model | Heap (`malloc/calloc`) | DPDK hugepages (`rte_malloc`) |

### Traffic Slicing Scheme

The simulator uses a **letter-based traffic composition language**:

```
Input:  aaaaa/aaab/aaabbb/abbbbbb/bbbbbbbbbb/bbbbbbbbbb/aaab/aaaaa

  a = BENIGN class    b = DDoS class
  / = time slice boundary
  Repeat count = number of flows × TRAFFIC_SAMPLE_RATE
```

This models:
1. Benign stable (aaaaa)
2. Attack ramp-up (aaab → aaabbb → abbbbbb)
3. Sustained attack (bbbbbbbbbb)
4. Attack taper (aaab → aaaaa)

### DBSCAN Variants

| Function | Description |
|----------|-------------|
| `FlowDBScanFloat` | Basic DBSCAN, O(n²) per BFS neighbor check |
| `FlowDBScanFloatPro` | Optimized: pre-computed neighbor lists, faster BFS |
| `FlowDBScanFloatFast` | Flat-array variant (for DPDK data layout) |
| `FlowDBScanInt` | Integer feature variant |

### Classifier Training Pipeline

1. Run CSVFlowSimu to generate `cluster_boxes_*.csv` files
2. Use `train_classifier.py` to train:
   - **Decision Tree** (max_depth=5) on spatial features `[min_f0, max_f0, min_f1_us, max_f1_us]`
   - **Logistic Regression** on meta features `[box_ratio, box_ratio², box_volume, delta_points]`
3. Copy trained weights into `box_classifier.c` (for DPDK system)

---

## Key Design Decisions

### Why Manhattan Distance?

Manhattan distance (L1) was chosen over Euclidean (L2) for clustering because:
- **Computational efficiency**: No square root; just absolute differences
- **Early termination**: Can abort as soon as accumulated distance exceeds EPS
- **Axis-aligned box compatibility**: Clusters naturally form axis-aligned bounding boxes

### Why 3 Packets Per Flow?

Observing 3 packets balances:
- **Detection latency**: 3 packets is enough to capture max length and IAT
- **Memory efficiency**: 3 × (2 bytes len + 8 bytes timestamp) ≈ 30 bytes per flow entry
- **Statistical sufficiency**: DDoS flows show distinctive patterns within the first 3 packets

### Why Double Buffering?

The double-buffered box model design ensures:
- **Zero data-plane stall**: Classification uses the current model without locks
- **Atomic model swap**: Data plane reads a pointer; control plane writes the inactive buffer
- **Consistent per-window evaluation**: Each window uses a single model version

### Why Feature Transformation?

Raw packet lengths (64–1514) and IATs (0–200,000 µs) span orders of magnitude. The power-law and log transforms:
- **Normalize variance** across the feature range
- **Compact dense regions** for more meaningful clustering
- **Inverse-transformed back** for interpretable box boundaries

---

## Build & Run

### CluBox4PDP (DPDK Online System)

**Prerequisites**:
- Linux with DPDK 22.11+ installed
- Meson build system
- libpcap development headers

```bash
cd CluBox4PDP/

# Configure (training mode with pcap rate-limit)
meson setup build
meson configure -Dpcap_ratelimit=true build
ninja -C build

# Run with pcap replay
sudo build/xpkt_clubox -l 0,1 \
    --vdev 'eth_pcap0,rx_pcap=ddos_sim.pcap' --

# Run without rate-limit (deployment mode)
meson configure -Dpcap_ratelimit=false build
ninja -C build
```

### Generate Test Traffic

```bash
# Single-source DDoS (fixed attacker IP)
python3 gen_ddos_pcap.py --mode single

# Distributed DDoS (50k spoofed sources, 200 victims)
python3 gen_ddos_pcap.py --mode distributed

# Pure benign traffic (throughput baseline)
python3 gen_benign_pcap.py --flows 150000
```

### CSVFlowSimu (Offline Simulator)

**Prerequisites**:
- Windows with MinGW or MSVC
- Python 3 with pandas, numpy, matplotlib, scikit-learn, seaborn

```bash
cd CSVFlowSimu/

# Compile
gcc -O2 main.c clubox/clubox.c simu/simu.c -o csvflowsimu -lm

# Run
./csvflowsimu

# Input traffic pattern when prompted:
# e.g.: aaaaa/aaab/aaabbb/abbbbbb/bbbbbbbbbb/bbbbbbbbbb/aaab/aaaaa
```

### Train Classifier from Output

```bash
cd CluBox4PDP/
python3 train_classifier.py --threshold 0.5 --max-depth 5
# Copy printed C code into box_classifier.c
```

---

## Evaluation & Baselines

The system is evaluated against **three state-of-the-art baselines**:

| System | Venue | Method | Vulnerability |
|--------|-------|--------|---------------|
| **Poseidon** | NDSS 2020 | Source-IP heavy-hitter detection | ❌ IP spoofing |
| **Jaqen** | USENIX Security 2021 | Bidirectional heavy-hitter + fan-out | ❌ Distributed victims |
| **ACC-Turbo** | SIGCOMM 2022 | Destination-prefix aggregate rate | ❌ Multi-subnet victims |
| **CluBox4PDP** | This work | Flow-feature online clustering | ✅ None of the above |

### Evaluation Scenarios

#### Scenario 1: Single-Source DDoS
- Fixed attacker: `192.168.50.1 → 10.0.0.100` (UDP flood)
- **All systems detect** (trivial heavy-hitter)
- CluBox4PDP validates baseline performance

#### Scenario 2: Distributed DDoS
- 50,000 spoofed source IPs (public internet ranges)
- 200 victim IPs across 200 different `/24` subnets (`198.x.x.x`)
- **Only CluBox4PDP detects** — all baselines fail because:
  - Poseidon: no single source exceeds rate threshold
  - Jaqen: no single destination exceeds rate threshold
  - ACC-Turbo: no single `/24` aggregate exceeds rate threshold

### Metrics

| Metric | Definition |
|--------|-----------|
| **TP** | Attack flow correctly classified as malicious |
| **TN** | Benign flow correctly classified as benign |
| **FP** | Benign flow incorrectly classified as malicious |
| **FN** | Attack flow incorrectly classified as benign |
| **Attack Rejection Rate** | TP / (TP + FN) — recall for attack class |
| **Benign Drop Rate** | FP / (TN + FP) — false positive rate |
| **Throughput** | Mpps / Gbps processed |
| **Clustering Latency** | µs per reclustering operation |

### Running Comparisons

```bash
# After a DPDK run produces output_YYYYMMDD_HHMMSS/
python3 compare_baselines.py output_YYYYMMDD_HHMMSS --mode distributed --plot --csv results_distributed.csv
python3 calc_drop_reject.py output_YYYYMMDD_HHMMSS --mode distributed

# Plot results
python3 plot_flow_comparison.py results_distributed.csv --out comparison_flows.png
python3 plot_throughput_clubox.py output_YYYYMMDD_HHMMSS
python3 plot_linerate_main.py --out linerate_combined.png
```

---

## Output Artifacts

Each DPDK run produces a timestamped output directory:

```
output_YYYYMMDD_HHMMSS/
├── sample_clusters_0.csv    # Per-flow: src_ip,dst_ip,sport,dport,proto,feature1,feature2,box_id
├── cluster_boxes_0.csv      # Per-box: min/max features, points, volume, attack ratio, score, label
├── sample_clusters_1.csv    # (window 1)
├── cluster_boxes_1.csv
├── ...
├── timing.csv               # window_id, cluster_us, eval_us, total_us, box_count, is_recluster
└── results.csv              # window_id, cm_tp, cm_tn, cm_fp, cm_fn, mpps, gbps
```

CSVFlowSimu outputs to:
```
CSVFlowSimu/data/result/
├── cm/cm.csv                # Per-slice confusion matrices + aggregate
└── new_result/
    ├── *_dbscan_*_points.csv # Per-point cluster assignments
    └── *_dbscan_*_boxes.csv  # Box definitions
```

---

## Citation

If you use this code in your research, please cite:

```bibtex
@misc{clubox4pdp,
  author = {HankTheSniper},
  title  = {CluBox4PDP: An Adaptive Anti-DDoS Method with Programmable Data Plane},
  year   = {2026},
  note   = {https://github.com/HankTheSniper/CluBox4PDP}
}
```

## License

This project is provided for academic and research purposes. See the repository for license details.
