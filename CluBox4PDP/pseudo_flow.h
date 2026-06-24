#ifndef __PSEUDO_FLOW_H
#define __PSEUDO_FLOW_H

#include <stdint.h>
#include <rte_common.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_cycles.h>
#include <rte_ring.h>

#include "clubox.h"

#define PKT_COUNT 3
#define FEATURE_DIM 2

#define SAMPLE_WINDOW 5000
#define OUTLIER_THRESHOLD_RATE (2.0f / 25.0f)

extern uint32_t total_flow_count;
extern volatile uint64_t total_drop_count;

/* per-window throughput snapshots (indexed by buffer slot 0/1) */
extern uint64_t g_window_pkt_snap[2];
extern uint64_t g_window_byte_snap[2];

extern struct rte_ring *feature_ring;
extern float feature_sample_flat[2][SAMPLE_WINDOW * FEATURE_DIM] __attribute__((aligned(64)));;

extern uint32_t box_points_atomic[MAX_CLUSTER];

extern float sample_time[2];

extern uint64_t curr_time;
extern uint64_t prev_time;

extern uint8_t processing_lock;

struct box_model; 
struct dissector_result;
struct rte_mbuf;

struct flow_key
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} __rte_packed;

extern struct flow_key key_sample_flat[2][SAMPLE_WINDOW];

struct pseudo_flow
{
    uint16_t lens[PKT_COUNT];
    uint64_t tscs[PKT_COUNT];

    uint64_t last_ts;
    uint8_t  count;

    int features[FEATURE_DIM];
};

void init_timestamp_dynfield(void);
void set_box_model_reference(struct box_model **ref);
int init_pseudo_flow_table(uint32_t size);
void process_packet_features(struct rte_mbuf *m, struct dissector_result *res);
void cleanup_timeout_flows(void);

#endif /* __PSEUDO_FLOW_H */