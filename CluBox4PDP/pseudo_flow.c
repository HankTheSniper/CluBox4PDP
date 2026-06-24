#include <rte_mbuf_dyn.h>
#include "dissectors.h"
#include "clubox.h"
#include "pseudo_flow.h"

uint32_t total_flow_count = 0;
volatile uint64_t total_drop_count = 0;
static uint32_t outlier_flow_count = 0;

uint64_t g_window_pkt_snap[2]  = {0, 0};
uint64_t g_window_byte_snap[2] = {0, 0};
static uint64_t s_window_pkt  = 0;
static uint64_t s_window_byte = 0;

/* Attack IP in host byte order: 192.168.50.1 */
#define ATTACK_IP_HBO  RTE_IPV4(192, 168, 50, 1)

static inline int is_attack_flow(const struct flow_key *k)
{
    uint32_t s = rte_be_to_cpu_32(k->src_ip);
    uint32_t d = rte_be_to_cpu_32(k->dst_ip);
    return (s == ATTACK_IP_HBO || d == ATTACK_IP_HBO);
}

float feature_sample_flat[2][SAMPLE_WINDOW * FEATURE_DIM] __attribute__((aligned(64)));;
struct flow_key key_sample_flat[2][SAMPLE_WINDOW];
float sample_time[2];
uint8_t active_index = 0;

uint64_t curr_time;
uint64_t prev_time;

uint32_t box_points_atomic[MAX_CLUSTER];

static struct rte_hash *flow_table = NULL;
static struct box_model **model_ref = NULL;

struct rte_ring *feature_ring = NULL;

uint8_t processing_lock = 0;

int init_pseudo_flow_table(uint32_t max_entries)
{
    struct rte_hash_parameters params = {
        .name = "pseudo_flow_table",
        .entries = max_entries,
        .key_len = sizeof(struct flow_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = (int)rte_socket_id(),
    };

    flow_table = rte_hash_create(&params);
    if (flow_table == NULL) {
        return -1;
    }
    return 0;
}

void set_box_model_reference(struct box_model **ref)
{
    model_ref = ref;
}

/* Dynamic field registered by rte_mbuf_dyn_rx_timestamp_register().
 * Populated by the pcap PMD when RTE_ETH_RX_OFFLOAD_TIMESTAMP is enabled. */
static int     ts_dynfield_offset = -1;
static uint64_t ts_dynflag        = 0;

void init_timestamp_dynfield(void)
{
    int ret = rte_mbuf_dyn_rx_timestamp_register(&ts_dynfield_offset, &ts_dynflag);
    if (ret == 0)
        printf("[pseudo_flow] pcap timestamp dynfield registered (offset=%d)\n",
               ts_dynfield_offset);
    else
        printf("[pseudo_flow] timestamp dynfield unavailable, IAT uses TSC\n");
}

/* Returns packet arrival time in microseconds.
 * Uses pcap header timestamp (via dynamic field) when available so that
 * replay at any speed produces correct IAT values.
 * Falls back to TSC-derived wall-clock time for live NIC capture. */
static inline uint64_t get_ts_us(struct rte_mbuf *m)
{
    if (ts_dynfield_offset >= 0 && (m->ol_flags & ts_dynflag)) {
        rte_mbuf_timestamp_t ts =
            *RTE_MBUF_DYNFIELD(m, ts_dynfield_offset, rte_mbuf_timestamp_t *);
        return (uint64_t)(ts / 1000);   /* nanoseconds → microseconds */
    }
    return rte_rdtsc() * 1000000ULL / rte_get_tsc_hz();
}

void process_packet_features(struct rte_mbuf *m, struct dissector_result *res)
{
    struct flow_key key = {0};
    struct pseudo_flow *data = NULL;

    s_window_pkt++;
    s_window_byte += rte_pktmbuf_pkt_len(m);

    uint32_t s_ip = res->ipv4_hdr->src_addr;
    uint32_t d_ip = res->ipv4_hdr->dst_addr;
    uint16_t s_port = 0, d_port = 0;

    if (res->tcp_hdr) 
    {
        s_port = res->tcp_hdr->src_port;
        d_port = res->tcp_hdr->dst_port;
    } 
    else if (res->udp_hdr) 
    {
        s_port = res->udp_hdr->src_port;
        d_port = res->udp_hdr->dst_port;
    } 
    else
    {
        return;
    }

    if (s_ip < d_ip || (s_ip == d_ip && s_port < d_port)) 
    {
        key.src_ip = s_ip; key.dst_ip = d_ip;
        key.src_port = s_port; key.dst_port = d_port;
    } 
    else 
    {
        key.src_ip = d_ip; key.dst_ip = s_ip;
        key.src_port = d_port; key.dst_port = s_port;
    }
    key.proto = res->ipv4_hdr->next_proto_id;

    int ret = rte_hash_lookup_data(flow_table, &key, (void **)&data);
    if (ret < 0) {
        data = rte_zmalloc("flow_data", sizeof(struct pseudo_flow), 0);
        if (!data) return;
        rte_hash_add_key_data(flow_table, &key, data);
    }

    data->last_ts = rte_rdtsc();
    if (data->count < PKT_COUNT)
    {
        uint16_t pkt_len = (uint16_t)rte_pktmbuf_pkt_len(m);
        if (pkt_len > 1514) pkt_len = 1514;
        if (pkt_len < 64) return;
        data->lens[data->count] = pkt_len;
        data->tscs[data->count] = get_ts_us(m);  /* microseconds: pcap ts or TSC-derived */
        if(data->count == 0) {
            data->features[0] = data->lens[0];
            data->features[1] = 0;
            // data->features[2] = data->lens[0];
        }
        else {
            data->features[0] = (data->lens[data->count] > data->features[0]) ? data->lens[data->count] : data->features[0];
            // data->features[2] = (data->lens[data->count] < data->features[2]) ? data->lens[data->count] : data->features[2];
            int iat_us = (int)(data->tscs[data->count] - data->tscs[data->count - 1]);
            data->features[1] = (iat_us > data->features[1]) ? iat_us : data->features[1];
        }
        data->count++;

        if (data->count == PKT_COUNT)
        {
            // data->features[2] = data->features[0] - data->features[2];
            struct box_model *current = *model_ref;
            float feature_array[FEATURE_DIM];
            for(int i = 0; i < FEATURE_DIM; i++)
            {
                feature_array[i] = (float)data->features[i];
                feature_sample_flat[active_index][total_flow_count * FEATURE_DIM + i] = (float)data->features[i];
            }
            key_sample_flat[active_index][total_flow_count] = key;
            int box_id = checkPointBoxFloat(feature_array, current->boxes, current->order_index, FEATURE_DIM, current->box_count);
            /* remove completed flow so it can be re-sampled on next pcap loop */
            rte_hash_del_key(flow_table, &key);
            rte_free(data);
            data = NULL;
            // printf("[Flow Detect] Pkts:3 | Features: [%d, %d] | BoxID: %d\n", data->features[0], data->features[1], box_id);
            __atomic_fetch_add(&total_flow_count, 1, __ATOMIC_RELAXED);
            if(box_id == -1)
            {
                __atomic_fetch_add(&outlier_flow_count, 1, __ATOMIC_RELAXED);
                /* if majority of boxes are malicious, treat outlier as attack */
                if (current->box_count > 0) {
                    int mal_cnt = 0;
                    for (int bi = 0; bi < current->box_count; bi++)
                        mal_cnt += current->box_labels[bi];
                    if (mal_cnt * 2 > current->box_count)
                        __atomic_fetch_add(&total_drop_count, 1, __ATOMIC_RELAXED);
                }
            }
            else
            {
                __atomic_fetch_add(&box_points_atomic[box_id], 1, __ATOMIC_RELAXED);
                if(is_attack_flow(&key))
                    __atomic_fetch_add(&current->box_attack_count[box_id], 1, __ATOMIC_RELAXED);
                else
                    __atomic_fetch_add(&current->box_benign_count[box_id], 1, __ATOMIC_RELAXED);
                if(current->box_labels[box_id] == 1)
                    __atomic_fetch_add(&total_drop_count, 1, __ATOMIC_RELAXED);
            }
            if(total_flow_count >= SAMPLE_WINDOW)
            {
                printf("Reach the sample window. Outlier flows: %u\n", outlier_flow_count);
                curr_time = rte_rdtsc();
                sample_time[active_index] = (float)(curr_time - prev_time) / (float)rte_get_tsc_hz();
                prev_time = curr_time;
                for(int i = 0; i < current->box_count; i++)
                {
                    box_points_atomic[i] = 0;
                }
                total_flow_count = 0;
                if(!processing_lock)
                {
                    processing_lock = 1;
                    uint8_t ready_idx = active_index;
                    uint8_t do_recluster = ((float)outlier_flow_count >
                        (float)SAMPLE_WINDOW * OUTLIER_THRESHOLD_RATE) ? 1 : 0;
                    uintptr_t msg_val = (uintptr_t)(ready_idx | (do_recluster << 1));
                    g_window_pkt_snap[ready_idx]  = s_window_pkt;
                    g_window_byte_snap[ready_idx] = s_window_byte;
                    s_window_pkt = 0; s_window_byte = 0;
                    rte_ring_enqueue(feature_ring, (void *)msg_val);
                    active_index = 1 - active_index;
                }
                else if (rte_ring_count(feature_ring) == 0)
                {
                    /* control plane is clustering (took msg, ring now empty);
                     * enqueue stats-only on the other buffer — no recluster */
                    uint8_t ready_idx = active_index;
                    uintptr_t msg_val = (uintptr_t)(ready_idx | 0);
                    g_window_pkt_snap[ready_idx]  = s_window_pkt;
                    g_window_byte_snap[ready_idx] = s_window_byte;
                    s_window_pkt = 0; s_window_byte = 0;
                    if (rte_ring_enqueue(feature_ring, (void *)msg_val) == 0)
                        active_index = 1 - active_index;
                }
                /* else: ring still has a pending msg, drop this overflow window */
                outlier_flow_count = 0;
            }
        }
    }
}

void cleanup_timeout_flows(void)
{
    const void *next_key;
    void *next_data;
    uint32_t iter = 0;
    uint64_t now = rte_rdtsc();
    uint64_t timeout_cycles = 5 * rte_get_tsc_hz(); 

    const void *keys_to_del[32]; 
    int to_del_count = 0;

    while (rte_hash_iterate(flow_table, &next_key, &next_data, &iter) >= 0)
    {
        struct pseudo_flow *data = (struct pseudo_flow *)next_data;
        
        if (now - data->last_ts > timeout_cycles)
        {
            if(data->count < PKT_COUNT)
            {
                // data->features[2] = data->features[0] - data->features[2];
                struct box_model *current = *model_ref;
                float feature_array[FEATURE_DIM];
                for(int i = 0; i < FEATURE_DIM; i++)
                {
                    feature_array[i] = (float)data->features[i];
                    feature_sample_flat[active_index][total_flow_count * FEATURE_DIM + i] = (float)data->features[i];
                }
                const struct flow_key *current_key = (const struct flow_key *)next_key;
                key_sample_flat[active_index][total_flow_count] = *current_key;
                int box_id = checkPointBoxFloat(feature_array, current->boxes, current->order_index, FEATURE_DIM, current->box_count);
                // printf("[Flow Aged] Pkts:%d | Features: [%d, %d] | BoxID: %d\n", data->count, data->features[0], data->features[1], box_id);
                __atomic_fetch_add(&total_flow_count, 1, __ATOMIC_RELAXED);
                if(box_id == -1)
                {
                    __atomic_fetch_add(&outlier_flow_count, 1, __ATOMIC_RELAXED);
                    /* if majority of boxes are malicious, treat outlier as attack */
                    if (current->box_count > 0) {
                        int mal_cnt = 0;
                        for (int bi = 0; bi < current->box_count; bi++)
                            mal_cnt += current->box_labels[bi];
                        if (mal_cnt * 2 > current->box_count)
                            __atomic_fetch_add(&total_drop_count, 1, __ATOMIC_RELAXED);
                    }
                }
                else
                {
                    __atomic_fetch_add(&box_points_atomic[box_id], 1, __ATOMIC_RELAXED);
                    if(is_attack_flow(current_key))
                        __atomic_fetch_add(&current->box_attack_count[box_id], 1, __ATOMIC_RELAXED);
                    else
                        __atomic_fetch_add(&current->box_benign_count[box_id], 1, __ATOMIC_RELAXED);
                    if(current->box_labels[box_id] == 1)
                        __atomic_fetch_add(&total_drop_count, 1, __ATOMIC_RELAXED);
                }
                if(total_flow_count >= SAMPLE_WINDOW)
                {
                    printf("Reach the sample window. Outlier flows: %u\n", outlier_flow_count);
                    curr_time = rte_rdtsc();
                    sample_time[active_index] = (float)(curr_time - prev_time) / (float)rte_get_tsc_hz();
                    prev_time = curr_time;
                    for(int i = 0; i < current->box_count; i++)
                    {
                        box_points_atomic[i] = 0;
                    }
                    total_flow_count = 0;
                    if(!processing_lock)
                    {
                        processing_lock = 1;
                        uint8_t ready_idx = active_index;
                        uint8_t do_recluster = ((float)outlier_flow_count >
                            (float)SAMPLE_WINDOW * OUTLIER_THRESHOLD_RATE) ? 1 : 0;
                        uintptr_t msg_val = (uintptr_t)(ready_idx | (do_recluster << 1));
                        g_window_pkt_snap[ready_idx]  = s_window_pkt;
                        g_window_byte_snap[ready_idx] = s_window_byte;
                        s_window_pkt = 0; s_window_byte = 0;
                        rte_ring_enqueue(feature_ring, (void *)msg_val);
                        active_index = 1 - active_index;
                    }
                    else if (rte_ring_count(feature_ring) == 0)
                    {
                        uint8_t ready_idx = active_index;
                        uintptr_t msg_val = (uintptr_t)(ready_idx | 0);
                        g_window_pkt_snap[ready_idx]  = s_window_pkt;
                        g_window_byte_snap[ready_idx] = s_window_byte;
                        s_window_pkt = 0; s_window_byte = 0;
                        if (rte_ring_enqueue(feature_ring, (void *)msg_val) == 0)
                            active_index = 1 - active_index;
                    }
                    outlier_flow_count = 0;
                }
            }
            keys_to_del[to_del_count++] = next_key;
            rte_free(data);
            if(to_del_count == 32) {
                for(int i = 0; i < to_del_count; i++)
                {
                    rte_hash_del_key(flow_table, keys_to_del[i]);
                }
                to_del_count = 0;
            }
            
        }
    }
    if(to_del_count > 0)
    {
        for(int i = 0; i < to_del_count; i++)
        {
            rte_hash_del_key(flow_table, keys_to_del[i]);
        }
    }
}