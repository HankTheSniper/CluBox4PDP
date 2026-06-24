#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_cycles.h>

#include "pseudo_flow.h"
#include "clubox.h"
#include "dissectors.h"
#include "box_classifier.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN }
};

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 1, tx_rings = 1;
    struct rte_eth_dev_info dev_info;
    int retval;
    uint16_t q;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) return retval;
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TIMESTAMP) {
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_TIMESTAMP;
        printf("Port %u: pcap timestamp offload enabled\n", port);
    }

    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) return retval;

    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
                rte_eth_dev_socket_id(port), NULL);
        if (retval < 0) return retval;
    }

    retval = rte_eth_dev_start(port);
    // if (retval < 0) return retval;
    if (retval < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", retval, port);

    rte_eth_promiscuous_enable(port);
    printf("Promiscuous mode enabled on port %u\n", port);
    return 0;
}

static __rte_noreturn int
lcore_main(void *arg)
{
    uint16_t port;

    uint64_t prev_tsc = 0;
    uint64_t cur_tsc;

    const uint64_t drain_tsc = rte_get_tsc_hz();

    void *msg = NULL;

    printf("Core %u forwarding packets.\n", rte_lcore_id());

    for (;;) {
        if (rte_ring_dequeue(box_ring, &msg) == 0)
        {
            int box_model_idx = (int)(uintptr_t)msg;
            set_box_model_reference(getBoxModelReference(box_model_idx));
            processing_lock = 0;
            printf("[Data Plane] Switched to box model index %d for flow processing.\n", box_model_idx);
        }

        cur_tsc = rte_rdtsc();
        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            cleanup_timeout_flows();
            prev_tsc = cur_tsc;
        }
        RTE_ETH_FOREACH_DEV(port) {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

            if (unlikely(nb_rx == 0)) continue;

            for (int i = 0; i < nb_rx; i++) {
                struct dissector_result res = {0};
                dissector_dissect(bufs[i], &res);
                if (res.ipv4_hdr != NULL) {
                    process_packet_features(bufs[i], &res);
                }

                rte_pktmbuf_free(bufs[i]);
            }
#ifdef PCAP_REPLAY_RATELIMIT
            rte_delay_us_block(1000); /* rate-limit pcap replay to ~32K pkt/s */
#endif
        }
    }
}

int
main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    uint16_t portid;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    init_timestamp_dynfield();  /* must be before mbuf pool creation */

    feature_ring = rte_ring_create("FEATURE_MSG_RING", 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    box_ring = rte_ring_create("BOX_MSG_RING", 1024, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    if (feature_ring == NULL || box_ring == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot create output ring\n");
    }

    if (init_pseudo_flow_table(1024 * 64) < 0) {
        rte_exit(EXIT_FAILURE, "Cannot init flow table\n");
    }

    initBoxes();
    set_box_model_reference(getBoxModelReference(active_box_model));

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    RTE_ETH_FOREACH_DEV(portid)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16"\n", portid);

    unsigned int lcore_id = rte_get_next_lcore(rte_lcore_id(), 1, 0);
    if (lcore_id == RTE_MAX_LCORE) {
        rte_exit(EXIT_FAILURE, "No slave core available. Check your -l parameter.\n");
    }
    curr_time = rte_rdtsc();
    prev_time = curr_time;
    rte_eal_remote_launch(lcore_main, NULL, lcore_id);
    printf("Data plane launched on lcore %u. Master core is free.\n", lcore_id);
    printf("[Control Plane] Master core %u is now polling for re-cluster signals...\n", rte_lcore_id());
    uint64_t prev_tsc_meta = 0;
    float feature_temp[SAMPLE_WINDOW * FEATURE_DIM] = {0};
    int *points_box = (int *)calloc(SAMPLE_WINDOW, sizeof(int));
    int re_cluster_count = 0;
    uint64_t cur_tsc;

    /* Create a per-experiment output directory named by start timestamp */
    char out_dir[64];
    {
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        strftime(out_dir, sizeof(out_dir), "output_%Y%m%d_%H%M%S", tm);
        if (mkdir(out_dir, 0755) != 0)
            rte_exit(EXIT_FAILURE, "Cannot create output directory '%s'\n", out_dir);
        printf("[Control Plane] Output directory: %s/\n", out_dir);
    }

    char timing_path[128];
    snprintf(timing_path, sizeof(timing_path), "%s/timing.csv", out_dir);
    FILE *f_timing = fopen(timing_path, "w");
    if (f_timing == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create timing file\n");
    fprintf(f_timing, "window_id,cluster_us,eval_us,total_us,box_count,is_recluster\n");
    fflush(f_timing);

    char results_path[128];
    snprintf(results_path, sizeof(results_path), "%s/results.csv", out_dir);
    FILE *f_results = fopen(results_path, "w");
    if (f_results == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create results file\n");
    fprintf(f_results, "window_id,cm_tp,cm_tn,cm_fp,cm_fn,mpps,gbps\n");
    fflush(f_results);

    uint64_t tsc_hz = rte_get_tsc_hz();

    while(1)
    {
        cur_tsc = rte_rdtsc();
        void *msg = NULL;
        char file_name[128];
        if (rte_ring_dequeue(feature_ring, &msg) == 0)
        {
            uintptr_t msg_val    = (uintptr_t)msg;
            uint8_t buf_idx      = (uint8_t)(msg_val & 0x1);
            int should_recluster = (int)((msg_val >> 1) & 0x1);

            printf("[Control Plane] Window %d: batch=%u %s\n",
                   re_cluster_count, buf_idx,
                   should_recluster ? "RECLUSTER" : "stats-only");

            uint64_t tsc_start = rte_rdtsc();

            /* always normalize features (needed for sample_clusters CSV) */
            for (int i = 0; i < SAMPLE_WINDOW; i++) {
                feature_temp[i * FEATURE_DIM + 0] = feature_sample_flat[buf_idx][i * FEATURE_DIM + 0];
                feature_temp[i * FEATURE_DIM + 1] = 75 * log10(feature_sample_flat[buf_idx][i * FEATURE_DIM + 1] + 1.0f);
            }

            if (should_recluster) {
                active_box_model = 1 - active_box_model;
                memset(local_box_model[active_box_model]->box_points, 0, MAX_CLUSTER * sizeof(int));
                local_box_model[active_box_model]->box_count = CluBoxFloat(
                    feature_temp, SAMPLE_WINDOW, FEATURE_DIM, points_box,
                    local_box_model[active_box_model]->boxes,
                    local_box_model[active_box_model]->box_points);
            }
            uint64_t tsc_after_cluster = rte_rdtsc();

            struct box_model *bm = local_box_model[active_box_model];
            int box_count = bm->box_count;

            /* tally attack/benign per box from sample keys */
            int sample_atk[MAX_CLUSTER]    = {0};
            int sample_ben[MAX_CLUSTER]    = {0};
            int window_pts[MAX_CLUSTER]    = {0};
            const uint32_t atk_ip = RTE_IPV4(192, 168, 50, 1);

            if (should_recluster) {
                /* points_box[] from CluBoxFloat (log-norm space) */
                for (int i = 0; i < SAMPLE_WINDOW; i++) {
                    int bid = points_box[i];
                    if (bid < 0 || bid >= box_count) continue;
                    window_pts[bid]++;
                    struct flow_key *k = &key_sample_flat[buf_idx][i];
                    uint32_t s = rte_be_to_cpu_32(k->src_ip);
                    uint32_t d = rte_be_to_cpu_32(k->dst_ip);
                    if (s == atk_ip || d == atk_ip) sample_atk[bid]++;
                    else                             sample_ben[bid]++;
                }
            } else {
                /* map raw-space samples to existing (inverse-transformed) boxes */
                for (int i = 0; i < SAMPLE_WINDOW; i++) {
                    float fv[FEATURE_DIM] = {
                        feature_sample_flat[buf_idx][i * FEATURE_DIM + 0],
                        feature_sample_flat[buf_idx][i * FEATURE_DIM + 1]
                    };
                    int bid = checkPointBoxFloat(fv, bm->boxes, bm->order_index,
                                                FEATURE_DIM, box_count);
                    points_box[i] = bid;
                    if (bid < 0 || bid >= box_count) continue;
                    window_pts[bid]++;
                    struct flow_key *k = &key_sample_flat[buf_idx][i];
                    uint32_t s = rte_be_to_cpu_32(k->src_ip);
                    uint32_t d = rte_be_to_cpu_32(k->dst_ip);
                    if (s == atk_ip || d == atk_ip) sample_atk[bid]++;
                    else                             sample_ben[bid]++;
                }
                /* update box_points with this window's hit counts */
                memcpy(bm->box_points, window_pts, box_count * sizeof(int));
            }

            /* sample_clusters CSV */
            sprintf(file_name, "%s/sample_clusters_%d.csv", out_dir, re_cluster_count);
            FILE *f_csv = fopen(file_name, "w");
            fprintf(f_csv, "src_ip,dst_ip,sport,dport,proto,feature1,feature2,box_id\n");
            for (int i = 0; i < SAMPLE_WINDOW; i++) {
                struct flow_key *m = &key_sample_flat[buf_idx][i];
                fprintf(f_csv, "%u.%u.%u.%u,%u.%u.%u.%u,%u,%u,%u,%.2f,%.2f,%d\n",
                    (rte_be_to_cpu_32(m->src_ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(m->src_ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(m->src_ip) >>  8) & 0xFF,
                     rte_be_to_cpu_32(m->src_ip)        & 0xFF,
                    (rte_be_to_cpu_32(m->dst_ip) >> 24) & 0xFF,
                    (rte_be_to_cpu_32(m->dst_ip) >> 16) & 0xFF,
                    (rte_be_to_cpu_32(m->dst_ip) >>  8) & 0xFF,
                     rte_be_to_cpu_32(m->dst_ip)        & 0xFF,
                    rte_be_to_cpu_16(m->src_port), rte_be_to_cpu_16(m->dst_port),
                    m->proto,
                    feature_temp[i * FEATURE_DIM + 0],
                    feature_temp[i * FEATURE_DIM + 1],
                    points_box[i]);
            }
            fclose(f_csv);

            /* cluster_boxes CSV — always written; inverse-transform only on recluster */
            if (should_recluster) {
                for (int i = 0; i < box_count; i++) {
                    float vol_log = computeBoxVolFloat(bm->boxes[i], FEATURE_DIM);
                    bm->box_volumes[i] = vol_log;
                    bm->boxes[i][0] -= 0.001f;
                    bm->boxes[i][1] += 0.001f;
                    float min_f1_us = powf(10.0f, bm->boxes[i][2] / 75.0f) - 1.0f;
                    float max_f1_us = powf(10.0f, bm->boxes[i][3] / 75.0f) - 1.0f;
                    bm->boxes[i][2] = min_f1_us;
                    bm->boxes[i][3] = max_f1_us;
                }
            }

            sprintf(file_name, "%s/cluster_boxes_%d.csv", out_dir, re_cluster_count);
            FILE *f_boxes = fopen(file_name, "w");
            fprintf(f_boxes, "window_id,box_id,min_f0,max_f0,min_f1_us,max_f1_us,"
                             "box_points,box_volume,box_ratio,log_density,"
                             "attack_count,benign_count,attack_ratio,"
                             "box_score,box_label,is_recluster\n");
            int malicious = 0;
            for (int i = 0; i < box_count; i++) {
                int cur   = bm->box_points[i];
                int prev  = bm->prev_box_points[i];
                float vol_raw = computeBoxVolFloat(bm->boxes[i], FEATURE_DIM);
                float box_ratio   = (float)cur / (float)SAMPLE_WINDOW;
                float density     = (vol_raw > 0.0f && cur > 0) ? (float)cur / vol_raw : 1e-10f;
                float log_density = logf(density);
                float s_score = classify_box_spatial(bm->boxes[i]);
                float m_score = score_box_meta(box_ratio, vol_raw, cur - prev);
                float combined = s_score + m_score;
                bm->box_scores[i]  = combined;
                bm->box_labels[i]  = (combined >= BOX_EVAL_THRESHOLD) ? 1 : 0;
                bm->prev_box_points[i] = cur;
                malicious += bm->box_labels[i];

                int atk = sample_atk[i];
                int ben = sample_ben[i];
                float ratio = (atk + ben > 0) ? (float)atk / (float)(atk + ben) : 0.0f;

                fprintf(f_boxes, "%d,%d,%f,%f,%f,%f,%d,%f,%.6f,%.6f,%d,%d,%.4f,%.4f,%d,%d\n",
                    re_cluster_count, i,
                    bm->boxes[i][0], bm->boxes[i][1],
                    bm->boxes[i][2], bm->boxes[i][3],
                    cur, vol_raw, box_ratio, log_density,
                    atk, ben, ratio,
                    combined, bm->box_labels[i], should_recluster);
            }
            fclose(f_boxes);

            float win_time_s = sample_time[buf_idx];
            float mpps = (win_time_s > 0.0f)
                ? (float)g_window_pkt_snap[buf_idx] / win_time_s / 1e6f : 0.0f;
            float gbps = (win_time_s > 0.0f)
                ? (float)g_window_byte_snap[buf_idx] * 8.0f / win_time_s / 1e9f : 0.0f;

            /* flow-level confusion matrix:
             * true label  = flow involves attack IP (192.168.50.1)
             * pred label  = box_labels[box_id]; outlier → majority-malicious rule */
            int cm_tp = 0, cm_tn = 0, cm_fp = 0, cm_fn = 0;
            int mal_cnt_total = 0;
            for (int i = 0; i < box_count; i++)
                mal_cnt_total += bm->box_labels[i];
            int outlier_pred = (box_count > 0 && mal_cnt_total * 2 > box_count) ? 1 : 0;

            for (int i = 0; i < SAMPLE_WINDOW; i++) {
                struct flow_key *k = &key_sample_flat[buf_idx][i];
                uint32_t s = rte_be_to_cpu_32(k->src_ip);
                uint32_t d = rte_be_to_cpu_32(k->dst_ip);
                int true_lbl = (s == atk_ip || d == atk_ip) ? 1 : 0;
                int bid      = points_box[i];
                int pred_lbl = (bid >= 0 && bid < box_count)
                               ? bm->box_labels[bid] : outlier_pred;
                if      (pred_lbl && true_lbl)   cm_tp++;
                else if (!pred_lbl && !true_lbl) cm_tn++;
                else if (pred_lbl && !true_lbl)  cm_fp++;
                else                             cm_fn++;
            }

            if (should_recluster) {
                if (checkOverlapFloat(bm->boxes, box_count, FEATURE_DIM))
                    bm->order_index = sortFloat(bm->box_volumes, box_count, 1);
                else
                    bm->order_index = sortInt(bm->box_points, box_count, 0);
                rte_ring_enqueue(box_ring, (void *)(uintptr_t)active_box_model);
                memset(bm->box_attack_count, 0, MAX_CLUSTER * sizeof(int));
                memset(bm->box_benign_count, 0, MAX_CLUSTER * sizeof(int));
            } else {
                processing_lock = 0;  /* no box_ring enqueue; unlock directly */
            }

            uint64_t tsc_end = rte_rdtsc();
            uint64_t cluster_us = (tsc_after_cluster - tsc_start) * 1000000ULL / tsc_hz;
            uint64_t eval_us    = (tsc_end - tsc_after_cluster) * 1000000ULL / tsc_hz;
            uint64_t total_us   = (tsc_end - tsc_start) * 1000000ULL / tsc_hz;
            fprintf(f_timing, "%d,%lu,%lu,%lu,%d,%d\n",
                    re_cluster_count, cluster_us, eval_us, total_us,
                    box_count, should_recluster);
            fflush(f_timing);

            fprintf(f_results, "%d,%d,%d,%d,%d,%.4f,%.4f\n",
                    re_cluster_count, cm_tp, cm_tn, cm_fp, cm_fn, mpps, gbps);
            fflush(f_results);

            printf("[BOX EVAL] Window %d (%s): %d boxes (%d mal) "
                   "TP=%d TN=%d FP=%d FN=%d | %.3f Mpps %.3f Gbps | drops=%lu"
                   " [cluster=%luus eval=%luus]\n",
                   re_cluster_count,
                   should_recluster ? "RECLUSTER" : "STATS",
                   box_count, malicious,
                   cm_tp, cm_tn, cm_fp, cm_fn,
                   mpps, gbps, total_drop_count,
                   cluster_us, eval_us);

            re_cluster_count++;
        }
    }
    fclose(f_results);
    rte_eal_mp_wait_lcore();

    return 0;
}