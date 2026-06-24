#ifndef _APP_DISSECTOR_H_
#define _APP_DISSECTOR_H_

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_tcp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>

struct dissector_result
{
    struct rte_mbuf *mbuf;

    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;

    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;
};

/**
 * @brief
 *
 * @param mbufs
 * @param results
 * @param num
 * @return int
 */
void app_dissector_dissect(struct rte_mbuf *mbufs[], struct dissector_result *results, uint32_t num);
void dissector_dissect(const struct rte_mbuf *mbuf, struct dissector_result *result);

#endif
