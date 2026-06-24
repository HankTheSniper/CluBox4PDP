#include "dissectors.h"

void dissector_dissect(const struct rte_mbuf *mbuf, struct dissector_result *result)
{
    struct rte_ether_hdr *ether_hdr;
    struct rte_vlan_hdr *vlan_hdr = NULL;
    rte_be16_t ether_type;

    ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    ether_type = ether_hdr->ether_type;

    while (ether_type == rte_cpu_to_be_16(0x8100))
    {
        vlan_hdr = vlan_hdr == NULL ? (struct rte_vlan_hdr *)(&ether_hdr[1]) : &vlan_hdr[1];
        ether_type = vlan_hdr->eth_proto;
    }

    void *next_hdr = vlan_hdr ? (void *)(&vlan_hdr[1]) : (void *)(&ether_hdr[1]);

    if (ether_type == rte_cpu_to_be_16(0x0800))
    {
        result->ipv4_hdr = (struct rte_ipv4_hdr *)next_hdr;
        uint8_t proto = result->ipv4_hdr->next_proto_id;

        if (proto == IPPROTO_TCP) {
            result->tcp_hdr = RTE_PTR_ADD(result->ipv4_hdr, result->ipv4_hdr->ihl * 4);
        } 
        else if (proto == IPPROTO_UDP) {
            result->udp_hdr = (struct rte_udp_hdr *)RTE_PTR_ADD(result->ipv4_hdr, result->ipv4_hdr->ihl * 4);
        }
    }
    else if (ether_type == rte_cpu_to_be_16(0x86dd))
    {
        result->ipv6_hdr = (struct rte_ipv6_hdr *)next_hdr;

        if (result->ipv6_hdr->proto != 6) // ignore exts
            return;

        result->tcp_hdr = (struct rte_tcp_hdr *)(&result->ipv6_hdr[1]);
    }
    else
    {
        return;
    }
}

void app_dissector_dissect(struct rte_mbuf *mbufs[], struct dissector_result *results, uint32_t num)
{
    for (int i = 0; i < num; i++)
    {
        dissector_dissect(mbufs[i], &results[i]);
    }
}
