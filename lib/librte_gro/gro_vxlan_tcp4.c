/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_udp.h>

#include "gro_vxlan_tcp4.h"

void *
gro_vxlan_tcp4_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow)
{
	struct gro_vxlan_tcp4_tbl *tbl;
	size_t size;
	uint32_t entries_num, i;

	entries_num = max_flow_num * max_item_per_flow;
	entries_num = RTE_MIN(entries_num, GRO_VXLAN_TCP4_TBL_MAX_ITEM_NUM);

	if (entries_num == 0)
		return NULL;

	tbl = rte_zmalloc_socket(__func__,
			sizeof(struct gro_vxlan_tcp4_tbl),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl == NULL)
		return NULL;

	size = sizeof(struct gro_vxlan_tcp4_item) * entries_num;
	tbl->items = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->items == NULL) {
		rte_free(tbl);
		return NULL;
	}
	tbl->max_item_num = entries_num;

	size = sizeof(struct gro_vxlan_tcp4_flow) * entries_num;
	tbl->flows = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->flows == NULL) {
		rte_free(tbl->items);
		rte_free(tbl);
		return NULL;
	}

	for (i = 0; i < entries_num; i++)
		tbl->flows[i].start_index = INVALID_ARRAY_INDEX;
	tbl->max_flow_num = entries_num;

	return tbl;
}

void
gro_vxlan_tcp4_tbl_destroy(void *tbl)
{
	struct gro_vxlan_tcp4_tbl *vxlan_tbl = tbl;

	if (vxlan_tbl) {
		rte_free(vxlan_tbl->items);
		rte_free(vxlan_tbl->flows);
	}
	rte_free(vxlan_tbl);
}

static inline uint32_t
find_an_empty_item(struct gro_vxlan_tcp4_tbl *tbl)
{
	uint32_t max_item_num = tbl->max_item_num, i;

	for (i = 0; i < max_item_num; i++)
		if (tbl->items[i].inner_item.firstseg == NULL)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
find_an_empty_flow(struct gro_vxlan_tcp4_tbl *tbl)
{
	uint32_t max_flow_num = tbl->max_flow_num, i;

	for (i = 0; i < max_flow_num; i++)
		if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
insert_new_item(struct gro_vxlan_tcp4_tbl *tbl,
		struct rte_mbuf *pkt,
		uint16_t outer_ip_id,
		uint32_t sent_seq,
		uint32_t prev_idx,
		uint64_t start_time)
{
	uint32_t item_idx;

	item_idx = find_an_empty_item(tbl);
	if (item_idx == INVALID_ARRAY_INDEX)
		return INVALID_ARRAY_INDEX;

	tbl->items[item_idx].inner_item.firstseg = pkt;
	tbl->items[item_idx].inner_item.lastseg = rte_pktmbuf_lastseg(pkt);
	tbl->items[item_idx].inner_item.start_time = start_time;
	tbl->items[item_idx].inner_item.next_pkt_idx = INVALID_ARRAY_INDEX;
	tbl->items[item_idx].inner_item.sent_seq = sent_seq;
	tbl->items[item_idx].inner_item.nb_merged = 1;
	tbl->items[item_idx].outer_ip_id = outer_ip_id;
	tbl->item_num++;

	/* If the previous packet exists, chain the new one with it. */
	if (prev_idx != INVALID_ARRAY_INDEX) {
		tbl->items[item_idx].inner_item.next_pkt_idx =
			tbl->items[prev_idx].inner_item.next_pkt_idx;
		tbl->items[prev_idx].inner_item.next_pkt_idx = item_idx;
	}

	return item_idx;
}

static inline uint32_t
delete_item(struct gro_vxlan_tcp4_tbl *tbl,
		uint32_t item_idx,
		uint32_t prev_item_idx)
{
	uint32_t next_idx = tbl->items[item_idx].inner_item.next_pkt_idx;

	/* NULL indicates an empty item. */
	tbl->items[item_idx].inner_item.firstseg = NULL;
	tbl->item_num--;
	if (prev_item_idx != INVALID_ARRAY_INDEX)
		tbl->items[prev_item_idx].inner_item.next_pkt_idx = next_idx;

	return next_idx;
}

static inline uint32_t
insert_new_flow(struct gro_vxlan_tcp4_tbl *tbl,
		struct vxlan_tcp4_flow_key *src,
		uint32_t item_idx)
{
	struct vxlan_tcp4_flow_key *dst;
	uint32_t flow_idx;

	flow_idx = find_an_empty_flow(tbl);
	if (flow_idx == INVALID_ARRAY_INDEX)
		return INVALID_ARRAY_INDEX;

	dst = &(tbl->flows[flow_idx].key);

	ether_addr_copy(&(src->inner_key.eth_saddr),
			&(dst->inner_key.eth_saddr));
	ether_addr_copy(&(src->inner_key.eth_daddr),
			&(dst->inner_key.eth_daddr));
	dst->inner_key.ip_src_addr = src->inner_key.ip_src_addr;
	dst->inner_key.ip_dst_addr = src->inner_key.ip_dst_addr;
	dst->inner_key.recv_ack = src->inner_key.recv_ack;
	dst->inner_key.src_port = src->inner_key.src_port;
	dst->inner_key.dst_port = src->inner_key.dst_port;

	dst->vxlan_hdr = src->vxlan_hdr;
	ether_addr_copy(&(src->outer_eth_saddr), &(dst->outer_eth_saddr));
	ether_addr_copy(&(src->outer_eth_daddr), &(dst->outer_eth_daddr));
	dst->outer_ip_src_addr = src->outer_ip_src_addr;
	dst->outer_ip_dst_addr = src->outer_ip_dst_addr;
	dst->outer_src_port = src->outer_src_port;
	dst->outer_dst_port = src->outer_dst_port;

	tbl->flows[flow_idx].start_index = item_idx;
	tbl->flow_num++;

	return flow_idx;
}

static inline int
is_same_vxlan_tcp4_flow(struct vxlan_tcp4_flow_key k1,
		struct vxlan_tcp4_flow_key k2)
{
	if (is_same_tcp4_flow(k1.inner_key, k2.inner_key) == 0 ||
			is_same_ether_addr(&k1.outer_eth_saddr,
				&k2.outer_eth_saddr) == 0 ||
			is_same_ether_addr(&k1.outer_eth_daddr,
				&k2.outer_eth_daddr) == 0)
		return 0;

	return ((k1.outer_ip_src_addr == k2.outer_ip_src_addr) &&
			(k1.outer_ip_dst_addr == k2.outer_ip_dst_addr) &&
			(k1.outer_src_port == k2.outer_src_port) &&
			(k1.outer_dst_port == k2.outer_dst_port) &&
			(k1.vxlan_hdr.vx_flags == k2.vxlan_hdr.vx_flags) &&
			(k1.vxlan_hdr.vx_vni == k2.vxlan_hdr.vx_vni));
}

static inline int
check_vxlan_seq_option(struct gro_vxlan_tcp4_item *item,
		struct tcp_hdr *tcp_hdr,
		uint16_t tcp_hl,
		uint16_t tcp_dl,
		uint16_t outer_ip_id,
		uint32_t sent_seq)
{
	struct rte_mbuf *pkt = item->inner_item.firstseg;
	int cmp;
	uint16_t l2_offset;

	l2_offset = pkt->outer_l2_len + pkt->outer_l3_len;
	cmp = check_seq_option(&item->inner_item, tcp_hdr, tcp_hl, tcp_dl,
			sent_seq, l2_offset);
	if (cmp == 1 && outer_ip_id == item->outer_ip_id + 1)
		/* Append the packet. */
		return 1;
	else if (cmp == -1 && outer_ip_id + item->inner_item.nb_merged ==
			item->outer_ip_id)
		/* Prepend the packet. */
		return -1;
	else
		return 0;
}

static inline int
merge_two_vxlan_tcp4_packets(struct gro_vxlan_tcp4_item *item,
		struct rte_mbuf *pkt,
		uint16_t outer_ip_id,
		uint32_t sent_seq,
		int cmp)
{
	if (merge_two_tcp4_packets(&item->inner_item, pkt, sent_seq, cmp,
				pkt->outer_l2_len + pkt->outer_l3_len)) {
		item->outer_ip_id = outer_ip_id;
		return 1;
	} else
		return 0;
}

static inline void
update_vxlan_header(struct gro_vxlan_tcp4_item *item)
{
	struct ipv4_hdr *ipv4_hdr;
	struct udp_hdr *udp_hdr;
	struct rte_mbuf *pkt = item->inner_item.firstseg;
	uint16_t len;

	/* Update the outer IPv4 header. */
	len = pkt->pkt_len - pkt->outer_l2_len;
	ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
			pkt->outer_l2_len);
	ipv4_hdr->total_length = rte_cpu_to_be_16(len);

	/* Update the outer UDP header. */
	len -= pkt->outer_l3_len;
	udp_hdr = (struct udp_hdr *)((char *)ipv4_hdr + pkt->outer_l3_len);
	udp_hdr->dgram_len = rte_cpu_to_be_16(len);

	/* Update the inner IPv4 header. */
	len -= pkt->l2_len;
	ipv4_hdr = (struct ipv4_hdr *)((char *)udp_hdr + pkt->l2_len);
	ipv4_hdr->total_length = rte_cpu_to_be_16(len);
}

int32_t
gro_vxlan_tcp4_reassemble(struct rte_mbuf *pkt,
		struct gro_vxlan_tcp4_tbl *tbl,
		uint64_t start_time)
{
	struct ether_hdr *outer_eth_hdr, *eth_hdr;
	struct ipv4_hdr *outer_ipv4_hdr, *ipv4_hdr;
	struct tcp_hdr *tcp_hdr;
	struct udp_hdr *udp_hdr;
	struct vxlan_hdr *vxlan_hdr;
	uint32_t sent_seq;
	uint16_t tcp_dl, outer_ip_id;

	struct vxlan_tcp4_flow_key key;
	uint32_t cur_idx, prev_idx, item_idx;
	uint32_t i, max_flow_num;
	uint16_t hdr_len;
	int cmp;

	outer_eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	outer_ipv4_hdr = (struct ipv4_hdr *)((char *)outer_eth_hdr +
			pkt->outer_l2_len);
	outer_ip_id = rte_be_to_cpu_16(outer_ipv4_hdr->packet_id);
	udp_hdr = (struct udp_hdr *)((char *)outer_ipv4_hdr +
			pkt->outer_l3_len);
	vxlan_hdr = (struct vxlan_hdr *)((char *)udp_hdr +
			sizeof(struct udp_hdr));
	eth_hdr = (struct ether_hdr *)((char *)vxlan_hdr +
			sizeof(struct vxlan_hdr));
	ipv4_hdr = (struct ipv4_hdr *)((char *)udp_hdr + pkt->l2_len);
	tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr + pkt->l3_len);

	/*
	 * Check if the inner TCP header flag sets FIN, SYN, RST,
	 * PSH, URG, ECE or CWR bit.
	 */
	if (tcp_hdr->tcp_flags != TCP_ACK_FLAG)
		return -1;
	hdr_len = pkt->outer_l2_len + pkt->outer_l3_len + pkt->l2_len +
		pkt->l3_len + pkt->l4_len;
	/*
	 * If the payload length is less than or equal to 0, return
	 * immediately.
	 */
	tcp_dl = pkt->pkt_len - hdr_len;
	if (tcp_dl <= 0)
		return -1;

	sent_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);

	ether_addr_copy(&(eth_hdr->s_addr), &(key.inner_key.eth_saddr));
	ether_addr_copy(&(eth_hdr->d_addr), &(key.inner_key.eth_daddr));
	key.inner_key.ip_src_addr = ipv4_hdr->src_addr;
	key.inner_key.ip_dst_addr = ipv4_hdr->dst_addr;
	key.inner_key.src_port = tcp_hdr->src_port;
	key.inner_key.dst_port = tcp_hdr->dst_port;
	key.inner_key.recv_ack = tcp_hdr->recv_ack;

	ether_addr_copy(&(outer_eth_hdr->s_addr), &(key.outer_eth_saddr));
	ether_addr_copy(&(outer_eth_hdr->d_addr), &(key.outer_eth_daddr));
	key.outer_ip_src_addr = outer_ipv4_hdr->src_addr;
	key.outer_ip_dst_addr = outer_ipv4_hdr->dst_addr;
	key.outer_src_port = udp_hdr->src_port;
	key.outer_dst_port = udp_hdr->dst_port;
	key.vxlan_hdr.vx_flags = vxlan_hdr->vx_flags;
	key.vxlan_hdr.vx_vni = vxlan_hdr->vx_vni;

	/* Search for a matched flow. */
	max_flow_num = tbl->max_flow_num;
	for (i = 0; i < max_flow_num; i++) {
		if (tbl->flows[i].start_index != INVALID_ARRAY_INDEX &&
				is_same_vxlan_tcp4_flow(tbl->flows[i].key,
					key))
			break;
	}

	/*
	 * Can't find a matched flow. Insert a new flow and store the
	 * packet into the flow.
	 */
	if (i == tbl->max_flow_num) {
		item_idx = insert_new_item(tbl, pkt, outer_ip_id, sent_seq,
				INVALID_ARRAY_INDEX, start_time);
		if (item_idx == INVALID_ARRAY_INDEX)
			return -1;
		if (insert_new_flow(tbl, &key, item_idx) ==
				INVALID_ARRAY_INDEX) {
			/*
			 * Fail to insert a new flow, so
			 * delete the inserted packet.
			 */
			delete_item(tbl, item_idx, INVALID_ARRAY_INDEX);
			return -1;
		}
		return 0;
	}

	/* Check all packets in the flow and try to find a neighbor. */
	cur_idx = tbl->flows[i].start_index;
	prev_idx = cur_idx;
	do {
		cmp = check_vxlan_seq_option(&(tbl->items[cur_idx]), tcp_hdr,
				pkt->l4_len, tcp_dl, outer_ip_id, sent_seq);
		if (cmp) {
			if (merge_two_vxlan_tcp4_packets(&(tbl->items[cur_idx]),
						pkt, outer_ip_id, sent_seq,
						cmp))
				return 1;
			/*
			 * Can't merge two packets, as the packet
			 * length will be greater than the max value.
			 * Insert the packet into the flow.
			 */
			if (insert_new_item(tbl, pkt, outer_ip_id, sent_seq,
						prev_idx, start_time) ==
					INVALID_ARRAY_INDEX)
				return -1;
			return 0;
		}
		prev_idx = cur_idx;
		cur_idx = tbl->items[cur_idx].inner_item.next_pkt_idx;
	} while (cur_idx != INVALID_ARRAY_INDEX);

	/* Can't find neighbor. Insert the packet into the flow. */
	if (insert_new_item(tbl, pkt, outer_ip_id, sent_seq, prev_idx,
				start_time) == INVALID_ARRAY_INDEX)
		return -1;

	return 0;
}

uint16_t
gro_vxlan_tcp4_tbl_timeout_flush(struct gro_vxlan_tcp4_tbl *tbl,
		uint64_t flush_timestamp,
		struct rte_mbuf **out,
		uint16_t nb_out)
{
	uint16_t k = 0;
	uint32_t i, j;
	uint32_t max_flow_num = tbl->max_flow_num;

	for (i = 0; i < max_flow_num; i++) {
		if (unlikely(tbl->flow_num == 0))
			return k;

		j = tbl->flows[i].start_index;
		while (j != INVALID_ARRAY_INDEX) {
			if (tbl->items[j].inner_item.start_time <=
					flush_timestamp) {
				out[k++] = tbl->items[j].inner_item.firstseg;
				if (tbl->items[j].inner_item.nb_merged > 1)
					update_vxlan_header(&(tbl->items[j]));
				/*
				 * Delete the item and get the next packet
				 * index.
				 */
				j = delete_item(tbl, j, INVALID_ARRAY_INDEX);
				tbl->flows[i].start_index = j;
				if (j == INVALID_ARRAY_INDEX)
					tbl->flow_num--;

				if (unlikely(k == nb_out))
					return k;
			} else
				/*
				 * The left packets in the flow won't be
				 * timeout. Go to check other flows.
				 */
				break;
		}
	}
	return k;
}

uint32_t
gro_vxlan_tcp4_tbl_pkt_count(void *tbl)
{
	struct gro_vxlan_tcp4_tbl *gro_tbl = tbl;

	if (gro_tbl)
		return gro_tbl->item_num;

	return 0;
}
