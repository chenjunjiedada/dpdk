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

#include "gro_tcp4.h"

void *
gro_tcp4_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow)
{
	struct gro_tcp4_tbl *tbl;
	size_t size;
	uint32_t entries_num, i;

	entries_num = max_flow_num * max_item_per_flow;
	entries_num = RTE_MIN(entries_num, GRO_TCP4_TBL_MAX_ITEM_NUM);

	if (entries_num == 0)
		return NULL;

	tbl = rte_zmalloc_socket(__func__,
			sizeof(struct gro_tcp4_tbl),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl == NULL)
		return NULL;

	size = sizeof(struct gro_tcp4_item) * entries_num;
	tbl->items = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->items == NULL) {
		rte_free(tbl);
		return NULL;
	}
	tbl->max_item_num = entries_num;

	size = sizeof(struct gro_tcp4_flow) * entries_num;
	tbl->flows = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->flows == NULL) {
		rte_free(tbl->items);
		rte_free(tbl);
		return NULL;
	}
	/* INVALID_ARRAY_INDEX indicates an empty flow */
	for (i = 0; i < entries_num; i++)
		tbl->flows[i].start_index = INVALID_ARRAY_INDEX;
	tbl->max_flow_num = entries_num;

	return tbl;
}

void
gro_tcp4_tbl_destroy(void *tbl)
{
	struct gro_tcp4_tbl *tcp_tbl = tbl;

	if (tcp_tbl) {
		rte_free(tcp_tbl->items);
		rte_free(tcp_tbl->flows);
	}
	rte_free(tcp_tbl);
}

static inline uint32_t
find_an_empty_item(struct gro_tcp4_tbl *tbl)
{
	uint32_t i;
	uint32_t max_item_num = tbl->max_item_num;

	for (i = 0; i < max_item_num; i++)
		if (tbl->items[i].firstseg == NULL)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
find_an_empty_flow(struct gro_tcp4_tbl *tbl)
{
	uint32_t i;
	uint32_t max_flow_num = tbl->max_flow_num;

	for (i = 0; i < max_flow_num; i++)
		if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
insert_new_item(struct gro_tcp4_tbl *tbl,
		struct rte_mbuf *pkt,
		uint32_t sent_seq,
		uint32_t prev_idx,
		uint64_t start_time)
{
	uint32_t item_idx;

	item_idx = find_an_empty_item(tbl);
	if (item_idx == INVALID_ARRAY_INDEX)
		return INVALID_ARRAY_INDEX;

	tbl->items[item_idx].firstseg = pkt;
	tbl->items[item_idx].lastseg = rte_pktmbuf_lastseg(pkt);
	tbl->items[item_idx].start_time = start_time;
	tbl->items[item_idx].next_pkt_idx = INVALID_ARRAY_INDEX;
	tbl->items[item_idx].sent_seq = sent_seq;
	tbl->items[item_idx].nb_merged = 1;
	tbl->item_num++;

	/* if the previous packet exists, chain the new one with it */
	if (prev_idx != INVALID_ARRAY_INDEX) {
		tbl->items[item_idx].next_pkt_idx =
			tbl->items[prev_idx].next_pkt_idx;
		tbl->items[prev_idx].next_pkt_idx = item_idx;
	}

	return item_idx;
}

static inline uint32_t
delete_item(struct gro_tcp4_tbl *tbl, uint32_t item_idx,
		uint32_t prev_item_idx)
{
	uint32_t next_idx = tbl->items[item_idx].next_pkt_idx;

	/* NULL indicates an empty item */
	tbl->items[item_idx].firstseg = NULL;
	tbl->item_num--;
	if (prev_item_idx != INVALID_ARRAY_INDEX)
		tbl->items[prev_item_idx].next_pkt_idx = next_idx;

	return next_idx;
}

static inline uint32_t
insert_new_flow(struct gro_tcp4_tbl *tbl,
		struct tcp4_flow_key *src,
		uint32_t item_idx)
{
	struct tcp4_flow_key *dst;
	uint32_t flow_idx;

	flow_idx = find_an_empty_flow(tbl);
	if (flow_idx == INVALID_ARRAY_INDEX)
		return INVALID_ARRAY_INDEX;

	dst = &(tbl->flows[flow_idx].key);

	ether_addr_copy(&(src->eth_saddr), &(dst->eth_saddr));
	ether_addr_copy(&(src->eth_daddr), &(dst->eth_daddr));
	dst->ip_src_addr = src->ip_src_addr;
	dst->ip_dst_addr = src->ip_dst_addr;
	dst->recv_ack = src->recv_ack;
	dst->src_port = src->src_port;
	dst->dst_port = src->dst_port;

	tbl->flows[flow_idx].start_index = item_idx;
	tbl->flow_num++;

	return flow_idx;
}

static inline void
update_header(struct gro_tcp4_item *item)
{
	struct ipv4_hdr *ipv4_hdr;
	struct rte_mbuf *pkt = item->firstseg;

	ipv4_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
			pkt->l2_len);
	ipv4_hdr->total_length = rte_cpu_to_be_16(pkt->pkt_len -
			pkt->l2_len);
}

int32_t
gro_tcp4_reassemble(struct rte_mbuf *pkt,
		struct gro_tcp4_tbl *tbl,
		uint64_t start_time)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct tcp_hdr *tcp_hdr;
	uint32_t sent_seq;
	uint16_t tcp_dl, hdr_len;

	struct tcp4_flow_key key;
	uint32_t cur_idx, prev_idx, item_idx;
	uint32_t i, max_flow_num;
	int cmp;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)((char *)eth_hdr + pkt->l2_len);
	tcp_hdr = (struct tcp_hdr *)((char *)ipv4_hdr + pkt->l3_len);
	hdr_len = pkt->l2_len + pkt->l3_len + pkt->l4_len;

	/*
	 * Don't process the packet which has FIN, SYN, RST, PSH, URG, ECE
	 * or CWR set.
	 */
	if (tcp_hdr->tcp_flags != TCP_ACK_FLAG)
		return -1;
	/*
	 * Don't process the packet whose payload length is less than or
	 * equal to 0.
	 */
	tcp_dl = pkt->pkt_len - hdr_len;
	if (tcp_dl <= 0)
		return -1;

	sent_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);

	ether_addr_copy(&(eth_hdr->s_addr), &(key.eth_saddr));
	ether_addr_copy(&(eth_hdr->d_addr), &(key.eth_daddr));
	key.ip_src_addr = ipv4_hdr->src_addr;
	key.ip_dst_addr = ipv4_hdr->dst_addr;
	key.src_port = tcp_hdr->src_port;
	key.dst_port = tcp_hdr->dst_port;
	key.recv_ack = tcp_hdr->recv_ack;

	/* Search for a matched flow. */
	max_flow_num = tbl->max_flow_num;
	for (i = 0; i < max_flow_num; i++) {
		if ((tbl->flows[i].start_index != INVALID_ARRAY_INDEX) &&
				is_same_tcp4_flow(tbl->flows[i].key, key))
			break;
	}

	/*
	 * Fail to find a matched flow. Insert a new flow and store the
	 * packet into the flow.
	 */
	if (i == tbl->max_flow_num) {
		item_idx = insert_new_item(tbl, pkt, sent_seq,
				INVALID_ARRAY_INDEX, start_time);
		if (item_idx == INVALID_ARRAY_INDEX)
			return -1;
		if (insert_new_flow(tbl, &key, item_idx) ==
				INVALID_ARRAY_INDEX) {
			/* Fail to insert a new flow. */
			delete_item(tbl, item_idx, INVALID_ARRAY_INDEX);
			return -1;
		}
		return 0;
	}

	/*
	 * Check all packets in the flow and try to find a neighbor for
	 * the input packet.
	 */
	cur_idx = tbl->flows[i].start_index;
	prev_idx = cur_idx;
	do {
		cmp = check_seq_option(&(tbl->items[cur_idx]), tcp_hdr,
				pkt->l4_len, tcp_dl, sent_seq, 0);
		if (cmp) {
			if (merge_two_tcp4_packets(&(tbl->items[cur_idx]),
						pkt, sent_seq, cmp, 0))
				return 1;
			/*
			 * Fail to merge the two packets, as the packet
			 * length is greater than the max value. Store
			 * the packet into the flow.
			 */
			if (insert_new_item(tbl, pkt, sent_seq,
						prev_idx, start_time) ==
					INVALID_ARRAY_INDEX)
				return -1;
			return 0;
		}
		prev_idx = cur_idx;
		cur_idx = tbl->items[cur_idx].next_pkt_idx;
	} while (cur_idx != INVALID_ARRAY_INDEX);

	/* Fail to find a neighbor, so store the packet into the flow. */
	if (insert_new_item(tbl, pkt, sent_seq, prev_idx,
				start_time) == INVALID_ARRAY_INDEX)
		return -1;

	return 0;
}

uint16_t
gro_tcp4_tbl_timeout_flush(struct gro_tcp4_tbl *tbl,
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
			if (tbl->items[j].start_time <= flush_timestamp) {
				out[k++] = tbl->items[j].firstseg;
				if (tbl->items[j].nb_merged > 1)
					update_header(&(tbl->items[j]));
				/*
				 * Delete the packet and get the next
				 * packet in the flow.
				 */
				j = delete_item(tbl, j, INVALID_ARRAY_INDEX);
				tbl->flows[i].start_index = j;
				if (j == INVALID_ARRAY_INDEX)
					tbl->flow_num--;

				if (unlikely(k == nb_out))
					return k;
			} else
				/*
				 * The left packets in this flow won't be
				 * timeout. Go to check other flows.
				 */
				break;
		}
	}
	return k;
}

uint32_t
gro_tcp4_tbl_pkt_count(void *tbl)
{
	struct gro_tcp4_tbl *gro_tbl = tbl;

	if (gro_tbl)
		return gro_tbl->item_num;

	return 0;
}
