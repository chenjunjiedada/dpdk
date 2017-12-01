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

#ifndef _GRO_TCP4_H_
#define _GRO_TCP4_H_

#include <rte_ip.h>
#include <rte_tcp.h>

#define INVALID_ARRAY_INDEX 0xffffffffUL
#define GRO_TCP4_TBL_MAX_ITEM_NUM (1024UL * 1024UL)

/*
 * The max length of a IPv4 packet, which includes the length of L3
 * header, L4 header and the payload.
 */
#define MAX_IPV4_PKT_LENGTH UINT16_MAX

/* Header fields representing a TCP/IPv4 flow. */
struct tcp4_flow_key {
	struct ether_addr eth_saddr;
	struct ether_addr eth_daddr;
	uint32_t ip_src_addr;
	uint32_t ip_dst_addr;

	uint32_t recv_ack;
	uint16_t src_port;
	uint16_t dst_port;
};

struct gro_tcp4_flow {
	struct tcp4_flow_key key;
	/*
	 * The index of the first packet in the flow.
	 * INVALID_ARRAY_INDEX indicates an empty flow.
	 */
	uint32_t start_index;
};

struct gro_tcp4_item {
	/*
	 * First segment of the packet. If the value
	 * is NULL, it means the item is empty.
	 */
	struct rte_mbuf *firstseg;
	/* Last segment of the packet */
	struct rte_mbuf *lastseg;
	/*
	 * The time when the first packet is inserted
	 * into the table. If a packet in the table is
	 * merged with an incoming packet, this value
	 * won't be updated.
	 */
	uint64_t start_time;
	/*
	 * next_pkt_idx is used to chain the packets that
	 * are in the same flow but can't be merged together
	 * (i.e. caused by packet reordering).
	 */
	uint32_t next_pkt_idx;
	/* TCP sequence number of the packet */
	uint32_t sent_seq;
	/* The number of merged packets */
	uint16_t nb_merged;
};

/*
 * TCP/IPv4 reassembly table structure.
 */
struct gro_tcp4_tbl {
	/* item array */
	struct gro_tcp4_item *items;
	/* flow array */
	struct gro_tcp4_flow *flows;
	/* current item number */
	uint32_t item_num;
	/* current flow num */
	uint32_t flow_num;
	/* item array size */
	uint32_t max_item_num;
	/* flow array size */
	uint32_t max_flow_num;
};

/**
 * This function creates a TCP/IPv4 reassembly table.
 *
 * @param socket_id
 *  Socket index for allocating the TCP/IPv4 reassemble table
 * @param max_flow_num
 *  The maximum number of flows in the TCP/IPv4 GRO table
 * @param max_item_per_flow
 *  The maximum number of packets per flow
 *
 * @return
 *  - Return the table pointer on success.
 *  - Return NULL on failure.
 */
void *gro_tcp4_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow);

/**
 * This function destroys a TCP/IPv4 reassembly table.
 *
 * @param tbl
 *  Pointer pointint to the TCP/IPv4 reassembly table.
 */
void gro_tcp4_tbl_destroy(void *tbl);

/**
 * This function merges a TCP/IPv4 packet. It doesn't process the packet,
 * which has SYN, FIN, RST, PSH, CWR, ECE or URG set, or doesn't have
 * payload. It returns the packet if there is no available space in the
 * table.
 *
 * This function doesn't check if the packet has correct checksums.
 * Additionally, it doesn't re-calculate checksums for the merged packet.
 * If the input packet is IP fragmented, it assumes the packet is complete.
 *
 * @param pkt
 *  Packet to reassemble
 * @param tbl
 *  Pointer pointing to the TCP/IPv4 reassembly table
 * @start_time
 *  The time when the packet is inserted into the table
 *
 * @return
 *  - Return a positive value if the input packet is merged.
 *  - Return zero if the input packet isn't merged but stored in the table.
 *  - Return a negative value for invalid parameters.
 */
int32_t gro_tcp4_reassemble(struct rte_mbuf *pkt,
		struct gro_tcp4_tbl *tbl,
		uint64_t start_time);

/**
 * This function flushes timeout packets in a TCP/IPv4 reassembly table,
 * and without updating checksums.
 *
 * @param tbl
 *  Pointer points to a TCP/IPv4 reassembly table
 * @param flush_timestamp
 *  Flush packets which are inserted into the table before or at the
 *  flush_timestamp
 * @param out
 *  Pointer array used to keep flushed packets
 * @param nb_out
 *  The element number in 'out'. It also determines the maximum number of
 *  packets that can be flushed finally.
 *
 * @return
 *  The number of flushed packets
 */
uint16_t gro_tcp4_tbl_timeout_flush(struct gro_tcp4_tbl *tbl,
		uint64_t flush_timestamp,
		struct rte_mbuf **out,
		uint16_t nb_out);

/**
 * This function returns the number of the packets in a TCP/IPv4
 * reassembly table.
 *
 * @param tbl
 *  Pointer pointing to a TCP/IPv4 reassembly table
 *
 * @return
 *  The number of packets in the table
 */
uint32_t gro_tcp4_tbl_pkt_count(void *tbl);

/*
 * Check if two TCP/IPv4 packets belong to the same flow.
 */
static inline int
is_same_tcp4_flow(struct tcp4_flow_key k1, struct tcp4_flow_key k2)
{
	if (is_same_ether_addr(&k1.eth_saddr, &k2.eth_saddr) == 0)
		return 0;

	if (is_same_ether_addr(&k1.eth_daddr, &k2.eth_daddr) == 0)
		return 0;

	return ((k1.ip_src_addr == k2.ip_src_addr) &&
			(k1.ip_dst_addr == k2.ip_dst_addr) &&
			(k1.recv_ack == k2.recv_ack) &&
			(k1.src_port == k2.src_port) &&
			(k1.dst_port == k2.dst_port));
}

/*
 * Check if two TCP/IPv4 packets are neighbors.
 */
static inline int
check_seq_option(struct gro_tcp4_item *item,
		struct tcp_hdr *tcph,
		uint16_t tcp_hl,
		uint16_t tcp_dl,
		uint32_t sent_seq,
		uint16_t l2_offset)
{
	struct rte_mbuf *pkt_orig = item->firstseg;
	struct ipv4_hdr *iph_orig;
	struct tcp_hdr *tcph_orig;
	uint16_t len, l4_len_orig;

	iph_orig = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt_orig, char *) +
			l2_offset + pkt_orig->l2_len);
	tcph_orig = (struct tcp_hdr *)((char *)iph_orig + pkt_orig->l3_len);
	l4_len_orig = pkt_orig->l4_len;

	/* Check if TCP option fields equal */
	len = RTE_MAX(tcp_hl, l4_len_orig) - sizeof(struct tcp_hdr);
	if ((tcp_hl != l4_len_orig) || ((len > 0) &&
				(memcmp(tcph + 1, tcph_orig + 1,
					len) != 0)))
		return 0;

	/* Check if the two packets are neighbors */
	len = pkt_orig->pkt_len - l2_offset - pkt_orig->l2_len -
		pkt_orig->l3_len - l4_len_orig;
	if (sent_seq == item->sent_seq + len)
		/* Append the new packet */
		return 1;
	else if (sent_seq + tcp_dl == item->sent_seq)
		/* Pre-pend the new packet */
		return -1;
	else
		return 0;
}

/*
 * Merge two TCP/IPv4 packets without updating checksums.
 * If cmp is larger than 0, append the new packet to the
 * original packet. Otherwise, pre-pend the new packet to
 * the original packet.
 */
static inline int
merge_two_tcp4_packets(struct gro_tcp4_item *item,
		struct rte_mbuf *pkt,
		uint32_t sent_seq,
		int cmp,
		uint16_t l2_offset)
{
	struct rte_mbuf *pkt_head, *pkt_tail, *lastseg;
	uint16_t hdr_len;

	if (cmp > 0) {
		pkt_head = item->firstseg;
		pkt_tail = pkt;
	} else {
		pkt_head = pkt;
		pkt_tail = item->firstseg;
	}

	/* Check if the length is greater than the max value */
	hdr_len = l2_offset + pkt_head->l2_len + pkt_head->l3_len +
		pkt_head->l4_len;
	if (pkt_head->pkt_len - l2_offset - pkt_head->l2_len +
			pkt_tail->pkt_len - hdr_len > MAX_IPV4_PKT_LENGTH)
		return 0;

	/* Remove packet header for the tail packet */
	rte_pktmbuf_adj(pkt_tail, hdr_len);

	/* Chain two packets together */
	if (cmp > 0) {
		item->lastseg->next = pkt;
		item->lastseg = rte_pktmbuf_lastseg(pkt);
	} else {
		lastseg = rte_pktmbuf_lastseg(pkt);
		lastseg->next = item->firstseg;
		item->firstseg = pkt;
		/* Update sent_seq to the smaller value */
		item->sent_seq = sent_seq;
	}
	item->nb_merged++;

	/* Update mbuf metadata for the merged packet */
	pkt_head->nb_segs += pkt_tail->nb_segs;
	pkt_head->pkt_len += pkt_tail->pkt_len;

	return 1;
}
#endif
