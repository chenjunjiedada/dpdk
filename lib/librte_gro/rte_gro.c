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

#include "rte_gro.h"
#include "gro_tcp4.h"
#include "gro_vxlan_tcp4.h"

typedef void *(*gro_tbl_create_fn)(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow);
typedef void (*gro_tbl_destroy_fn)(void *tbl);
typedef uint32_t (*gro_tbl_pkt_count_fn)(void *tbl);

static gro_tbl_create_fn tbl_create_fn[RTE_GRO_TYPE_MAX_NUM] = {
		gro_tcp4_tbl_create, gro_vxlan_tcp4_tbl_create, NULL};
static gro_tbl_destroy_fn tbl_destroy_fn[RTE_GRO_TYPE_MAX_NUM] = {
			gro_tcp4_tbl_destroy, gro_vxlan_tcp4_tbl_destroy,
			NULL};
static gro_tbl_pkt_count_fn tbl_pkt_count_fn[RTE_GRO_TYPE_MAX_NUM] = {
			gro_tcp4_tbl_pkt_count, gro_vxlan_tcp4_tbl_pkt_count,
			NULL};

#define IS_IPV4_TCP_PKT(ptype) (RTE_ETH_IS_IPV4_HDR(ptype) && \
		((ptype & RTE_PTYPE_L4_TCP) == RTE_PTYPE_L4_TCP))

#define IS_IPV4_VXLAN_TCP4_PKT(ptype) (RTE_ETH_IS_IPV4_HDR(ptype) && \
		((ptype & RTE_PTYPE_L4_UDP) == RTE_PTYPE_L4_UDP) && \
		((ptype & RTE_PTYPE_TUNNEL_VXLAN) == \
		 RTE_PTYPE_TUNNEL_VXLAN) && \
		 ((ptype & RTE_PTYPE_INNER_L4_TCP) == \
		  RTE_PTYPE_INNER_L4_TCP) && \
		  (((ptype & RTE_PTYPE_INNER_L3_MASK) & \
		    (RTE_PTYPE_INNER_L3_IPV4 | \
		     RTE_PTYPE_INNER_L3_IPV4_EXT | \
		     RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN)) != 0))

/*
 * GRO context structure, which is used to merge packets. It keeps
 * many reassembly tables of desired GRO types. Applications need to
 * create GRO context objects before using rte_gro_reassemble to
 * perform GRO.
 */
struct gro_ctx {
	/* GRO types to perform */
	uint64_t gro_types;
	/* reassembly tables */
	void *tbls[RTE_GRO_TYPE_MAX_NUM];
};

void *
rte_gro_ctx_create(const struct rte_gro_param *param)
{
	struct gro_ctx *gro_ctx;
	gro_tbl_create_fn create_tbl_fn;
	uint64_t gro_type_flag = 0;
	uint64_t gro_types = 0;
	uint8_t i;

	gro_ctx = rte_zmalloc_socket(__func__,
			sizeof(struct gro_ctx),
			RTE_CACHE_LINE_SIZE,
			param->socket_id);
	if (gro_ctx == NULL)
		return NULL;

	for (i = 0; i < RTE_GRO_TYPE_MAX_NUM; i++) {
		gro_type_flag = 1ULL << i;
		if ((param->gro_types & gro_type_flag) == 0)
			continue;

		create_tbl_fn = tbl_create_fn[i];
		if (create_tbl_fn == NULL)
			continue;

		gro_ctx->tbls[i] = create_tbl_fn(param->socket_id,
				param->max_flow_num,
				param->max_item_per_flow);
		if (gro_ctx->tbls[i] == NULL) {
			/* destroy all created tables */
			gro_ctx->gro_types = gro_types;
			rte_gro_ctx_destroy(gro_ctx);
			return NULL;
		}
		gro_types |= gro_type_flag;
	}
	gro_ctx->gro_types = param->gro_types;

	return gro_ctx;
}

void
rte_gro_ctx_destroy(void *ctx)
{
	gro_tbl_destroy_fn destroy_tbl_fn;
	struct gro_ctx *gro_ctx = ctx;
	uint64_t gro_type_flag;
	uint8_t i;

	if (gro_ctx == NULL)
		return;
	for (i = 0; i < RTE_GRO_TYPE_MAX_NUM; i++) {
		gro_type_flag = 1ULL << i;
		if ((gro_ctx->gro_types & gro_type_flag) == 0)
			continue;
		destroy_tbl_fn = tbl_destroy_fn[i];
		if (destroy_tbl_fn)
			destroy_tbl_fn(gro_ctx->tbls[i]);
	}
	rte_free(gro_ctx);
}

uint16_t
rte_gro_reassemble_burst(struct rte_mbuf **pkts,
		uint16_t nb_pkts,
		const struct rte_gro_param *param)
{
	/* Allocate a reassembly table for TCP/IPv4 GRO. */
	struct gro_tcp4_tbl tcp_tbl;
	struct gro_tcp4_flow tcp_flows[RTE_GRO_MAX_BURST_ITEM_NUM];
	struct gro_tcp4_item tcp_items[RTE_GRO_MAX_BURST_ITEM_NUM] = {{0} };

	/* Allocate a reassembly table for VXLAN GRO. */
	struct gro_vxlan_tcp4_tbl vxlan_tbl;
	struct gro_vxlan_tcp4_flow vxlan_flows[RTE_GRO_MAX_BURST_ITEM_NUM];
	struct gro_vxlan_tcp4_item vxlan_items[RTE_GRO_MAX_BURST_ITEM_NUM] = {
		{{0}, 0} };

	struct rte_mbuf *unprocess_pkts[nb_pkts];
	uint64_t current_time;
	uint32_t item_num;
	int32_t ret;
	uint16_t i, unprocess_num = 0, nb_after_gro = nb_pkts;
	uint8_t do_tcp4_gro = 0, do_vxlan_tcp4_gro = 0;

	if ((param->gro_types & (RTE_GRO_IPV4_VXLAN_TCP_IPV4 |
					RTE_GRO_TCP_IPV4)) == 0)
		return nb_pkts;

	/* Get the actual number of packets. */
	item_num = RTE_MIN(nb_pkts, (param->max_flow_num *
				param->max_item_per_flow));
	item_num = RTE_MIN(item_num, RTE_GRO_MAX_BURST_ITEM_NUM);

	if (param->gro_types & RTE_GRO_IPV4_VXLAN_TCP_IPV4) {
		for (i = 0; i < item_num; i++)
			vxlan_flows[i].start_index = INVALID_ARRAY_INDEX;

		vxlan_tbl.flows = vxlan_flows;
		vxlan_tbl.items = vxlan_items;
		vxlan_tbl.flow_num = 0;
		vxlan_tbl.item_num = 0;
		vxlan_tbl.max_flow_num = item_num;
		vxlan_tbl.max_item_num = item_num;
		do_vxlan_tcp4_gro = 1;
	}

	if (param->gro_types & RTE_GRO_TCP_IPV4) {
		for (i = 0; i < item_num; i++)
			tcp_flows[i].start_index = INVALID_ARRAY_INDEX;

		tcp_tbl.flows = tcp_flows;
		tcp_tbl.items = tcp_items;
		tcp_tbl.flow_num = 0;
		tcp_tbl.item_num = 0;
		tcp_tbl.max_flow_num = item_num;
		tcp_tbl.max_item_num = item_num;
		do_tcp4_gro = 1;
	}

	current_time = rte_rdtsc();

	for (i = 0; i < nb_pkts; i++) {
		if (do_vxlan_tcp4_gro && IS_IPV4_VXLAN_TCP4_PKT(
					pkts[i]->packet_type)) {
			ret = gro_vxlan_tcp4_reassemble(pkts[i], &vxlan_tbl,
					current_time);
			if (ret > 0)
				/* Merge successfully */
				nb_after_gro--;
			else if (ret < 0)
				unprocess_pkts[unprocess_num++] = pkts[i];
		} else if (do_tcp4_gro && IS_IPV4_TCP_PKT(
					pkts[i]->packet_type)) {
			ret = gro_tcp4_reassemble(pkts[i], &tcp_tbl,
					current_time);
			if (ret > 0)
				/* Merge successfully */
				nb_after_gro--;
			else if (ret < 0)
				unprocess_pkts[unprocess_num++] = pkts[i];
		} else
			unprocess_pkts[unprocess_num++] = pkts[i];
	}

	if (nb_after_gro < nb_pkts) {
		i = 0;
		/* Flush packets from the tables. */
		if (do_vxlan_tcp4_gro) {
			i = gro_vxlan_tcp4_tbl_timeout_flush(&vxlan_tbl,
					current_time, pkts, nb_pkts);
		}
		if (do_tcp4_gro) {
			i += gro_tcp4_tbl_timeout_flush(&tcp_tbl,
					current_time, &pkts[i], nb_pkts - i);
		}
		/* Copy unprocessed packets. */
		if (unprocess_num > 0) {
			memcpy(&pkts[i], unprocess_pkts,
					sizeof(struct rte_mbuf *) *
					unprocess_num);
		}
	}

	return nb_after_gro;
}

uint16_t
rte_gro_reassemble(struct rte_mbuf **pkts,
		uint16_t nb_pkts,
		void *ctx)
{
	struct rte_mbuf *unprocess_pkts[nb_pkts];
	struct gro_ctx *gro_ctx = ctx;
	void *tbl;
	uint64_t current_time;
	uint16_t i, unprocess_num = 0;
	uint8_t do_tcp4_gro = 0, do_vxlan_tcp4_gro = 0;

	if ((gro_ctx->gro_types & (RTE_GRO_IPV4_VXLAN_TCP_IPV4 |
					RTE_GRO_TCP_IPV4)) == 0)
		return nb_pkts;
	if (gro_ctx->gro_types & RTE_GRO_IPV4_VXLAN_TCP_IPV4)
		do_vxlan_tcp4_gro = 1;
	if (gro_ctx->gro_types & RTE_GRO_TCP_IPV4)
		do_tcp4_gro = 1;

	current_time = rte_rdtsc();

	for (i = 0; i < nb_pkts; i++) {
		if (do_vxlan_tcp4_gro && IS_IPV4_VXLAN_TCP4_PKT(
					pkts[i]->packet_type)) {
			tbl = gro_ctx->tbls[RTE_GRO_IPV4_VXLAN_TCP_IPV4_INDEX];
			if (gro_vxlan_tcp4_reassemble(pkts[i], tbl,
						current_time) < 0)
				unprocess_pkts[unprocess_num++] = pkts[i];
		} else if (do_tcp4_gro && IS_IPV4_TCP_PKT(
					pkts[i]->packet_type)) {
			tbl = gro_ctx->tbls[RTE_GRO_TCP_IPV4_INDEX];
			if (gro_tcp4_reassemble(pkts[i], tbl,
						current_time) < 0)
				unprocess_pkts[unprocess_num++] = pkts[i];
		} else
			unprocess_pkts[unprocess_num++] = pkts[i];
	}
	if (unprocess_num > 0) {
		memcpy(pkts, unprocess_pkts,
				sizeof(struct rte_mbuf *) *
				unprocess_num);
	}

	return unprocess_num;
}

uint16_t
rte_gro_timeout_flush(void *ctx,
		uint64_t timeout_cycles,
		uint64_t gro_types,
		struct rte_mbuf **out,
		uint16_t max_nb_out)
{
	struct gro_ctx *gro_ctx = ctx;
	uint64_t flush_timestamp;
	uint16_t num = 0;

	gro_types = gro_types & gro_ctx->gro_types;
	flush_timestamp = rte_rdtsc() - timeout_cycles;

	if (gro_types & RTE_GRO_IPV4_VXLAN_TCP_IPV4) {
		num = gro_vxlan_tcp4_tbl_timeout_flush(gro_ctx->tbls[
				RTE_GRO_IPV4_VXLAN_TCP_IPV4_INDEX],
				flush_timestamp, out, max_nb_out);
	}

	max_nb_out -= num;
	if ((gro_types & RTE_GRO_TCP_IPV4) && max_nb_out > 0) {
		num += gro_tcp4_tbl_timeout_flush(
				gro_ctx->tbls[RTE_GRO_TCP_IPV4_INDEX],
				flush_timestamp,
				&out[num], max_nb_out);
	}

	return num;
}

uint64_t
rte_gro_get_pkt_count(void *ctx)
{
	struct gro_ctx *gro_ctx = ctx;
	gro_tbl_pkt_count_fn pkt_count_fn;
	uint64_t item_num = 0;
	uint64_t gro_type_flag;
	uint8_t i;

	for (i = 0; i < RTE_GRO_TYPE_MAX_NUM; i++) {
		gro_type_flag = 1ULL << i;
		if ((gro_ctx->gro_types & gro_type_flag) == 0)
			continue;

		pkt_count_fn = tbl_pkt_count_fn[i];
		if (pkt_count_fn == NULL)
			continue;
		item_num += pkt_count_fn(gro_ctx->tbls[i]);
	}

	return item_num;
}
