/* Lookup table for various RAN implementations */
/*
 * (C) 2019 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <osmocom/core/utils.h>
#include <osmocom/core/tdef.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/nas_a.h>
#include <osmocom/msc/nas_iu.h>
#include <osmocom/msc/ran_peer.h>

#include <osmocom/msc/ran_infra.h>

#include "config.h"

const struct value_string an_proto_names[] = {
	{ OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_48006, "Ts3G-48006" },
	{ OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_25413, "Ts3G-25413" },
	{}
};

#define RAN_TDEFS \
	{ .T = -1, .default_val = 5, .desc = "RAN connection Complete Layer 3, Authentication and Ciphering timeout" }, \
	{ .T = -2, .default_val = 30, .desc = "RAN connection release sanity timeout" }, \
	{ .T = -3, .default_val = 10, .desc = "Timeout to find a target BSS after Handover Required" }, \

struct osmo_tdef msc_tdefs_geran[] = {
	RAN_TDEFS
	{}
};

struct osmo_tdef msc_tdefs_utran[] = {
	RAN_TDEFS
	{}
};

struct osmo_tdef msc_tdefs_sgs[] = {
	{}
};

void ran_infra_init()
{
	osmo_tdefs_reset(msc_tdefs_geran);
	osmo_tdefs_reset(msc_tdefs_utran);
	osmo_tdefs_reset(msc_tdefs_sgs);
}

struct ran_infra msc_ran_infra[] = {
	[OSMO_RAT_UNKNOWN] = {
		.type = OSMO_RAT_UNKNOWN,
		.log_subsys = DMSC,
		.tdefs = msc_tdefs_geran,
	},
	[OSMO_RAT_GERAN_A] = {
		.type = OSMO_RAT_GERAN_A,
		.an_proto = OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_48006,
		.ssn = OSMO_SCCP_SSN_BSSAP,
		.log_subsys = DBSSAP,
		.tdefs = msc_tdefs_geran,
		.sccp_ran_ops = {
			.up_l2 = ran_peer_up_l2,
			.disconnect = ran_peer_disconnect,
			.is_reset_msg = bssmap_is_reset_msg,
			.make_reset_msg = bssmap_make_reset_msg,
			.make_paging_msg = bssmap_make_paging_msg,
			.msg_name = bssmap_msg_name,
		},
		.nas_dec_l2 = nas_a_decode_l2,
		.nas_encode = nas_a_encode,
	},
	[OSMO_RAT_UTRAN_IU] = {
		.type = OSMO_RAT_UTRAN_IU,
		.an_proto = OSMO_GSUP_ACCESS_NETWORK_PROTOCOL_TS3G_25413,
		.ssn = OSMO_SCCP_SSN_RANAP,
		.log_subsys = DIUCS,
		.tdefs = msc_tdefs_utran,
#if BUILD_IU
		.sccp_ran_ops = {
			.up_l2 = ran_peer_up_l2,
			.disconnect = ran_peer_disconnect,
			.is_reset_msg = ranap_is_reset_msg,
			.make_reset_msg = ranap_make_reset_msg,
			.make_paging_msg = ranap_make_paging_msg,
			.msg_name = ranap_msg_name,
		},
		.nas_dec_l2 = nas_iu_decode_l2,
		.nas_encode = nas_iu_encode,
#endif
	},
	[OSMO_RAT_EUTRAN_SGS] = {
		.type = OSMO_RAT_EUTRAN_SGS,
		.log_subsys = DSGS,
		.nas_encode = NULL,
		.tdefs = msc_tdefs_sgs,
	},
};

const int msc_ran_infra_len = ARRAY_SIZE(msc_ran_infra);
