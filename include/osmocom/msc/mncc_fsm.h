/* Handle an MNCC managed call (external MNCC). */
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

#pragma once

#include <osmocom/msc/mncc.h>

struct osmo_fsm_inst;
struct rtp_stream;

#define LOG_MNCC(MNCC, LEVEL, FMT, ARGS...) \
	LOGPFSML((MNCC) ? (MNCC)->fi : NULL, LEVEL, FMT, ##ARGS)

enum mncc_fsm_event {
	MNCC_EV_RX_MNCC_MSG,

	MNCC_EV_OUTGOING_START,
	MNCC_EV_OUTGOING_PROCEEDING,
	MNCC_EV_OUTGOING_ALERTING,
	MNCC_EV_OUTGOING_SETUP_COMPLETE,

	MNCC_EV_INCOMING_START,
	MNCC_EV_INCOMING_SETUP,
	MNCC_EV_INCOMING_SETUP_COMPLETE,

	MNCC_EV_CN_RELEASE,
	MNCC_EV_MS_RELEASE,
};

enum mncc_fsm_state {
	MNCC_ST_NOT_STARTED = 0,

	MNCC_ST_OUTGOING_WAIT_PROCEEDING,
	MNCC_ST_OUTGOING_WAIT_COMPLETE,

	MNCC_ST_INCOMING_WAIT_COMPLETE,

	MNCC_ST_TALKING,

	MNCC_ST_WAIT_RELEASE_ACK,
};

struct mncc_outgoing_call_req {
	bool bearer_cap_present;
	struct gsm_mncc_bearer_cap bearer_cap;

	bool facility_present;
	struct gsm_mncc_facility facility;

	bool called_present;
	struct gsm_mncc_number called;

	/* If no calling number is set, mncc->vsub->msisdn is used as calling number */
	bool calling_present;
	struct gsm_mncc_number calling;

	bool useruser_present;
	struct gsm_mncc_useruser useruser;

	bool ssversion_present;
	struct gsm_mncc_ssversion ssversion;

	bool cccap_present;
	struct gsm_mncc_cccap cccap;

	bool emergency;
	bool clir_sup;
	bool clir_inv;
};

struct mncc_incoming_call_req {
	bool bearer_cap_present;
	struct gsm_mncc_bearer_cap bearer_cap;

	bool cccap_present;
	struct gsm_mncc_cccap cccap;

	struct gsm_mncc setup_req_msg;
};

struct mncc;
typedef void (* mncc_forward_cb_t )(struct mncc *mncc, const union mncc_msg *mncc_msg, void *data);

struct mncc {
	struct llist_head entry;

	struct osmo_fsm_inst *fi;
	struct vlr_subscr *vsub;
	struct gsm_network *net;

	struct mncc_outgoing_call_req outgoing_req;

	uint32_t callref;
	bool remote_msisdn_present;
	struct gsm_mncc_number remote_msisdn;
	bool local_msisdn_present;
	struct gsm_mncc_number local_msisdn;
	struct rtp_stream *rtps;
	bool received_rtp_create;

	mncc_forward_cb_t forward_cb;
	void *forward_cb_data;

	int parent_event_call_setup_complete;
};

void mncc_fsm_init(struct gsm_network *net);
struct mncc *mncc_alloc(struct vlr_subscr *vsub,
			struct osmo_fsm_inst *parent,
			int parent_event_call_setup_complete,
			uint32_t parent_event_call_released,
			mncc_forward_cb_t forward_cb, void *forward_cb_data);
void mncc_reparent(struct mncc *mncc,
		   struct osmo_fsm_inst *new_parent,
		   int parent_event_call_setup_complete,
		   uint32_t parent_event_call_released,
		   mncc_forward_cb_t forward_cb, void *forward_cb_data);

int mncc_outgoing_start(struct mncc *mncc, const struct mncc_outgoing_call_req *outgoing_req);

int mncc_incoming_start(struct mncc *mncc, const struct mncc_incoming_call_req *incoming_req);
int mncc_incoming_tx_setup_cnf(struct mncc *mncc, const struct gsm_mncc_number *connected_number);

int mncc_set_rtp_stream(struct mncc *mncc, struct rtp_stream *rtps);
void mncc_detach_rtp_stream(struct mncc *mncc);

void mncc_rx(struct mncc *mncc, const union mncc_msg *mncc_msg);
int mncc_tx(struct mncc *mncc, union mncc_msg *mncc_msg);
int mncc_tx_msgt(struct mncc *mncc, uint32_t msg_type);

struct mncc *mncc_find_by_callref(uint32_t callref);

void mncc_release(struct mncc *mncc);
