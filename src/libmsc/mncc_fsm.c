/* Handle an MNCC managed call (external MNCC). */
/* At the time of writing, this is only used for inter-MSC handover: forward a voice stream to a remote MSC.
 * Maybe it makes sense to also use it for all "normal" external call management at some point. */
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

#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/msc/mncc_fsm.h>
#include <osmocom/msc/debug.h>
#include <osmocom/msc/gsm_data.h>
#include <osmocom/msc/rtp_stream.h>
#include <osmocom/msc/msub.h>
#include <osmocom/msc/vlr.h>

struct osmo_fsm mncc_fsm;
static bool mncc_tx_rtp_create(struct mncc *mncc);

LLIST_HEAD(mncc_list);

static const struct osmo_tdef_state_timeout mncc_fsm_timeouts[32] = {
	/* TODO */
};

struct gsm_network *gsmnet = NULL;

/* Transition to a state, using the T timer defined in msc_a_fsm_timeouts.
 * The actual timeout value is in turn obtained from network->T_defs.
 * Assumes local variable fi exists. */
#define mncc_fsm_state_chg(MNCC, STATE) \
	osmo_tdef_fsm_inst_state_chg((MNCC)->fi, STATE, mncc_fsm_timeouts, gsmnet->mncc_tdefs, 5)

#define mncc_error(MNCC, FMT, ARGS...) do { \
		LOG_MNCC(MNCC, LOGL_ERROR, FMT, ##ARGS); \
		osmo_fsm_inst_term((MNCC)->fi, OSMO_FSM_TERM_REGULAR, 0); \
	} while(0)

void mncc_fsm_init(struct gsm_network *net)
{
	osmo_fsm_register(&mncc_fsm);
	gsmnet = net;
}

void mncc_fsm_update_id(struct mncc *mncc)
{
	osmo_fsm_inst_update_id_f_sanitize(mncc->fi, '-', "%s:callref-0x%x%s%s",
					   vlr_subscr_name(mncc->vsub), mncc->callref,
					   mncc->remote_msisdn_present ? ":to-msisdn-" : "",
					   mncc->remote_msisdn_present ? mncc->remote_msisdn.number : "");
}

/* Allocate an MNCC FSM as child of the given MSC role FSM.
 * parent_event_call_released is mandatory and is passed as the parent_term_event.
 * parent_event_call_setup_complete is dispatched when the MNCC FSM enters the MNCC_ST_TALKING state.
 * parent_event_call_setup_complete is optional, pass a negative number to avoid dispatching.
 *
 * If non-NULL, forward_cb is invoked whenever an MNCC message is received from the the MNCC socket, which is useful to
 * forward things like DTMF to CC or to another MNCC call.
 *
 * After mncc_alloc(), call either mncc_outgoing_start() or mncc_incoming_start().
 */
struct mncc *mncc_alloc(struct vlr_subscr *vsub,
			struct osmo_fsm_inst *parent,
			int parent_event_call_setup_complete,
			uint32_t parent_event_call_released,
			mncc_forward_cb_t forward_cb, void *forward_cb_data)
{
	struct mncc *mncc;
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&mncc_fsm, parent, parent_event_call_released);
	OSMO_ASSERT(fi);
	OSMO_ASSERT(vsub);

	mncc = talloc_zero(fi, struct mncc);
	OSMO_ASSERT(mncc);
	fi->priv = mncc;

	*mncc = (struct mncc){
		.fi = fi,
		.vsub = vsub,
		.parent_event_call_setup_complete = parent_event_call_setup_complete,
		.forward_cb = forward_cb,
		.forward_cb_data = forward_cb_data,
	};

	llist_add(&mncc->entry, &mncc_list);
	mncc_fsm_update_id(mncc);

	return mncc;
}

void mncc_reparent(struct mncc *mncc,
		   struct osmo_fsm_inst *new_parent,
		   int parent_event_call_setup_complete,
		   uint32_t parent_event_call_released,
		   mncc_forward_cb_t forward_cb, void *forward_cb_data)
{
	LOG_MNCC(mncc, LOGL_DEBUG, "Reparenting from parent %s to parent %s\n",
		 mncc->fi->proc.parent->name, new_parent->name);
	osmo_fsm_inst_change_parent(mncc->fi, new_parent, parent_event_call_released);
	talloc_steal(new_parent, mncc->fi);
	mncc->parent_event_call_setup_complete = parent_event_call_setup_complete;
	mncc->forward_cb = forward_cb;
	mncc->forward_cb_data = forward_cb_data;
}

/* As soon as the MGW endpoint is available and the local side of the RTP stream is set up, this function tells the MNCC
 * about it. Can be called directly after mncc_alloc(), or the caller can first wait for an MSC_MNCC_EV_NEED_LOCAL_RTP,
 * set up the MGW and call mncc_set_rtp_stream() once ready. */
int mncc_set_rtp_stream(struct mncc *mncc, struct rtp_stream *rtps)
{
	if (mncc->rtps && mncc->rtps != rtps) {
		LOG_MNCC(mncc, LOGL_ERROR, "Cannot associate with RTP stream %s, already associated with %s\n",
			 rtps ? rtps->fi->name : "NULL", mncc->rtps->fi->name);
		return -ENOSPC;
	}

	mncc->rtps = rtps;
	LOG_MNCC(mncc, LOGL_DEBUG, "Associated with RTP stream %s\n", mncc->rtps->fi->name);
	return 0;
}

/* When the MNCC FSM ends for any reason, it will release the RTP stream (which usually triggers complete tear down of
 * the call_leg and CC transaction). If the RTP stream should still remain in use, e.g. during Subseqent inter-MSC
 * Handover where this MNCC was a forwarding to a remote MSC that is no longer needed, this function must be called
 * before the MNCC FSM instance terminates. Also call this *before* setting a new remote RTP address on the rtp_stream,
 * since this clears the rtp_stream->remote ip:port information. */
void mncc_detach_rtp_stream(struct mncc *mncc)
{
	struct rtp_stream *rtps = mncc->rtps;
	struct osmo_sockaddr_str clear;
	if (!rtps)
		return;
	mncc->rtps = NULL;
	rtp_stream_set_remote_addr(rtps, &clear);
}

static void mncc_tx_setup_ind(struct mncc *mncc)
{
	struct gsm_mncc mncc_msg = {
		.msg_type = MNCC_SETUP_IND,
		.callref = mncc->callref,
		.clir = {
			.sup = mncc->outgoing_req.clir_sup ? 1 : 0,
			.inv = mncc->outgoing_req.clir_inv ? 1 : 0,
		},
	};

	OSMO_STRLCPY_ARRAY(mncc_msg.imsi, mncc->vsub->imsi);

	if (mncc->outgoing_req.bearer_cap_present) {
		mncc_msg.fields |= MNCC_F_BEARER_CAP;
		mncc_msg.bearer_cap = mncc->outgoing_req.bearer_cap;
	}

	if (mncc->outgoing_req.facility_present) {
		mncc_msg.fields |= MNCC_F_FACILITY;
		mncc_msg.facility = mncc->outgoing_req.facility;
	}

	if (mncc->outgoing_req.called_present) {
		mncc_msg.fields |= MNCC_F_CALLED;
		mncc_msg.called = mncc->outgoing_req.called;

		mncc->remote_msisdn_present = true;
		mncc->remote_msisdn = mncc->outgoing_req.called;
	}

	if (mncc->outgoing_req.calling_present) {
		mncc_msg.fields |= MNCC_F_CALLING;
		mncc_msg.calling = mncc->outgoing_req.calling;

		mncc->local_msisdn_present = true;
		mncc->local_msisdn = mncc->outgoing_req.calling;
	} else {
		/* No explicit calling number set, use the local subscriber */
		mncc_msg.fields |= MNCC_F_CALLING;
		OSMO_STRLCPY_ARRAY(mncc_msg.calling.number, mncc->vsub->msisdn);

		mncc->local_msisdn_present = true;
		mncc->local_msisdn = mncc_msg.calling;
	}

	if (mncc->outgoing_req.useruser_present) {
		mncc_msg.fields |= MNCC_F_USERUSER;
		mncc_msg.useruser = mncc->outgoing_req.useruser;
	}

	if (mncc->outgoing_req.ssversion_present) {
		mncc_msg.fields |= MNCC_F_SSVERSION;
		mncc_msg.ssversion = mncc->outgoing_req.ssversion;
	}

	if (mncc->outgoing_req.cccap_present) {
		mncc_msg.fields |= MNCC_F_CCCAP;
		mncc_msg.cccap = mncc->outgoing_req.cccap;
	}

	if (mncc->outgoing_req.emergency) {
		mncc_msg.fields |= MNCC_F_EMERGENCY;
		mncc_msg.emergency = 1;

		/* use destination number as configured by user (if any) */
		if (gsmnet->emergency.route_to_msisdn
		    && !(mncc_msg.fields & MNCC_F_CALLED)) {
			mncc_msg.fields |= MNCC_F_CALLED;
			mncc_msg.called.type = 0; /* unknown */
			mncc_msg.called.plan = 0; /* unknown */
			OSMO_STRLCPY_ARRAY(mncc_msg.called.number,
					   gsmnet->emergency.route_to_msisdn);
		}
	}

	rate_ctr_inc(&gsmnet->msc_ctrs->ctr[MSC_CTR_CALL_MO_SETUP]);

	mncc_tx(mncc, (union mncc_msg*)&mncc_msg);
}

static void mncc_rx_setup_req(struct mncc *mncc, const struct gsm_mncc *incoming_req)
{
	mncc->callref = incoming_req->callref;

	if (incoming_req->fields & MNCC_F_CALLED) {
		mncc->local_msisdn_present = true;
		mncc->local_msisdn = incoming_req->called;
	}

	if (incoming_req->fields & MNCC_F_CALLING) {
		mncc->remote_msisdn_present = true;
		mncc->remote_msisdn = incoming_req->calling;
	}

	mncc_fsm_update_id(mncc);
}

/* Remote PBX asks for RTP_CREATE. This merely asks us to create an RTP stream, and does not actually contain any useful
 * information like the remote RTP IP:port (these follow in the RTP_CONNECT from the SIP side) */
static bool mncc_rx_rtp_create(struct mncc *mncc)
{
	mncc->received_rtp_create = true;

	if (!mncc->rtps) {
		LOG_MNCC(mncc, LOGL_DEBUG, "Got RTP_CREATE, but no RTP stream associated\n");
		return true;
	}

	if (!osmo_sockaddr_str_is_set(&mncc->rtps->local)) {
		LOG_MNCC(mncc, LOGL_DEBUG, "Got RTP_CREATE, but RTP stream has no local address\n");
		return true;
	}
	
	if (!mncc->rtps->codec_known) {
		LOG_MNCC(mncc, LOGL_DEBUG, "Got RTP_CREATE, but RTP stream has no codec set\n");
		return true;
	}

	LOG_MNCC(mncc, LOGL_DEBUG, "Got RTP_CREATE, responding with " OSMO_SOCKADDR_STR_FMT " %s\n",
		 OSMO_SOCKADDR_STR_FMT_ARGS(&mncc->rtps->local),
		 osmo_mgcpc_codec_name(mncc->rtps->codec));
	/* Already know what RTP IP:port to tell the MNCC. Send it. */
	return mncc_tx_rtp_create(mncc);
}

uint32_t mgcp_codec_to_mncc_payload_msg_type(enum mgcp_codecs codec)
{
	switch (codec) {
	default:
		/* disclaimer: i have no idea what i'm doing. */
	case CODEC_GSM_8000_1:
		return GSM_TCHF_FRAME;
	case CODEC_GSMEFR_8000_1:
		return GSM_TCHF_FRAME_EFR;
	case CODEC_GSMHR_8000_1:
		return GSM_TCHH_FRAME;
	case CODEC_AMR_8000_1:
	case CODEC_AMRWB_16000_1:
		//return GSM_TCHF_FRAME;
		return GSM_TCH_FRAME_AMR;
	}
}

static bool mncc_tx_rtp_create(struct mncc *mncc)
{
	if (!mncc->rtps || !osmo_sockaddr_str_is_set(&mncc->rtps->local)) {
		mncc_error(mncc, "Cannot send RTP_CREATE, no local RTP address set up\n");
		return false;
	}
	struct osmo_sockaddr_str *rtp_local = &mncc->rtps->local;
	union mncc_msg mncc_msg = {
		.rtp = {
			.msg_type = MNCC_RTP_CREATE,
			.callref = mncc->callref,
			.port = rtp_local->port,
		},
	};

	if (osmo_sockaddr_str_to_32n(rtp_local, &mncc_msg.rtp.ip)) {
		mncc_error(mncc, "Failed to compose IP address " OSMO_SOCKADDR_STR_FMT "\n",
			   OSMO_SOCKADDR_STR_FMT_ARGS(rtp_local));
		return false;
	}

	if (mncc->rtps->codec_known) {
		mncc_msg.rtp.payload_type = 0; /* ??? */
		mncc_msg.rtp.payload_msg_type = mgcp_codec_to_mncc_payload_msg_type(mncc->rtps->codec);
	}

	if (mncc_tx(mncc, &mncc_msg))
		return false;
	return true;
}

static bool mncc_rx_rtp_connect(struct mncc *mncc, const struct gsm_mncc_rtp *mncc_msg)
{
	struct osmo_sockaddr_str rtp;

	if (!mncc->rtps) {
		/* The user has not associated an RTP stream, hence we're not supposed to take any action here. */
		return true;
	}

	if (osmo_sockaddr_str_from_32n(&rtp, mncc_msg->ip, mncc_msg->port)) {
		mncc_error(mncc, "Cannot RTP-CONNECT, invalid RTP IP:port in incoming MNCC message\n");
		return false;
	}

	rtp_stream_set_remote_addr(mncc->rtps, &rtp);
	if (rtp_stream_commit(mncc->rtps)) {
		mncc_error(mncc, "RTP-CONNECT, failed, RTP stream is not properly set up: %s\n",
			   mncc->rtps->fi->id);
		return false;
	}
	return true;
}

/* Return true if the FSM instance still exists after this call, false if it was terminated. */
static bool mncc_rx_release_msg(struct mncc *mncc, const union mncc_msg *mncc_msg)
{
	switch (mncc_msg->msg_type) {
	case MNCC_DISC_REQ:
		/* Remote call leg ended the call, MNCC tells us to DISC. We ack with a REL. */
		mncc_tx_msgt(mncc, MNCC_REL_IND);
		osmo_fsm_inst_term(mncc->fi, OSMO_FSM_TERM_REGULAR, 0);
		return false;

	case MNCC_REL_REQ:
		/* MNCC acks with a REL to a previous DISC IND we have (probably) sent.
		 * We ack with a REL CNF. */
		mncc_tx_msgt(mncc, MNCC_REL_CNF);
		osmo_fsm_inst_term(mncc->fi, OSMO_FSM_TERM_REGULAR, 0);
		return false;

	default:
		return true;
	}
}

/* Return true if the FSM instance still exists after this call, false if it was terminated. */
static bool mncc_rx_common_msg(struct mncc *mncc, const union mncc_msg *mncc_msg)
{
	switch (mncc_msg->msg_type) {
	case MNCC_RTP_CREATE:
		mncc_rx_rtp_create(mncc);
		return true;

	case MNCC_RTP_CONNECT:
		mncc_rx_rtp_connect(mncc, &mncc_msg->rtp);
		return true;

	default:
		return mncc_rx_release_msg(mncc, mncc_msg);
	}
}

static void mncc_forward(struct mncc *mncc, const union mncc_msg *mncc_msg)
{
	if (!mncc || !mncc->forward_cb)
		return;
	mncc->forward_cb(mncc, mncc_msg, mncc->forward_cb_data);
}

int mncc_outgoing_start(struct mncc *mncc, const struct mncc_outgoing_call_req *outgoing_req)
{
	if (!mncc)
		return -EINVAL;
	/* By dispatching an event instead of taking direct action, make sure that the FSM permits starting an outgoing
	 * call. */
	return osmo_fsm_inst_dispatch(mncc->fi, MNCC_EV_OUTGOING_START, (void*)outgoing_req);
}

int mncc_incoming_start(struct mncc *mncc, const struct mncc_incoming_call_req *incoming_req)
{
	if (!mncc)
		return -EINVAL;
	/* By dispatching an event instead of taking direct action, make sure that the FSM permits starting an incoming
	 * call. */
	return osmo_fsm_inst_dispatch(mncc->fi, MNCC_EV_INCOMING_START, (void*)incoming_req);
}

void mncc_incoming_tx_call_conf_ind(struct mncc *mncc, const struct gsm_mncc_bearer_cap *bearer_cap)
{
	if (mncc->fi->state != MNCC_ST_INCOMING_WAIT_COMPLETE) {
		LOG_MNCC(mncc, LOGL_ERROR, "%s not allowed in this state\n", __func__);
		return;
	}

	union mncc_msg mncc_msg = {
		.signal = {
			.msg_type = MNCC_CALL_CONF_IND,
			.callref = mncc->callref,
		},
	};

	if (bearer_cap) {
		mncc_msg.signal.fields |= MNCC_F_BEARER_CAP;
		mncc_msg.signal.bearer_cap = *bearer_cap;
	}

	mncc_tx(mncc, &mncc_msg);
}

int mncc_incoming_tx_setup_cnf(struct mncc *mncc, const struct gsm_mncc_number *connected_number)
{
	if (mncc->fi->state != MNCC_ST_INCOMING_WAIT_COMPLETE) {
		LOG_MNCC(mncc, LOGL_ERROR, "%s not allowed in this state\n", __func__);
		return -EINVAL;
	}

	union mncc_msg mncc_msg = {
		.signal = {
			.msg_type = MNCC_SETUP_CNF,
			.callref = mncc->callref,
		},
	};

	if (connected_number) {
		mncc_msg.signal.fields |= MNCC_F_CONNECTED;
		mncc_msg.signal.connected = *connected_number;
	}

	return mncc_tx(mncc, &mncc_msg);
}


static void mncc_fsm_not_started(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc *mncc = fi->priv;
	const struct mncc_outgoing_call_req *outgoing_req;
	const struct mncc_incoming_call_req *incoming_req;

	switch (event) {
	case MNCC_EV_OUTGOING_START:
		outgoing_req = data;
		mncc->outgoing_req = *outgoing_req;
		mncc->callref = msc_cc_next_outgoing_callref();
		mncc_fsm_state_chg(mncc, MNCC_ST_OUTGOING_WAIT_PROCEEDING);
		mncc_tx_setup_ind(mncc);
		return;

	case MNCC_EV_INCOMING_START:
		incoming_req = data;
		mncc_rx_setup_req(mncc, &incoming_req->setup_req_msg);
		mncc_fsm_state_chg(mncc, MNCC_ST_INCOMING_WAIT_COMPLETE);
		mncc_incoming_tx_call_conf_ind(mncc, incoming_req->bearer_cap_present ? &incoming_req->bearer_cap : NULL);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void mncc_fsm_outgoing_wait_proceeding(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc *mncc = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_rx_common_msg(mncc, mncc_msg))
			return;

		switch (mncc_msg->msg_type) {
		case MNCC_CALL_PROC_REQ:
			mncc_fsm_state_chg(mncc, MNCC_ST_OUTGOING_WAIT_COMPLETE);
			break;
		default:
			break;
		}
		
		mncc_forward(mncc, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_fsm_outgoing_wait_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc *mncc = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_rx_common_msg(mncc, mncc_msg))
			return;

		switch (mncc_msg->msg_type) {
		case MNCC_SETUP_RSP:
			mncc_fsm_state_chg(mncc, MNCC_ST_TALKING);
			mncc_tx_msgt(mncc, MNCC_SETUP_COMPL_IND);
			break;
		default:
			break;
		}

		mncc_forward(mncc, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_fsm_incoming_wait_complete(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc *mncc = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_rx_common_msg(mncc, mncc_msg))
			return;

		switch (mncc_msg->msg_type) {
		case MNCC_SETUP_COMPL_REQ:
			mncc_fsm_state_chg(mncc, MNCC_ST_TALKING);
			break;
		default:
			break;
		}

		mncc_forward(mncc, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_fsm_talking(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc *mncc = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_rx_common_msg(mncc, mncc_msg))
			return;
		mncc_forward(mncc, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_fsm_wait_release_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct mncc *mncc = fi->priv;
	const union mncc_msg *mncc_msg;

	switch (event) {
	case MNCC_EV_RX_MNCC_MSG:
		mncc_msg = data;
		if (!mncc_rx_release_msg(mncc, mncc_msg))
			return;
		mncc_forward(mncc, mncc_msg);
		return;

	default:
		OSMO_ASSERT(false);
	};
}

static void mncc_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct mncc *mncc = fi->priv;

	switch (fi->state) {
	case MNCC_ST_NOT_STARTED:
	case MNCC_ST_WAIT_RELEASE_ACK:
		break;
	default:
		/* Make sure we did indicate some sort of release */
		mncc_tx_msgt(mncc, MNCC_REL_IND);
		break;
	}

	/* Releasing the RTP stream should trigger completely tearing down the call leg as well as the CC transaction.
	 * In case of an inter-MSC handover where this MNCC connection is replaced by another MNCC / another BSC
	 * connection, the caller needs to detach the RTP stream from this FSM before terminating it. */
	if (mncc->rtps) {
		rtp_stream_release(mncc->rtps);
		mncc->rtps = NULL;
	}

	llist_del(&mncc->entry);
}

static int mncc_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	return 1;
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state mncc_fsm_states[] = {
	[MNCC_ST_NOT_STARTED] = {
		.name = "NOT_STARTED",
		.in_event_mask = 0
			| S(MNCC_EV_OUTGOING_START)
			| S(MNCC_EV_INCOMING_START)
			,
		.out_state_mask = 0
			| S(MNCC_ST_OUTGOING_WAIT_PROCEEDING)
			| S(MNCC_ST_INCOMING_WAIT_COMPLETE)
			,
		.action = mncc_fsm_not_started,
	},
	[MNCC_ST_OUTGOING_WAIT_PROCEEDING] = {
		.name = "OUTGOING_WAIT_PROCEEDING",
		.in_event_mask = 0
			| S(MNCC_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_ST_OUTGOING_WAIT_COMPLETE)
			,
		.action = mncc_fsm_outgoing_wait_proceeding,
	},
	[MNCC_ST_OUTGOING_WAIT_COMPLETE] = {
		.name = "OUTGOING_WAIT_COMPLETE",
		.in_event_mask = 0
			| S(MNCC_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_ST_TALKING)
			,
		.action = mncc_fsm_outgoing_wait_complete,
	},
	[MNCC_ST_INCOMING_WAIT_COMPLETE] = {
		.name = "INCOMING_WAIT_COMPLETE",
		.in_event_mask = 0
			| S(MNCC_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_ST_TALKING)
			,
		.action = mncc_fsm_incoming_wait_complete,
	},
	[MNCC_ST_TALKING] = {
		.name = "TALKING",
		.in_event_mask = 0
			| S(MNCC_EV_RX_MNCC_MSG)
			,
		.out_state_mask = 0
			| S(MNCC_ST_WAIT_RELEASE_ACK)
			,
		.action = mncc_fsm_talking,
	},
	[MNCC_ST_WAIT_RELEASE_ACK] = {
		.name = "WAIT_RELEASE_ACK",
		.in_event_mask = 0
			| S(MNCC_EV_RX_MNCC_MSG)
			,
		.action = mncc_fsm_wait_release_ack,
	},
};

static const struct value_string mncc_fsm_event_names[] = {
	OSMO_VALUE_STRING(MNCC_EV_RX_MNCC_MSG),

	OSMO_VALUE_STRING(MNCC_EV_OUTGOING_START),
	OSMO_VALUE_STRING(MNCC_EV_OUTGOING_PROCEEDING),
	OSMO_VALUE_STRING(MNCC_EV_OUTGOING_ALERTING),
	OSMO_VALUE_STRING(MNCC_EV_OUTGOING_SETUP_COMPLETE),

	OSMO_VALUE_STRING(MNCC_EV_INCOMING_START),
	OSMO_VALUE_STRING(MNCC_EV_INCOMING_SETUP),
	OSMO_VALUE_STRING(MNCC_EV_INCOMING_SETUP_COMPLETE),

	OSMO_VALUE_STRING(MNCC_EV_CN_RELEASE),
	OSMO_VALUE_STRING(MNCC_EV_MS_RELEASE),
	{}
};

struct osmo_fsm mncc_fsm = {
	.name = "mncc",
	.states = mncc_fsm_states,
	.num_states = ARRAY_SIZE(mncc_fsm_states),
	.log_subsys = DMNCC,
	.event_names = mncc_fsm_event_names,
	.timer_cb = mncc_fsm_timer_cb,
	.cleanup = mncc_fsm_cleanup,
};

/* Invoked by the socket read callback */
void mncc_rx(struct mncc *mncc, const union mncc_msg *mncc_msg)
{
	if (!mncc)
		return;
	LOG_MNCC(mncc, LOGL_DEBUG, "Rx %s\n", get_mncc_name(mncc_msg->msg_type));
	osmo_fsm_inst_dispatch(mncc->fi, MNCC_EV_RX_MNCC_MSG, (void*)mncc_msg);
}

int mncc_tx(struct mncc *mncc, union mncc_msg *mncc_msg)
{
	struct msgb *msg;
	unsigned char *data;

	LOG_MNCC(mncc, LOGL_DEBUG, "tx %s\n", get_mncc_name(mncc_msg->msg_type));

	msg = msgb_alloc(sizeof(*mncc_msg), "MNCC-tx");
	OSMO_ASSERT(msg);

	data = msgb_put(msg, sizeof(*mncc_msg));
	memcpy(data, mncc_msg, sizeof(*mncc_msg));

	if (gsmnet->mncc_recv(gsmnet, msg)) {
		mncc_error(mncc, "Failed to send MNCC message %s\n", get_mncc_name(mncc_msg->msg_type));
		return -EIO;
	}
	return 0;
}

/* Send a trivial MNCC message with just a message type. */
int mncc_tx_msgt(struct mncc *mncc, uint32_t msg_type)
{
	union mncc_msg mncc_msg = {
		.signal = {
			.msg_type = msg_type,
			.callref = mncc->callref,
		},
	};
	return mncc_tx(mncc, &mncc_msg);
}

struct mncc *mncc_find_by_callref(uint32_t callref)
{
	struct mncc *mncc;
	llist_for_each_entry(mncc, &mncc_list, entry) {
		if (mncc->callref == callref)
			return mncc;
	}
	return NULL;
}

void mncc_release(struct mncc *mncc)
{
	if (!mncc)
		return;
	mncc_tx_msgt(mncc, MNCC_DISC_IND);
	mncc_fsm_state_chg(mncc, MNCC_ST_WAIT_RELEASE_ACK);
}
