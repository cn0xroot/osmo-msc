/* RANAP encoding and decoding for MSC */
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

#include <asn1c/asn1helpers.h>

#include <osmocom/core/prim.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/ranap/ranap_common_cn.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#include <osmocom/ranap/iu_helpers.h>

#include <osmocom/msc/debug.h>
#include <osmocom/msc/msc_common.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/nas_iu.h>

/* Implement the extern talloc_asn1_ctx from libasn1c as talloc ctx for ASN.1 message composition */
void *talloc_asn1_ctx = NULL;

/* Implement the extern asn_debug from libasn1c to indicate whether to print asn.1 debug messages. */
int asn_debug = 0;

/* Implement the extern asn1_xer_print to indicate whether the ASN.1 binary code decoded and encoded during Iu
 * communication should be logged to stderr (see asn.1 generated code in osmo-iuh). */
int asn1_xer_print = 0;

#define LOG_NAS_IU_DEC(NAS_DEC, level, fmt, args...) \
	LOG_NAS_DEC(NAS_DEC, DIUCS, level, "RANAP: " fmt, ## args)

#define LOG_NAS_IU_ENC(FI, level, fmt, args...) \
	LOG_NAS_ENC(FI, DIUCS, level, "RANAP: " fmt, ## args)

static void nas_iu_decode_l3_initial(struct nas_dec *nas_iu_decode, const RANAP_InitialUE_MessageIEs_t *ies, const char *msg_name)
{
	struct msgb *nas = msgb_alloc(256, msg_name);
	struct nas_msg nas_dec_msg;

	struct osmo_plmn_id plmn;

	if (ies->lai.pLMNidentity.size < 3) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Too short PLMNidentity in RANAP InitialUE message\n");
		return;
	}
	osmo_plmn_from_bcd(ies->lai.pLMNidentity.buf, &plmn);

	struct gsm0808_cell_id cid = {
		.id_discr = CELL_IDENT_LAI,
		.id.lai_and_lac = {
			.plmn = plmn,
			.lac = asn1str_to_u16(&ies->lai.lAC),
		},
	};

	/* TODO: really necessary to copy the NAS PDU?? */
	nas->l3h = msgb_put(nas, ies->nas_pdu.size);
	memcpy(nas->l3h, ies->nas_pdu.buf, ies->nas_pdu.size);

	nas_dec_msg = (struct nas_msg){
		.msg_type = NAS_MSG_COMPL_L3,
		.msg_name = msg_name,
		.compl_l3 = {
			.cell_id = &cid,
			.msg = nas,
		},
	};
	nas_decoded(nas_iu_decode, &nas_dec_msg);

	msgb_free(nas);
}

static void nas_iu_decode_l3(struct nas_dec *nas_iu_decode, RANAP_NAS_PDU_t *nas_pdu, const char *msg_name)
{
	struct msgb *nas = msgb_alloc(256, msg_name);
	struct nas_msg nas_dec_msg;

	/* TODO: really necessary to copy the NAS PDU?? */
	nas->l3h = msgb_put(nas, nas_pdu->size);
	memcpy(nas->l3h, nas_pdu->buf, nas_pdu->size);

	nas_dec_msg = (struct nas_msg){
		.msg_type = NAS_MSG_DTAP,
		.msg_name = msg_name,
		.dtap = nas,
	};
	nas_decoded(nas_iu_decode, &nas_dec_msg);

	msgb_free(nas);
}

static void nas_iu_decode_err(struct nas_dec *nas_iu_decode, RANAP_ErrorIndicationIEs_t *ies)
{
	LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Rx Error Indication (%s)\n",
		   (ies->presenceMask & ERRORINDICATIONIES_RANAP_CAUSE_PRESENT)?
		       ranap_cause_str(&ies->cause) : "no cause specified");
}

static int nas_iu_decode_rab_assignment_response_decode_setup_ies(struct nas_dec *nas_iu_decode,
							      struct nas_msg *nas_dec_msg,
							      RANAP_RAB_SetupOrModifiedItemIEs_t *setup_ies)
{
	RANAP_RAB_SetupOrModifiedItem_t *item;
	RANAP_TransportLayerAddress_t *transp_layer_addr;
	RANAP_IuTransportAssociation_t *transp_assoc;
	uint16_t port = 0;
	char addr[INET_ADDRSTRLEN];
	uint8_t rab_id;

	item = &setup_ies->raB_SetupOrModifiedItem;

	rab_id = item->rAB_ID.buf[0];
	LOG_NAS_IU_DEC(nas_iu_decode, LOGL_DEBUG, "Received RAB assignment response for rab_id=%d\n", rab_id);

	if (!(item->iuTransportAssociation && item->transportLayerAddress)) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "RAB Assignment Response does not contain RAB information\n");
		return -1;
	}

	transp_layer_addr = item->transportLayerAddress;
	transp_assoc = item->iuTransportAssociation;

	if (ranap_transp_assoc_decode(&port, transp_assoc)) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Unable to decode RTP port in RAB Assignment Response\n");
		return -1;
	}

	if (ranap_transp_layer_addr_decode(addr, sizeof(addr), transp_layer_addr)) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Unable to decode IP-Address in RAB Assignment Response\n");
		return -1;
	}

	*nas_dec_msg = (struct nas_msg){
		.msg_type = NAS_MSG_ASSIGNMENT_COMPLETE,
		.msg_name = "RANAP RAB Assignment Response",
		.assignment_complete = {
			.codec = CODEC_AMR_8000_1,
		},
	};
	if (osmo_sockaddr_str_from_str(&nas_dec_msg->assignment_complete.remote_rtp, addr, port)) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Assignment Complete: unable to decode remote RTP IP address %s\n",
			      osmo_quote_str(addr, -1));
		return -1;
	}
	return 0;
}

static void nas_iu_decode_rab_assignment_response(struct nas_dec *nas_iu_decode, const RANAP_RAB_AssignmentResponseIEs_t *ies)
{
	int rc;
	RANAP_IE_t *ranap_ie;
	RANAP_RAB_SetupOrModifiedItemIEs_t setup_ies;
	struct nas_msg nas_dec_msg;
	bool free_ies = false;

	if (!(ies->presenceMask & RAB_ASSIGNMENTRESPONSEIES_RANAP_RAB_SETUPORMODIFIEDLIST_PRESENT)) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "RAB Assignment Response does not contain RAB information\n");
		goto failure;
	}

	/* So far we assign a single RAB at a time, so it should not be necessary to iterate over the list of
	 * SetupOrModifiedList IEs and handle each one. */
	ranap_ie = ies->raB_SetupOrModifiedList.raB_SetupOrModifiedList_ies.list.array[0];

	rc = ranap_decode_rab_setupormodifieditemies_fromlist(&setup_ies, &ranap_ie->value);
	if (rc) {
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Error in ranap_decode_rab_setupormodifieditemies(): rc=%d\n", rc);
		goto failure;
	}
	free_ies = true;

	if (!nas_iu_decode_rab_assignment_response_decode_setup_ies(nas_iu_decode, &nas_dec_msg, &setup_ies))
		goto success;

failure:
	nas_dec_msg = (struct nas_msg){
		.msg_type = NAS_MSG_ASSIGNMENT_FAILURE,
		.msg_name = "RANAP RAB Assignment Response: Failure",
		.assignment_failure = {
			.bssap_cause = NAS_MSG_BSSAP_CAUSE_UNSET,
			.rr_cause = GSM48_RR_CAUSE_ABNORMAL_UNSPEC,
		},
	};

success:
	nas_decoded(nas_iu_decode, &nas_dec_msg);

	if (free_ies)
		ranap_free_rab_setupormodifieditemies(&setup_ies);
}

static void nas_iu_decode_security_mode_complete(struct nas_dec *nas_iu_decode)
{
	struct nas_msg nas_dec_msg = {
		.msg_type = NAS_MSG_CIPHER_MODE_COMPLETE,
		.msg_name = "RANAP SecurityModeControl successfulOutcome",
	};
	nas_decoded(nas_iu_decode, &nas_dec_msg);
}

static void nas_iu_decode_security_mode_reject(struct nas_dec *nas_iu_decode)
{
	struct nas_msg nas_dec_msg = {
		.msg_type = NAS_MSG_CIPHER_MODE_REJECT,
		.msg_name = "RANAP SecurityModeControl unsuccessfulOutcome",
		.cipher_mode_reject = {
			.bssap_cause = NAS_MSG_BSSAP_CAUSE_UNSET,
		},
	};
	nas_decoded(nas_iu_decode, &nas_dec_msg);
}

static void nas_iu_decode_release_request(struct nas_dec *nas_iu_decode)
{
	struct nas_msg nas_dec_msg = {
		.msg_type = NAS_MSG_CLEAR_REQUEST,
		.msg_name = "RANAP Iu ReleaseRequest",
		.clear_request = {
			.bssap_cause = NAS_MSG_BSSAP_CAUSE_UNSET,
		},
	};
	nas_decoded(nas_iu_decode, &nas_dec_msg);
}

static void nas_iu_decode_release_complete(struct nas_dec *nas_iu_decode)
{
	struct nas_msg nas_dec_msg = {
		.msg_type = NAS_MSG_CLEAR_COMPLETE,
		.msg_name = "RANAP Iu Release successfulOutcome",
	};
	nas_decoded(nas_iu_decode, &nas_dec_msg);
}

static void nas_iu_decode_ranap_msg(void *_nas_dec, ranap_message *message)
{
	struct nas_dec *nas_iu_decode = _nas_dec;

	LOG_NAS_IU_DEC(nas_iu_decode, LOGL_DEBUG, "dir=%u proc=%u\n", message->direction, message->procedureCode);

	switch (message->procedureCode) {

	case RANAP_ProcedureCode_id_InitialUE_Message:
		nas_iu_decode_l3_initial(nas_iu_decode, &message->msg.initialUE_MessageIEs, "RANAP InitialUE NAS PDU");
		return;

	case RANAP_ProcedureCode_id_DirectTransfer:
		nas_iu_decode_l3(nas_iu_decode, &message->msg.directTransferIEs.nas_pdu, "RANAP DirectTransfer NAS PDU");
		return;

	case RANAP_ProcedureCode_id_SecurityModeControl:
		switch (message->direction) {
		case RANAP_RANAP_PDU_PR_successfulOutcome:
			nas_iu_decode_security_mode_complete(nas_iu_decode);
			return;
		case RANAP_RANAP_PDU_PR_unsuccessfulOutcome:
			nas_iu_decode_security_mode_reject(nas_iu_decode);
			return;
		default:
			LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR,
				   "Received SecurityModeControl: unexpected RANAP ProcedureCode: %d\n",
				   message->direction);
			return;
		}

	case RANAP_ProcedureCode_id_RAB_Assignment:
		/* This should always be a RANAP_RANAP_PDU_PR_outcome. No need to check for that. */
		nas_iu_decode_rab_assignment_response(nas_iu_decode, &message->msg.raB_AssignmentResponseIEs);
		return;

	case RANAP_ProcedureCode_id_Iu_ReleaseRequest:
		nas_iu_decode_release_request(nas_iu_decode);
		return;

	case RANAP_ProcedureCode_id_Iu_Release:
		if (message->direction != RANAP_RANAP_PDU_PR_successfulOutcome) {
			LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Received Iu_Release: expected successfulOutcome, got %d\n",
				   message->direction);
			return;
		}
		nas_iu_decode_release_complete(nas_iu_decode);
		return;

	case RANAP_ProcedureCode_id_ErrorIndication:
		nas_iu_decode_err(nas_iu_decode, &message->msg.errorIndicationIEs);
		return;

	default:
		LOG_NAS_IU_DEC(nas_iu_decode, LOGL_ERROR, "Received unhandled RANAP Procedure Code %d\n", message->procedureCode);
		return;
	}
}

int nas_iu_decode_l2(struct nas_dec *nas_iu_decode, struct msgb *ranap)
{
	return ranap_cn_rx_co(nas_iu_decode_ranap_msg, nas_iu_decode, msgb_l2(ranap), msgb_l2len(ranap));
}

/* Create a RANAP Initiating DirectTransfer message containing the given DTAP as NAS PDU, and return the resulting
 * AN-APDU to be forwarded via E-interface. */
static struct msgb *nas_iu_wrap_dtap(struct msgb *dtap)
{
	struct msgb *an_apdu;
	an_apdu = ranap_new_msg_dt(0, dtap->data, msgb_length(dtap));
	an_apdu->l2h = an_apdu->data;
	msgb_free(dtap);
	return an_apdu;
}

static struct msgb *nas_iu_make_rab_assignment(struct osmo_fsm_inst *caller_fi, const struct nas_assignment_command *ac)
{
	struct msgb *msg;
	bool use_x213_nsap;
	uint32_t cn_rtp_ip;
	static uint8_t next_rab_id = 1;
	uint8_t rab_id = next_rab_id;

	next_rab_id ++;
	if (!next_rab_id)
		next_rab_id = 1;

	cn_rtp_ip = osmo_htonl(inet_addr(ac->cn_rtp->ip));

	if (cn_rtp_ip == INADDR_NONE) {
		LOG_NAS_IU_ENC(caller_fi, LOGL_ERROR, "Error during RAB Assignment: invalid RTP IP-Address\n");
		return NULL;
	}
	if (ac->cn_rtp->port == 0) {
		LOG_NAS_IU_ENC(caller_fi, LOGL_ERROR, "Error during RAB Assignment: invalid RTP port\n");
		return NULL;
	}

	use_x213_nsap = (ac->rab_assign_addr_enc == NSAP_ADDR_ENC_X213);
	LOG_NAS_IU_ENC(caller_fi, LOGL_DEBUG, "RAB Assignment: rab_id=%d, rtp=" OSMO_SOCKADDR_STR_FMT ", use_x213_nsap=%d\n",
			rab_id, OSMO_SOCKADDR_STR_FMT_ARGS(ac->cn_rtp), use_x213_nsap);

	msg = ranap_new_msg_rab_assign_voice(rab_id, cn_rtp_ip, ac->cn_rtp->port, use_x213_nsap);
	msg->l2h = msg->data;

	return msg;
}

static struct msgb *nas_iu_make_security_mode_command(struct osmo_fsm_inst *caller_fi,
						      const struct nas_cipher_mode_command *cm)
{

	LOG_NAS_IU_ENC(caller_fi, LOGL_DEBUG, "Tx RANAP SECURITY MODE COMMAND to RNC, ik %s\n",
			osmo_hexdump_nospc(cm->vec->ik, 16));
	return ranap_new_msg_sec_mod_cmd(cm->vec->ik, NULL, RANAP_KeyStatus_new);
}


static struct msgb *nas_iu_make_release_command(struct osmo_fsm_inst *caller_fi,
						   const struct nas_clear_command *ccmd)
{
	static const struct RANAP_Cause cause = {
		.present = RANAP_Cause_PR_radioNetwork,
		.choice.radioNetwork = RANAP_CauseRadioNetwork_release_due_to_utran_generated_reason,
		/* TODO: set various causes depending on the nas_clear_command cause value */
	};
	return ranap_new_msg_iu_rel_cmd(&cause);
}

struct msgb *nas_iu_encode(struct osmo_fsm_inst *caller_fi, const struct nas_msg *nas_enc_msg)
{
	LOG_NAS_IU_ENC(caller_fi, LOGL_DEBUG, "%s\n", nas_msg_type_name(nas_enc_msg->msg_type));

	switch (nas_enc_msg->msg_type) {

	case NAS_MSG_DTAP:
		return nas_iu_wrap_dtap(nas_enc_msg->dtap);

	// TODO: NAS_MSG_CLASSMARK_REQUEST ??

	case NAS_MSG_CIPHER_MODE_COMMAND:
		return nas_iu_make_security_mode_command(caller_fi, &nas_enc_msg->cipher_mode_command);

	case NAS_MSG_ASSIGNMENT_COMMAND:
		return nas_iu_make_rab_assignment(caller_fi, &nas_enc_msg->assignment_command);

	case NAS_MSG_COMMON_ID:
		return ranap_new_msg_common_id(nas_enc_msg->common_id.imsi);

	case NAS_MSG_CLEAR_COMMAND:
		return nas_iu_make_release_command(caller_fi, &nas_enc_msg->clear_command);

	default:
		LOG_NAS_IU_ENC(caller_fi, LOGL_ERROR, "Message type not implemented: %s\n",
				nas_msg_type_name(nas_enc_msg->msg_type));
		return NULL;
	}
}

/* Entry point for connection-less RANAP message */
static void ranap_handle_cl(void *ctx, ranap_message *message)
{
	int *rc = ctx;
	*rc = SCCP_RAN_MSG_NON_RESET;

	if (message->procedureCode != RANAP_ProcedureCode_id_Reset)
		return;

	switch (message->direction) {
	case RANAP_RANAP_PDU_PR_initiatingMessage:
		*rc = SCCP_RAN_MSG_RESET;
		return;
	case RANAP_RANAP_PDU_PR_successfulOutcome:
		*rc = SCCP_RAN_MSG_RESET_ACK;
		return;
	default:
		return;
	}
}

enum reset_msg_type ranap_is_reset_msg(const struct sccp_ran_inst *sri, const struct msgb *l2)
{
	int ret = SCCP_RAN_MSG_NON_RESET;
	int rc;

	rc = ranap_cn_rx_cl(ranap_handle_cl, &ret, msgb_l2(l2), msgb_l2len(l2));
	if (rc)
		return 0;
	return ret;
}

struct msgb *ranap_make_reset_msg(const struct sccp_ran_inst *sri, enum reset_msg_type type)
{
	const RANAP_Cause_t cause = {
		.present = RANAP_Cause_PR_protocol,
		.choice = {
			.protocol = RANAP_CauseProtocol_message_not_compatible_with_receiver_state,
		},
	};
	switch (type) {
	case SCCP_RAN_MSG_RESET:
		return ranap_new_msg_reset(RANAP_CN_DomainIndicator_cs_domain, &cause);
	case SCCP_RAN_MSG_RESET_ACK:
		return ranap_new_msg_reset_ack(RANAP_CN_DomainIndicator_cs_domain, NULL);
	default:
		return NULL;
	}
}

static e_RANAP_PagingCause ranap_paging_cause_from_msc(enum paging_cause cause)
{
	switch (cause) {
	default:
	case PAGING_CAUSE_UNSPECIFIED:
	case PAGING_CAUSE_CALL_CONVERSATIONAL:
		return RANAP_PagingCause_terminating_conversational_call;
	case PAGING_CAUSE_CALL_STREAMING:
		return RANAP_PagingCause_terminating_streaming_call;
	case PAGING_CAUSE_CALL_INTERACTIVE:
		return RANAP_PagingCause_terminating_interactive_call;
	case PAGING_CAUSE_CALL_BACKGROUND:
		return RANAP_PagingCause_terminating_background_call;
	case PAGING_CAUSE_SIGNALLING_LOW_PRIO:
		return RANAP_PagingCause_terminating_low_priority_signalling;
	case PAGING_CAUSE_SIGNALLING_HIGH_PRIO:
		return RANAP_PagingCause_terminating_high_priority_signalling;
	}
}

struct msgb *ranap_make_paging_msg(const struct sccp_ran_inst *sri, const struct gsm0808_cell_id *page_cell_id,
				   const char *imsi, uint32_t tmsi, enum paging_cause cause)
{
	return ranap_new_msg_paging_cmd(imsi, tmsi == GSM_RESERVED_TMSI ? NULL : &tmsi, false,
					ranap_paging_cause_from_msc(cause));
}

const char *ranap_msg_name(const struct sccp_ran_inst *sri, const struct msgb *l2)
{
	uint8_t msgt;
	uint8_t procedure;
	static char buf[32];
	if (!l2->l2h)
		return "?";

	msgt = l2->l2h[0];
	procedure = l2->l2h[1];

	snprintf(buf, sizeof(buf), "type %u procedureCode %u", msgt, procedure);
	return buf;
}
