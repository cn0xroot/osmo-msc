/* Common bits for NAS message handling */
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

#include <osmocom/msc/nas.h>

const struct value_string nas_msg_type_names[] = {
	{ NAS_MSG_NONE, "NONE" },
	{ NAS_MSG_COMPL_L3, "COMPL_L3" },
	{ NAS_MSG_DTAP, "DTAP" },
	{ NAS_MSG_CLEAR_COMMAND, "CLEAR_COMMAND" },
	{ NAS_MSG_CLEAR_REQUEST, "CLEAR_REQUEST" },
	{ NAS_MSG_CLEAR_COMPLETE, "CLEAR_COMPLETE" },
	{ NAS_MSG_CLASSMARK_REQUEST, "CLASSMARK_REQUEST" },
	{ NAS_MSG_CLASSMARK_UPDATE, "CLASSMARK_UPDATE" },
	{ NAS_MSG_CIPHER_MODE_COMMAND, "CIPHER_MODE_COMMAND" },
	{ NAS_MSG_CIPHER_MODE_COMPLETE, "CIPHER_MODE_COMPLETE" },
	{ NAS_MSG_CIPHER_MODE_REJECT, "CIPHER_MODE_REJECT" },
	{ NAS_MSG_COMMON_ID, "COMMON_ID" },
	{ NAS_MSG_ASSIGNMENT_COMMAND, "ASSIGNMENT_COMMAND" },
	{ NAS_MSG_ASSIGNMENT_COMPLETE, "ASSIGNMENT_COMPLETE" },
	{ NAS_MSG_ASSIGNMENT_FAILURE, "ASSIGNMENT_FAILURE" },
	{ NAS_MSG_SAPI_N_REJECT, "SAPI_N_REJECT" },
	{ NAS_MSG_LCLS_STATUS, "LCLS_STATUS" },
	{ NAS_MSG_LCLS_BREAK_REQ, "LCLS_BREAK_REQ" },
	{ NAS_MSG_HANDOVER_COMMAND, "HANDOVER_COMMAND" },
	{ NAS_MSG_HANDOVER_SUCCEEDED, "HANDOVER_SUCCEEDED" },
	{ NAS_MSG_HANDOVER_PERFORMED, "HANDOVER_PERFORMED" },
	{ NAS_MSG_HANDOVER_REQUIRED, "HANDOVER_REQUIRED" },
	{ NAS_MSG_HANDOVER_REQUIRED_REJECT, "HANDOVER_REQUIRED_REJECT" },
	{ NAS_MSG_HANDOVER_REQUEST, "HANDOVER_REQUEST" },
	{ NAS_MSG_HANDOVER_REQUEST_ACK, "HANDOVER_REQUEST_ACK" },
	{ NAS_MSG_HANDOVER_DETECT, "HANDOVER_DETECT" },
	{ NAS_MSG_HANDOVER_COMPLETE, "HANDOVER_COMPLETE" },
	{ NAS_MSG_HANDOVER_FAILURE, "HANDOVER_FAILURE" },
	{}
};

/* extract the N(SD) and return the modulo value for a R99 message */
static uint8_t nas_dec_dtap_undup_determine_nsd_ret_modulo_r99(uint8_t pdisc, uint8_t msg_type, uint8_t *n_sd)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		*n_sd = (msg_type >> 6) & 0x3;
		return 4;
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		*n_sd = (msg_type >> 6) & 0x1;
		return 2;
	default:
		/* no sequence number, we cannot detect dups */
		return 0;
	}
}

/* extract the N(SD) and return the modulo value for a R98 message */
static uint8_t gsm0407_determine_nsd_ret_modulo_r98(uint8_t pdisc, uint8_t msg_type, uint8_t *n_sd)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		*n_sd = (msg_type >> 6) & 0x1;
		return 2;
	default:
		/* no sequence number, we cannot detect dups */
		return 0;
	}
}

/* TS 24.007 11.2.3.2.3 Message Type Octet / Duplicate Detection.
 * (Not static for unit testing). */
int nas_dec_dtap_undup_pdisc_ctr_bin(uint8_t pdisc)
{
	switch (pdisc) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		return 0;
	case GSM48_PDISC_GROUP_CC:
		return 1;
	case GSM48_PDISC_BCAST_CC:
		return 2;
	case GSM48_PDISC_LOC:
		return 3;
	default:
		return -1;
	}
}

/* TS 24.007 11.2.3.2 Message Type Octet / Duplicate Detection */
bool nas_dec_dtap_undup_is_duplicate(struct osmo_fsm_inst *log_fi, uint8_t *n_sd_next, bool is_r99, struct msgb *l3)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t n_sd, modulo;
	int bin;

	gh = msgb_l3(l3);
	pdisc = gsm48_hdr_pdisc(gh);

	if (is_r99) {
		modulo = nas_dec_dtap_undup_determine_nsd_ret_modulo_r99(pdisc, gh->msg_type, &n_sd);
	} else { /* pre R99 */
		modulo = gsm0407_determine_nsd_ret_modulo_r98(pdisc, gh->msg_type, &n_sd);
	}
	if (modulo == 0)
		return false;
	bin = nas_dec_dtap_undup_pdisc_ctr_bin(pdisc);
	if (bin < 0)
		return false;

	OSMO_ASSERT(bin >= 0 && bin < 4);
	if (n_sd != n_sd_next[bin]) {
		/* not what we expected: duplicate */
		LOGPFSML(log_fi, LOGL_NOTICE, "Duplicate DTAP: bin=%d, expected n_sd == %u, got %u\n",
			 bin, n_sd_next[bin], n_sd);
		return true;
	} else {
		/* as expected: no dup; update expected counter for next message */
		n_sd_next[bin] = (n_sd + 1) % modulo;
		return false;
	}
}

/* convenience: NAS decode implementations can call this to dispatch the decode_cb with a decoded nas_msg. */
int nas_decoded(struct nas_dec *nas_dec, struct nas_msg *nas_msg)
{
	if (!nas_dec->decode_cb)
		return -1;
	return nas_dec->decode_cb(nas_dec->caller_fi, nas_dec->caller_data, nas_msg);
}
