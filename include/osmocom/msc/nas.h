/* API to forward upcoming NAS events, e.g. from BSSAP and RANAP, to be handled by MSC-A or MSC-I. */
/*
 * (C) 2019 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <neels@hofmeyr.de>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/sockaddr_str.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#include <osmocom/msc/msc_common.h>

struct msgb;
struct osmo_fsm_inst;

#define LOG_NAS_DEC(NAS_DEC, subsys, level, fmt, args...) \
	LOGPFSMSL((NAS_DEC)? (NAS_DEC)->caller_fi : NULL, subsys, level, "NAS decode: " fmt, ## args)

#define LOG_NAS_ENC(FI, subsys, level, fmt, args...) \
	LOGPFSMSL(FI, subsys, level, "NAS encode: " fmt, ## args)

/* These message types are named after the BSSAP procedures in nas_a.h; most are also used for RANAP procedures of
 * similar meaning in nas_iu.h. */
enum nas_msg_type {
	NAS_MSG_NONE = 0,
	NAS_MSG_COMPL_L3,
	NAS_MSG_DTAP,
	NAS_MSG_CLEAR_COMMAND,
	NAS_MSG_CLEAR_REQUEST,
	NAS_MSG_CLEAR_COMPLETE,
	NAS_MSG_CLASSMARK_REQUEST,
	NAS_MSG_CLASSMARK_UPDATE,
	NAS_MSG_CIPHER_MODE_COMMAND,
	NAS_MSG_CIPHER_MODE_COMPLETE,
	NAS_MSG_CIPHER_MODE_REJECT,
	NAS_MSG_COMMON_ID,
	NAS_MSG_ASSIGNMENT_COMMAND,
	NAS_MSG_ASSIGNMENT_COMPLETE,
	NAS_MSG_ASSIGNMENT_FAILURE,
	NAS_MSG_SAPI_N_REJECT,
	NAS_MSG_LCLS_STATUS,
	NAS_MSG_LCLS_BREAK_REQ,
	NAS_MSG_HANDOVER_COMMAND,
	NAS_MSG_HANDOVER_PERFORMED,
	NAS_MSG_HANDOVER_REQUIRED,
	NAS_MSG_HANDOVER_REQUIRED_REJECT,
	NAS_MSG_HANDOVER_REQUEST,
	NAS_MSG_HANDOVER_REQUEST_ACK,
	NAS_MSG_HANDOVER_DETECT,
	NAS_MSG_HANDOVER_SUCCEEDED,
	NAS_MSG_HANDOVER_COMPLETE,
	NAS_MSG_HANDOVER_FAILURE,
};

extern const struct value_string nas_msg_type_names[];
static inline const char *nas_msg_type_name(enum nas_msg_type val)
{ return get_value_string(nas_msg_type_names, val); }

struct nas_clear_command {
	enum gsm0808_cause gsm0808_cause;
	bool csfb_ind;
};

struct nas_assignment_command {
	const struct osmo_sockaddr_str *cn_rtp;
	const struct gsm0808_channel_type *channel_type;
	enum nsap_addr_enc rab_assign_addr_enc;
};

struct nas_cipher_mode_command {
	const struct osmo_auth_vector *vec;
	const struct osmo_gsm48_classmark *classmark;
	struct {
		bool umts_aka;
		bool retrieve_imeisv;
		uint8_t a5_encryption_mask;

		/* out-argument to return the key to the caller, pass NULL if not needed. */
		struct geran_encr *chosen_key;
	} geran;
};

struct nas_handover_request {
	const char *imsi;
	const struct osmo_gsm48_classmark *classmark;
	struct {
		struct gsm0808_channel_type *channel_type;
		uint8_t a5_encryption_mask;
		/*! chosen_encryption->alg_id is in encoded format:
		 * alg_id == 1 means A5/0 i.e. no encryption, alg_id == 4 means A5/3.
		 * alg_id == 0 means no such IE was present. */
		struct geran_encr *chosen_encryption;
	} geran;
	struct gsm0808_cell_id cell_id_serving;
	struct gsm0808_cell_id cell_id_target;

	enum gsm0808_cause bssap_cause;

	bool current_channel_type_1_present;
	uint8_t current_channel_type_1;

	enum gsm0808_permitted_speech speech_version_used;

	const uint8_t *old_bss_to_new_bss_info_raw;
	uint8_t old_bss_to_new_bss_info_raw_len;

	struct osmo_sockaddr_str *rtp_ran_local;

	struct gsm0808_speech_codec_list *codec_list_msc_preferred;

	bool call_id_present;
	uint32_t call_id;

	const uint8_t *global_call_reference;
	uint8_t global_call_reference_len;
};

struct nas_handover_request_ack {
	const uint8_t *rr_ho_command;
	uint8_t rr_ho_command_len;
	bool chosen_channel_present;
	uint8_t chosen_channel;
	/*! chosen_encr_alg is in encoded format:
	 * chosen_encr_alg == 1 means A5/0 i.e. no encryption, chosen_encr_alg == 4 means A5/3.
	 * chosen_encr_alg == 0 means no such IE was present. */
	uint8_t chosen_encr_alg;

	/* chosen_speech_version == 0 means "not present" */
	enum gsm0808_permitted_speech chosen_speech_version;

	struct osmo_sockaddr_str remote_rtp;
	bool codec_present;
	enum mgcp_codecs codec;
};

struct nas_handover_command {
	const uint8_t *rr_ho_command;
	uint8_t rr_ho_command_len;

	const uint8_t *new_bss_to_old_bss_info_raw;
	uint8_t new_bss_to_old_bss_info_raw_len;
};

struct nas_handover_required {
	uint16_t cause;
	struct gsm0808_cell_id_list2 cil;

	bool current_channel_type_1_present;
	/*! See gsm0808_chosen_channel() */
	uint8_t current_channel_type_1;

	enum gsm0808_permitted_speech speech_version_used;

	uint8_t *old_bss_to_new_bss_info_raw;
	size_t old_bss_to_new_bss_info_raw_len;
};

struct nas_msg {
	enum nas_msg_type msg_type;

	/* Since different RAN implementations feed these messages, they should place here an implementation specific
	 * string constant to name the actual message (e.g. "BSSMAP Assignment Complete" vs. "RANAP RAB Assignment
	 * Response") */
	const char *msg_name;

	union {
		struct {
			const struct gsm0808_cell_id *cell_id;
			struct msgb *msg;
		} compl_l3;
		struct msgb *dtap;
		struct {
			enum gsm0808_cause bssap_cause;
#define NAS_MSG_BSSAP_CAUSE_UNSET 0xffff
		} clear_request;
		struct nas_clear_command clear_command;
		struct {
			const struct osmo_gsm48_classmark *classmark;
		} classmark_update;
		struct nas_cipher_mode_command cipher_mode_command;
		struct {
			/*! alg_id is in encoded format:
			 * alg_id == 1 means A5/0 i.e. no encryption, alg_id == 4 means A5/3.
			 * alg_id == 0 means no such IE was present. */
			uint8_t alg_id;
			const char *imeisv;
		} cipher_mode_complete;
		struct {
			enum gsm0808_cause bssap_cause;
		} cipher_mode_reject;
		struct {
			const char *imsi;
		} common_id;
		struct {
			enum gsm48_reject_value cause;
		} cm_service_reject;
		struct nas_assignment_command assignment_command;
		struct {
			struct osmo_sockaddr_str remote_rtp;
			bool codec_present;
			enum mgcp_codecs codec;
		} assignment_complete;
		struct {
			enum gsm0808_cause bssap_cause;
			uint8_t rr_cause;
			const struct gsm0808_speech_codec_list *scl_bss_supported;
		} assignment_failure;
		struct {
			enum gsm0808_cause bssap_cause;
			uint8_t dlci;
		} sapi_n_reject;
		struct {
			enum gsm0808_lcls_status status;
		} lcls_status;
		struct {
			int todo;
		} lcls_break_req;
		struct nas_handover_required handover_required;
		struct gsm0808_handover_required_reject handover_required_reject;
		struct nas_handover_command handover_command;
		struct {
			enum gsm0808_cause cause;
		} handover_failure;
		struct nas_handover_request handover_request;
		struct nas_handover_request_ack handover_request_ack;
	};
};

/* MSC-A/I/T roles implement this to receive decoded NAS messages, upon feeding an L2 msgb to a nas_dec_l2_t matching the
 * RAN type implementation. */
typedef int (* nas_decode_cb_t )(struct osmo_fsm_inst *caller_fi, void *caller_data, const struct nas_msg *msg);

struct nas_dec {
	/* caller provided osmo_fsm_inst, used both for logging from within decoding of NAS events, as well as caller's
	 * context in decode_cb(). */
	struct osmo_fsm_inst *caller_fi;
	void *caller_data;

	/* Callback receives the decoded NAS messages */
	nas_decode_cb_t decode_cb;
};

/* NAS decoders (BSSAP/RANAP) implement this to turn a msgb into a struct nas_msg.
 * An implementation typically calls nas_decoded() when done decoding.
 * NAS decoding is modeled with a callback instead of a plain decoding, because some L2 messages by design contain more
 * than one NAS event, e.g. Ciphering Mode Complete may include another L3 message for Identity Response, and LCLS
 * Information messages can contain Status and Break Req events. */
typedef int (* nas_dec_l2_t )(struct nas_dec *nas_dec, struct msgb *l2);

int nas_decoded(struct nas_dec *nas_dec, struct nas_msg *msg);

/* An MSC-A/I/T role that receives NAS events containing DTAP buffers may use this to detect DTAP duplicates as in TS
 * 24.007 11.2.3.2 Message Type Octet / Duplicate Detection */
bool nas_dec_dtap_undup_is_duplicate(struct osmo_fsm_inst *log_fi, uint8_t *n_sd_next, bool is_r99, struct msgb *l3);

/* Implemented by individual RAN implementations, see nas_a_encode() and nas_iu_encode(). */
typedef struct msgb *(* nas_encode_t )(struct osmo_fsm_inst *caller_fi, const struct nas_msg *nas_enc_msg);
