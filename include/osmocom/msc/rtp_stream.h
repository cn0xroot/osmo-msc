#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/sockaddr_str.h>
#include <osmocom/mgcp_client/mgcp_client.h>

struct gsm_trans;

struct osmo_fsm_inst;
struct call_leg;
struct osmo_mgcpc_ep;
struct osmo_mgcpc_ep_ci;

enum rtp_direction {
	RTP_TO_RAN,
	RTP_TO_CN,
};

extern const struct value_string rtp_direction_names[];
static inline const char *rtp_direction_name(enum rtp_direction val)
{ return get_value_string(rtp_direction_names, val); }

/* A single bidirectional RTP hop between remote and MGW's local RTP port. */
struct rtp_stream {
	struct osmo_fsm_inst *fi;
	struct call_leg *parent_call_leg;
	enum rtp_direction dir;

	uint32_t call_id;

	/* Backpointer for callers (optional) */
	struct gsm_trans *for_trans;

	struct osmo_sockaddr_str local;
	struct osmo_sockaddr_str remote;
	bool remote_sent_to_mgw;

	bool codec_known;
	enum mgcp_codecs codec;
	bool codec_sent_to_mgw;

	struct osmo_mgcpc_ep_ci *ci;

	enum mgcp_connection_mode crcx_conn_mode;
};

#define RTP_STREAM_FMT "local=" RTP_IP_PORT_FMT ",remote=" RTP_IP_PORT_FMT
#define RTP_STREAM_ARGS(RS) RTP_IP_PORT_ARGS(&(RS)->local), RTP_IP_PORT_ARGS(&(RS)->remote),

void rtp_stream_init();

struct rtp_stream *rtp_stream_alloc(struct call_leg *parent_call_leg, enum rtp_direction dir,
				    uint32_t call_id, struct gsm_trans *for_trans);

int rtp_stream_ensure_ci(struct rtp_stream *rtps, struct osmo_mgcpc_ep *at_endpoint);
int rtp_stream_do_mdcx(struct rtp_stream *rtps);

void rtp_stream_set_codec(struct rtp_stream *rtps, enum mgcp_codecs codec);
void rtp_stream_set_remote_addr(struct rtp_stream *rtps, const struct osmo_sockaddr_str *r);
int rtp_stream_commit(struct rtp_stream *rtps);

void rtp_stream_release(struct rtp_stream *rtps);

bool rtp_stream_is_established(struct rtp_stream *rtps);
