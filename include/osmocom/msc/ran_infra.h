#pragma once

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/msc/sccp_ran.h>
#include <osmocom/msc/nas.h>

struct osmo_tdef;

extern struct osmo_tdef msc_tdefs_geran[];
extern struct osmo_tdef msc_tdefs_utran[];
extern struct osmo_tdef msc_tdefs_sgs[];

extern const struct value_string an_proto_names[];
static inline const char *an_proto_name(enum osmo_gsup_access_network_protocol val)
{ return get_value_string(an_proto_names, val); }

struct ran_infra {
	const enum osmo_rat_type type;
	const enum osmo_gsup_access_network_protocol an_proto;
	uint32_t ssn;
	const int log_subsys;
	struct osmo_tdef * const tdefs;
	const struct sccp_ran_ops sccp_ran_ops;
	const nas_dec_l2_t nas_dec_l2;
	const nas_encode_t nas_encode;
	struct sccp_ran_inst *sri;
};

extern struct ran_infra msc_ran_infra[];
extern const int msc_ran_infra_len;

void ran_infra_init();
