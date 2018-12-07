#pragma once

#include <osmocom/gsm/gsup.h>
#include <osmocom/msc/gsup_client_mux.h>

struct gsup_client_mux;
struct ipaccess_unit;

struct gsup_client_mux_rx_cb {
	int (* func )(struct gsup_client_mux *gcm, void *data, const struct osmo_gsup_message *gsup_msg);
	void *data;
};

struct gsup_client_mux {
	struct osmo_gsup_client *gsup_client;

	/* Target clients by enum osmo_gsup_kind */
	struct gsup_client_mux_rx_cb rx_cb[OSMO_GSUP_KIND_ARRAYSIZE];
};

struct gsup_client_mux *gsup_client_mux_alloc(void *talloc_ctx);
int gsup_client_mux_start(struct gsup_client_mux *gcm, const char *gsup_server_addr_str, uint16_t gsup_server_port,
			  struct ipaccess_unit *ipa_dev);

int gsup_client_mux_tx(struct gsup_client_mux *gcm, const struct osmo_gsup_message *gsup_msg);
void gsup_client_mux_tx_error_reply(struct gsup_client_mux *gcm, const struct osmo_gsup_message *gsup_orig,
				    enum gsm48_gmm_cause cause);

int gsup_client_mux_rx(struct osmo_gsup_client *gsup_client, struct msgb *msg);
