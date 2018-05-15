#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <osmocom/msc/gsm_data.h>

#define GSM_NAME_LENGTH 160

#define GSM_EXTENSION_LENGTH 15 /* MSISDN can only be 15 digits length */
#define GSM_MIN_EXTEN 20000
#define GSM_MAX_EXTEN 49999

#define GSM_SUBSCRIBER_FIRST_CONTACT	0x00000001
/* gprs_sgsn.h defines additional flags including and above bit 16 (0x10000) */

#define GSM_SUBSCRIBER_NO_EXPIRATION	0x0
#define GSM_SUBSCRIBER_LU_EXPIRATION_INTERVAL	60	/* in seconds */

enum gsm_subscriber_field {
	GSM_SUBSCRIBER_IMSI,
	GSM_SUBSCRIBER_TMSI,
	GSM_SUBSCRIBER_EXTENSION,
	GSM_SUBSCRIBER_ID,
};

enum gsm_subscriber_update_reason {
	GSM_SUBSCRIBER_UPDATE_ATTACHED,
	GSM_SUBSCRIBER_UPDATE_DETACHED,
	GSM_SUBSCRIBER_UPDATE_EQUIPMENT,
};

/*
 * Struct for pending channel requests. This is managed in the
 * llist_head requests of each subscriber. The reference counting
 * should work in such a way that a subscriber with a pending request
 * remains in memory.
 */
struct subscr_request {
       struct llist_head entry;

       /* human readable label to be able to log pending request kinds */
       const char *label;

       /* the callback data */
       gsm_cbfn *cbfn;
       void *param;
};

int subscr_update(struct vlr_subscr *vsub, int reason);

/*
 * Paging handling with authentication
 */
struct subscr_request *subscr_request_conn(struct vlr_subscr *vsub,
					   gsm_cbfn *cbfn, void *param,
					   const char *label);

void subscr_remove_request(struct subscr_request *req);
int subscr_rx_paging_response(struct msgb *msg,
			      struct gsm_subscriber_connection *conn);

void subscr_paging_cancel(struct vlr_subscr *vsub, enum gsm_paging_event event);
int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
			   struct msgb *msg, void *data, void *param);

/* Find an allocated channel for a specified subscriber */
struct gsm_subscriber_connection *connection_for_subscr(struct vlr_subscr *vsub);

#endif /* _GSM_SUBSCR_H */
