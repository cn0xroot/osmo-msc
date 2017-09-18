/* OsmoMSC - Circuit-Switched Core Network (MSC+VLR+HLR+SMSC) implementation
 */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Based on OsmoNITB:
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 *
 */

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <getopt.h>

/* build switches from the configure script */
#include "../../bscconfig.h"

#include <osmocom/msc/db.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <osmocom/msc/debug.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/talloc.h>
#include <osmocom/msc/signal.h>
#include <osmocom/msc/osmo_msc.h>
#include <osmocom/msc/bsc_msc_data.h>
#include <osmocom/msc/sms_queue.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/logging.h>
#include <osmocom/msc/vty.h>
#include <osmocom/msc/mncc.h>
#include <osmocom/msc/handover_decision.h>
#include <osmocom/msc/rrlp.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/msc/ctrl.h>
#include <osmocom/msc/smpp.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/mgcp_client/mgcp_client.h>

#ifdef BUILD_IU
#include <osmocom/ranap/iu_client.h>
#endif

#include <osmocom/msc/msc_ifaces.h>
#include <osmocom/msc/iucs.h>
#include <osmocom/msc/iucs_ranap.h>
#include <osmocom/msc/a_iface.h>

static const char * const osmomsc_copyright =
	"OsmoMSC - Osmocom Circuit-Switched Core Network implementation\r\n"
	"Copyright (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n"
	"Based on OsmoNITB:\r\n"
	"  (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>\r\n"
	"  (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>\r\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\r\n"
	"Dieter Spaar, Andreas Eversberg, Sylvain Munaut, Neels Hofmeyr\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

void *tall_msc_ctx = NULL;

/* satisfy deps from libbsc legacy.
   TODO double check these */
void *tall_fle_ctx = NULL;
void *tall_paging_ctx = NULL;
void *tall_map_ctx = NULL;
void *tall_upq_ctx = NULL;
/* end deps from libbsc legacy. */

static struct {
	const char *database_name;
	const char *config_file;
	int daemonize;
	const char *mncc_sock_path;
	int use_db_counter;
} msc_cmdline_config = {
	"sms.db",
	"osmo-msc.cfg",
	0,
	0,
	1
};

/* timer to store statistics */
#define DB_SYNC_INTERVAL	60, 0
#define EXPIRE_INTERVAL		10, 0

static struct osmo_timer_list db_sync_timer;

static void print_usage()
{
	printf("Usage: osmo-nitb\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help                  This text.\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -s --disable-color\n");
	printf("  -l --database db-name      The database to use.\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -V --version               Print the version of OpenBSC.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");
	printf("  -M --mncc-sock-path PATH   Disable built-in MNCC handler and offer socket.\n");
	printf("  -m --mncc-sock             Same as `-M /tmp/bsc_mncc' (deprecated).\n");
	printf("  -C --no-dbcounter          Disable regular syncing of counters to database.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"database", 1, 0, 'l'},
			{"timestamp", 0, 0, 'T'},
			{"version", 0, 0, 'V' },
			{"log-level", 1, 0, 'e'},
			{"mncc-sock", 0, 0, 'm'},
			{"mncc-sock-path", 1, 0, 'M'},
			{"no-dbcounter", 0, 0, 'C'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dsl:TVc:e:mCM:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			msc_cmdline_config.daemonize = 1;
			break;
		case 'l':
			msc_cmdline_config.database_name = optarg;
			break;
		case 'c':
			msc_cmdline_config.config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'M':
			msc_cmdline_config.mncc_sock_path = optarg;
			break;
		case 'm':
			msc_cmdline_config.mncc_sock_path = "/tmp/bsc_mncc";
			break;
		case 'C':
			msc_cmdline_config.use_db_counter = 0;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
		}
	}
}

struct gsm_network *msc_network_alloc(void *ctx,
				      mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net = gsm_network_init(ctx, 1, 1, mncc_recv);
	if (!net)
		return NULL;

	net->name_long = talloc_strdup(net, "OsmoMSC");
	net->name_short = talloc_strdup(net, "OsmoMSC");

	net->gsup_server_addr_str = talloc_strdup(net,
						  MSC_HLR_REMOTE_IP_DEFAULT);
	net->gsup_server_port = MSC_HLR_REMOTE_PORT_DEFAULT;

	mgcp_client_conf_init(&net->mgw.conf);

	return net;
}

void msc_network_shutdown(struct gsm_network *net)
{
	/* nothing here yet */
}

static struct gsm_network *msc_network = NULL;

extern void *tall_vty_ctx;
static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		msc_network_shutdown(msc_network);
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		osmo_generate_backtrace();
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_msc_ctx, stderr);
		break;
	case SIGUSR2:
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

/* timer handling */
static int _db_store_counter(struct osmo_counter *counter, void *data)
{
	return db_store_counter(counter);
}

static void db_sync_timer_cb(void *data)
{
	/* store counters to database and re-schedule */
	osmo_counters_for_each(_db_store_counter, NULL);
	osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info msc_vty_info = {
	.name		= "OsmoMSC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

#ifdef BUILD_IU
static int rcvmsg_iu_cs(struct msgb *msg, struct gprs_ra_id *ra_id, uint16_t *sai)
{
	DEBUGP(DIUCS, "got IuCS message"
	       " %d bytes: %s\n",
	       msg->len, osmo_hexdump(msg->data, msg->len));
	if (ra_id) {
		DEBUGP(DIUCS, "got IuCS message on"
		       " MNC %d MCC %d LAC %d RAC %d\n",
		       ra_id->mnc, ra_id->mcc, ra_id->lac, ra_id->rac);
	}

	return gsm0408_rcvmsg_iucs(msc_network, msg, ra_id? &ra_id->lac : NULL);
}

static int rx_iu_event(struct ranap_ue_conn_ctx *ctx, enum ranap_iu_event_type type,
		       void *data)
{
	DEBUGP(DIUCS, "got IuCS event %u: %s\n", type,
	       ranap_iu_event_type_str(type));

	return iucs_rx_ranap_event(msc_network, ctx, type, data);
}
#endif

#define DEFAULT_M3UA_REMOTE_IP "127.0.0.1"
#define DEFAULT_PC_A "0.23.1"
#define DEFAULT_PC_IU "0.23.2"
#define DEFAULT_PC_A_IU DEFAULT_PC_A

static struct osmo_sccp_instance *sccp_setup(void *ctx, uint32_t cs7_instance,
					     const char *label, const char *default_pc_str)
{
	int default_pc = osmo_ss7_pointcode_parse(NULL, default_pc_str);
	if (default_pc < 0)
		return NULL;

	return osmo_sccp_simple_client_on_ss7_id(ctx, cs7_instance, label, default_pc,
						 OSMO_SS7_ASP_PROT_M3UA,
						 0, NULL, /* local: use arbitrary port and 0.0.0.0. */
						 0, /* remote: use protocol default port */
						 DEFAULT_M3UA_REMOTE_IP);
	/* Note: If a differing remote IP is to be used, it was already entered in the vty config at
	 * 'cs7' / 'asp' / 'remote-ip', and this default remote IP has no effect.
	 * Similarly, 'cs7' / 'listen' can specify the local IP address. */
}

static int ss7_setup(void *ctx)
{
	uint32_t cs7_instance_a = msc_network->a.cs7_instance;
#if BUILD_IU
	uint32_t cs7_instance_iu = msc_network->iu.cs7_instance;

	if (cs7_instance_a == cs7_instance_iu) {
		/* Create one single SCCP instance which will be used for both,
		 * Iu and A at the same time, under the same point-code */
		LOGP(DMSC, LOGL_NOTICE, "CS7 Instance identifiers: A = Iu = %u\n", cs7_instance_a);

		msc_network->a.sccp = sccp_setup(ctx, cs7_instance_a, "OsmoMSC-A-Iu", DEFAULT_PC_A_IU);
		if (!msc_network->a.sccp)
			return -EINVAL;

		msc_network->iu.sccp = msc_network->a.sccp;
	} else {
		/* Create two separate SCCP instances to run A and Iu independently on different
		 * pointcodes */
		LOGP(DMSC, LOGL_NOTICE, "CS7 Instance identifiers: A = %u, Iu = %u\n",
		     cs7_instance_a, cs7_instance_iu);

		msc_network->a.sccp = sccp_setup(ctx, cs7_instance_a, "OsmoMSC-A", DEFAULT_PC_A);
		if (!msc_network->a.sccp)
			return -EINVAL;

		msc_network->iu.sccp = sccp_setup(ctx, cs7_instance_iu, "OsmoMSC-Iu", DEFAULT_PC_IU);
		if (!msc_network->iu.sccp)
			return -EINVAL;
	}
#else
	/* No Iu support, just open up an A instance */
	msc_network->a.sccp = sccp_setup(ctx, cs7_instance_a, "OsmoMSC-A", DEFAULT_PC_A);
	if (!msc_network->a.sccp)
		return -EINVAL;
#endif

	return 0;
}

int main(int argc, char **argv)
{
	int rc;

	msc_vty_info.copyright	= osmomsc_copyright;

	tall_msc_ctx = talloc_named_const(NULL, 1, "osmo_msc");
	talloc_ctx_init(tall_msc_ctx);

	osmo_init_logging(&log_info);
	osmo_stats_init(tall_msc_ctx);

	/* For --version, vty_init() must be called before handling options */
	vty_init(&msc_vty_info);

	osmo_ss7_init();
	osmo_ss7_vty_init_asp(tall_msc_ctx);

	/* Parse options */
	handle_options(argc, argv);

	/* Allocate global gsm_network struct; choose socket/internal MNCC */
	msc_network = msc_network_alloc(tall_msc_ctx,
				        msc_cmdline_config.mncc_sock_path?
						mncc_sock_from_cc
						: int_mncc_recv);
	if (!msc_network)
		return -ENOMEM;

	if (msc_vlr_alloc(msc_network)) {
		fprintf(stderr, "Failed to allocate VLR\n");
		exit(1);
	}

	ctrl_vty_init(tall_msc_ctx);
	logging_vty_add_cmds(&log_info);
	msc_vty_init(msc_network);
	bsc_vty_init_extra();

#ifdef BUILD_SMPP
	if (smpp_openbsc_alloc_init(tall_msc_ctx) < 0)
		return -1;
#endif

	/*
	 * For osmo-nitb, skip TCH/F for now, because otherwise dyn TS
	 * always imply the possibility to have a mix of TCH/F and
	 * TCH/H channels; if two phones request a TCH/F and a TCH/H,
	 * respectively, they cannot call each other. If we deny TCH/F,
	 * they will both fall back to TCH/H, and dynamic channels are
	 * usable. See OS#1778.
	 *
	 * A third-party MSC may well be able to handle a TCH/H TCH/F
	 * mismatch. Moreover, this option may be overwritten in the
	 * config file or in VTY.
	 */
	msc_network->dyn_ts_allow_tch_f = false;

	rc = vty_read_config_file(msc_cmdline_config.config_file, NULL);
	if (rc < 0) {
		LOGP(DNM, LOGL_FATAL, "Failed to parse the config file: '%s'\n",
		     msc_cmdline_config.config_file);
		return 1;
	}

	/* Initialize MNCC socket if appropriate */
	if (msc_cmdline_config.mncc_sock_path) {
		rc = mncc_sock_init(msc_network,
				    msc_cmdline_config.mncc_sock_path);
		if (rc) {
			fprintf(stderr, "MNCC socket initialization failed. exiting.\n");
			exit(1);
		}
	} else
		DEBUGP(DMNCC, "Using internal MNCC handler.\n");

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_msc_ctx, &msc_network,
			       vty_get_bind_addr(), OSMO_VTY_PORT_MSC);
	if (rc < 0)
		return 2;

	/* BSC stuff is to be split behind an A-interface to be used with
	 * OsmoBSC, but there is no need to remove it yet. Most of the
	 * following code until iu_init() is legacy. */

#ifdef BUILD_SMPP
	smpp_openbsc_start(msc_network);
#endif

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	msc_network->ctrl = ctrl_interface_setup_dynip(msc_network, ctrl_vty_get_bind_addr(),
						       OSMO_CTRL_PORT_MSC, NULL);
	if (!msc_network->ctrl) {
		printf("Failed to initialize control interface. Exiting.\n");
		return -1;
	}

#if 0
TODO: we probably want some of the _net_ ctrl commands from bsc_base_ctrl_cmds_install().
	if (bsc_base_ctrl_cmds_install() != 0) {
		printf("Failed to initialize the BSC control commands.\n");
		return -1;
	}
#endif

	if (msc_ctrl_cmds_install(msc_network) != 0) {
		printf("Failed to initialize the MSC control commands.\n");
		return -1;
	}

	/* seed the PRNG */
	srand(time(NULL));
	/* TODO: is this used for crypto?? Improve randomness, at least we
	 * should try to use the nanoseconds part of the current time. */

	if (db_init(msc_cmdline_config.database_name)) {
		printf("DB: Failed to init database: %s\n",
		       msc_cmdline_config.database_name);
		return 4;
	}

	osmo_fsm_log_addr(true);
	if (msc_vlr_start(msc_network)) {
		fprintf(stderr, "Failed to start VLR\n");
		exit(1);
	}

	msc_subscr_conn_init();

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return 5;
	}

	/* setup the timer */
	osmo_timer_setup(&db_sync_timer, db_sync_timer_cb, NULL);
	if (msc_cmdline_config.use_db_counter)
		osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	/* start the SMS queue */
	if (sms_queue_start(msc_network, 20) != 0)
		return -1;

	msc_network->mgw.client = mgcp_client_init(
			msc_network, &msc_network->mgw.conf);

	if (mgcp_client_connect(msc_network->mgw.client)) {
		printf("MGCPGW connect failed\n");
		return 7;
	}

	if (ss7_setup(tall_msc_ctx)) {
		printf("Setting up SCCP client failed.\n");
		return 8;
	}

#ifdef BUILD_IU
	/* Set up IuCS */
	ranap_iu_init(tall_msc_ctx, DRANAP, "OsmoMSC-IuCS", msc_network->iu.sccp, rcvmsg_iu_cs, rx_iu_event);
#endif

	/* Set up A interface */
	a_init(msc_network->a.sccp, msc_network);

	if (msc_cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			return 6;
		}
	}

	while (1) {
		log_reset_context();
		osmo_select_main(0);
	}
}
