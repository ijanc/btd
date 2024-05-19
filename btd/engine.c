/*
 * Copyright (c) 2024 Murilo Ijanc <murilo@ijanc.org>
 * Copyright (c) 2017 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "btd.h"

__dead void	 engine_shutdown(void);
void		 engine_sig_handler(int, short, void *);
void		 engine_dispatch_main(int, short, void *);
void		 engine_dispatch_bus(int, short, void *);
void		 engine_dispatch_frontend(int, short, void *);
void		 engine_fw_append(struct engine_fw *, const void *, size_t);
void		 engine_reconf(struct btd_conf *);
void		 engine_try_start(void);
static struct device *device_new(int, const struct bdaddr *);
static void	 device_free(struct device *);
static void	 device_retry(int, short, void *);
static void	 device_idle(struct device *);
static void	 device_down(struct device *);
static void	 engine_connect(struct device *, const struct bdaddr *,
		    uint8_t);
static void	 engine_connect_timeout(int, short, void *);
static void	 engine_conn_request(const uint8_t *, size_t);
static void	 engine_encryption(const uint8_t *, size_t, int);
static void	 engine_device_ctl(struct device *, struct ctl_device *);

struct engine_state	 engine_state;

static struct imsgev	*iev_main;
static struct imsgev	*iev_bus;
static struct imsgev	*iev_frontend;
static struct btd_conf	*nconf;
static int		 startup_main, startup_bus, fw_done, started;
static TAILQ_HEAD(, device) devices = TAILQ_HEAD_INITIALIZER(devices);
static struct device	*busy;
static struct event	 connect_timer;

void
engine_sig_handler(int sig, short event, void *bula)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		engine_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
engine(int debug, int verbose)
{
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pw = getpwnam(BTD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	setproctitle("%s", "engine");
	log_procinit("engine");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	signal_set(&ev_sigint, SIGINT, engine_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, engine_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	if (imsgbuf_init(&iev_main->ibuf, 3) == -1)
		fatal(NULL);
	imsgbuf_allow_fdpass(&iev_main->ibuf);
	iev_main->handler = engine_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	TAILQ_INIT(&engine_state.bonds);
	engine_state.conf = config_new_empty();
	engine_state.kbdtype = -1;

	event_dispatch();

	engine_shutdown();
}

__dead void
engine_shutdown(void)
{
	if (iev_frontend != NULL) {
		imsgbuf_clear(&iev_frontend->ibuf);
		close(iev_frontend->ibuf.fd);
		free(iev_frontend);
	}
	if (iev_bus != NULL) {
		imsgbuf_clear(&iev_bus->ibuf);
		close(iev_bus->ibuf.fd);
		free(iev_bus);
	}
	imsgbuf_clear(&iev_main->ibuf);
	close(iev_main->ibuf.fd);
	free(iev_main);

	log_info("engine exiting");
	exit(0);
}

int
engine_imsg_compose_main(int type, void *data, uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, 0, -1, data, datalen));
}

int
engine_imsg_compose_bus(int type, void *data, uint16_t datalen)
{
	if (iev_bus == NULL)
		return (-1);
	return (imsg_compose_event(iev_bus, type, 0, 0, -1, data, datalen));
}

int
engine_imsg_compose_frontend(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	if (iev_frontend == NULL)
		return (-1);
	return (imsg_compose_event(iev_frontend, type, 0, pid, -1, data,
	    datalen));
}

void
engine_dispatch_main(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct hid_conf		*hid;
	struct bond		*bond;
	struct ibuf		 data;
	uint32_t		 type;
	int			 n, shut = 0, verbose, xfd;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE)
				shut = 1;
			else
				fatal("imsgbuf_write");
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		type = imsg_get_type(&imsg);
		switch (type) {
		case IMSG_SOCKET_IPC:
		case IMSG_SOCKET_BUS:
			if ((xfd = imsg_get_fd(&imsg)) == -1)
				fatalx("%s: expected to receive imsg fd",
				    __func__);
			if (type == IMSG_SOCKET_IPC) {
				if (iev_frontend != NULL)
					fatalx("%s: received unexpected imsg "
					    "fd", __func__);
				if ((iev_frontend = malloc(sizeof(struct
				    imsgev))) == NULL)
					fatal(NULL);
				if (imsgbuf_init(&iev_frontend->ibuf, xfd)
				    == -1)
					fatal(NULL);
				iev_frontend->handler =
				    engine_dispatch_frontend;
				iev = iev_frontend;
			} else {
				if (iev_bus != NULL)
					fatalx("%s: received unexpected imsg "
					    "fd", __func__);
				if ((iev_bus = malloc(sizeof(struct imsgev)))
				    == NULL)
					fatal(NULL);
				if (imsgbuf_init(&iev_bus->ibuf, xfd) == -1)
					fatal(NULL);
				iev_bus->handler = engine_dispatch_bus;
				iev = iev_bus;
			}
			iev->events = EV_READ;
			event_set(&iev->ev, iev->ibuf.fd, iev->events,
			    iev->handler, iev);
			event_add(&iev->ev, NULL);
			iev = bula;
			if (iev_frontend != NULL && iev_bus != NULL &&
			    pledge("stdio", NULL) == -1)
				fatal("pledge");
			break;
		case IMSG_KBDTYPE:
			if (imsg_get_data(&imsg, &engine_state.kbdtype,
			    sizeof(engine_state.kbdtype)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			break;
		case IMSG_FIRMWARE:
		case IMSG_FIRMWARE_CONFIG:
			if (imsg_get_ibuf(&imsg, &data) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			engine_fw_append(type == IMSG_FIRMWARE ?
			    &engine_state.fw : &engine_state.fwconfig,
			    ibuf_data(&data), ibuf_size(&data));
			break;
		case IMSG_FIRMWARE_END:
			fw_done = 1;
			break;
		case IMSG_BOND_LOCAL:
			if (imsg_get_data(&imsg, &engine_state.local,
			    sizeof(engine_state.local)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			engine_state.have_local = 1;
			break;
		case IMSG_BOND:
			if ((bond = calloc(1, sizeof(*bond))) == NULL)
				fatal(NULL);
			if (imsg_get_data(&imsg, bond, sizeof(*bond)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			TAILQ_INSERT_TAIL(&engine_state.bonds, bond, entry);
			break;
		case IMSG_BONDS_END:
			break;
		case IMSG_RECONF_CONF:
			if (nconf != NULL)
				fatalx("%s: IMSG_RECONF_CONF already in "
				    "progress", __func__);
			nconf = config_new_empty();
			if (imsg_get_data(&imsg, nconf, sizeof(*nconf)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			TAILQ_INIT(&nconf->hid_list);
			nconf->headset = NULL;
			break;
		case IMSG_RECONF_HID:
			if (nconf == NULL)
				fatalx("%s: %s without IMSG_RECONF_CONF",
				    __func__, i2s(type));
			if ((hid = calloc(1, sizeof(*hid))) == NULL)
				fatal(NULL);
			if (imsg_get_data(&imsg, hid, sizeof(*hid)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			TAILQ_INSERT_TAIL(&nconf->hid_list, hid, entry);
			break;
		case IMSG_RECONF_HEADSET:
			if (nconf == NULL)
				fatalx("%s: %s without IMSG_RECONF_CONF",
				    __func__, i2s(type));
			if ((nconf->headset = calloc(1,
			    sizeof(*nconf->headset))) == NULL)
				fatal(NULL);
			if (imsg_get_data(&imsg, nconf->headset,
			    sizeof(*nconf->headset)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			break;
		case IMSG_RECONF_END:
			if (nconf == NULL)
				fatalx("%s: %s without IMSG_RECONF_CONF",
				    __func__, i2s(type));
			engine_reconf(nconf);
			nconf = NULL;
			break;
		case IMSG_STARTUP:
			startup_main = 1;
			engine_try_start();
			break;
		case IMSG_CTL_LOG_VERBOSE:
			if (imsg_get_data(&imsg, &verbose,
			    sizeof(verbose)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			log_setverbose(verbose);
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__, type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
engine_dispatch_bus(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct ibuf		 data;
	uint32_t		 type;
	int			 n, shut = 0;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE)
				shut = 1;
			else
				fatal("imsgbuf_write");
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		type = imsg_get_type(&imsg);
		switch (type) {
		case IMSG_STARTUP:
			startup_bus = 1;
			engine_try_start();
			break;
		case IMSG_HCI_EVT:
			if (imsg_get_ibuf(&imsg, &data) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			hci_input_event(ibuf_data(&data), ibuf_size(&data));
			break;
		case IMSG_HCI_ACLDATA:
			if (imsg_get_ibuf(&imsg, &data) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			hci_input_acl(ibuf_data(&data), ibuf_size(&data));
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__, type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
engine_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct ibuf		 data;
	uint32_t		 type;
	pid_t			 pid;
	int			 n, shut = 0, verbose, volume;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			fatal("imsgbuf_read error");
		if (n == 0)
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (imsgbuf_write(ibuf) == -1) {
			if (errno == EPIPE)
				shut = 1;
			else
				fatal("imsgbuf_write");
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
			fatal("imsgbuf_get");
		if (n == 0)
			break;

		type = imsg_get_type(&imsg);
		pid = imsg_get_pid(&imsg);
		switch (type) {
		case IMSG_CTL_LOG_VERBOSE:
			if (imsg_get_data(&imsg, &verbose,
			    sizeof(verbose)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			log_setverbose(verbose);
			break;
		case IMSG_CTL_SHOW_CONTROLLER:
			engine_show_controller(pid);
			break;
		case IMSG_CTL_SHOW_DEVICES:
			engine_show_devices(pid);
			break;
		case IMSG_CTL_SHOW_BONDS:
			engine_show_bonds(pid);
			break;
		case IMSG_AUDIO_FRAME:
			if (imsg_get_ibuf(&imsg, &data) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			rtp_frame(ibuf_data(&data), ibuf_size(&data));
			break;
		case IMSG_VOLUME_LOCAL:
			if (imsg_get_data(&imsg, &volume, sizeof(volume)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			avrcp_local_volume(volume);
			break;
		default:
			log_debug("%s: unexpected imsg %d", __func__, type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
engine_reconf(struct btd_conf *xconf)
{
	struct btd_conf	*old = engine_state.conf;

	engine_state.conf = xconf;
	if (started)
		device_reconf();
	config_clear(old);
}

void
engine_hci_event(uint8_t code, const uint8_t *p, size_t len)
{
	struct hci_conn	*c;

	switch (code) {
	case HCI_EVT_CONN_REQUEST:
		engine_conn_request(p, len);
		break;
	case HCI_EVT_ENCRYPTION_CHANGE:
		engine_encryption(p, len, 0);
		break;
	case HCI_EVT_ENCRYPTION_KEY_REFRESH:
		engine_encryption(p, len, 1);
		break;
	case HCI_EVT_LINK_KEY_REQUEST:
	case HCI_EVT_LINK_KEY_NOTIFICATION:
	case HCI_EVT_PIN_CODE_REQUEST:
	case HCI_EVT_IO_CAP_REQUEST:
	case HCI_EVT_IO_CAP_RESPONSE:
	case HCI_EVT_USER_CONFIRM_REQUEST:
	case HCI_EVT_SSP_COMPLETE:
	case HCI_EVT_AUTH_COMPLETE:
		ssp_event(code, p, len);
		break;
	case HCI_EVT_ROLE_CHANGE:
		if (len >= 8)
			log_debug("%s: role %s, status 0x%02x",
			    bdaddr_ntoa((const struct bdaddr *)(p + 1)),
			    p[7] ? "peripheral" : "central", p[0]);
		break;
	case HCI_EVT_MODE_CHANGE:
		if (len >= 6 && (c = hci_conn_find(get16(p + 1))) != NULL)
			log_debug("%s: mode %u, interval %u",
			    bdaddr_ntoa(&c->peer), p[3], get16(p + 4));
		break;
	default:
		if (log_getverbose() > 2)
			log_debug("unhandled event 0x%02x", code);
		break;
	}
}

void
engine_le_event(uint8_t sub, const uint8_t *p, size_t len)
{
	struct hci_conn	*c;
	uint8_t		 rsp[2];

	switch (sub) {
	case HCI_LE_CONN_UPDATE_COMPLETE:
		if (len < 9 || p[0] != 0 ||
		    (c = hci_conn_find(get16(p + 1))) == NULL)
			break;
		c->le_interval = get16(p + 3);
		c->le_latency = get16(p + 5);
		c->le_timeout = get16(p + 7);
		log_debug("%s: interval %u, latency %u, timeout %u",
		    bdaddr_ntoa(&c->peer), c->le_interval, c->le_latency,
		    c->le_timeout);
		break;
	case HCI_LE_LTK_REQUEST:
		if (len < 2)
			break;
		put16(rsp, get16(p));
		hci_cmd(HCI_CMD_LE_LTK_NEG_REPLY, rsp, sizeof(rsp), NULL,
		    NULL);
		break;
	default:
		break;
	}
}

