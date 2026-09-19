/*
 * Copyright (c) 2024-2026 Murilo Ijanc <murilo@ijanc.org>
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
engine_fw_append(struct engine_fw *fw, const void *p, size_t len)
{
	uint8_t	*nbuf;

	if (fw->len + len > fw->size) {
		if ((nbuf = recallocarray(fw->buf, fw->size, fw->len + len, 1))
		    == NULL)
			fatal(NULL);
		fw->buf = nbuf;
		fw->size = fw->len + len;
	}
	memcpy(fw->buf + fw->len, p, len);
	fw->len += len;
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
engine_try_start(void)
{
	if (started || !startup_main || !startup_bus || !fw_done)
		return;
	started = 1;
	sdp_init();
	avdtp_init();
	avrcp_init();
	evtimer_set(&connect_timer, engine_connect_timeout, NULL);
	device_reconf();
	hci_start();
}

void
engine_local_identity(struct bdaddr *addr)
{
	struct bond_local	*local = &engine_state.local;

	if (!engine_state.have_local) {
		arc4random_buf(local->addr.b, sizeof(local->addr.b));
		local->addr.b[5] |= 0xc0;
		arc4random_buf(local->irk, sizeof(local->irk));
		engine_state.have_local = 1;
		engine_imsg_compose_main(IMSG_BOND_LOCAL_SAVE, local,
		    sizeof(*local));
		log_info("new identity address %s", bdaddr_ntoa(&local->addr));
	}
	*addr = local->addr;
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
	case HCI_EVT_REMOTE_EXT_FEATURES:
		if (len < 13 || p[0] != 0 ||
		    (c = hci_conn_find(get16(p + 1))) == NULL)
			break;
		if (p[3] == 1)
			log_debug("%s: secure connections host support %s",
			    bdaddr_ntoa(&c->peer), p[5] & 0x08 ? "yes" : "no");
		else if (p[3] == 2)
			log_debug("%s: secure connections controller support "
			    "%s", bdaddr_ntoa(&c->peer), p[6] & 0x01 ? "yes" :
			    "no");
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

static void
engine_conn_request(const uint8_t *p, size_t len)
{
	struct device	*dev;
	struct bdaddr	 addr;
	uint8_t		 rsp[7];

	if (len < 10)
		return;
	memcpy(addr.b, p, 6);
	memcpy(rsp, p, 6);
	dev = device_find(DEV_HEADSET, &addr);
	if (p[9] != 0x01 || dev == NULL || dev->conn != NULL ||
	    (busy != NULL && busy != dev)) {
		log_debug("%s: connection request rejected",
		    bdaddr_ntoa(&addr));
		rsp[6] = HCI_ERR_LIMITED_RESOURCES;
		hci_cmd(HCI_CMD_REJECT_CONN, rsp, 7, NULL, NULL);
		return;
	}
	log_debug("%s: connection request accepted", bdaddr_ntoa(&addr));
	rsp[6] = 0x01;
	hci_cmd(HCI_CMD_ACCEPT_CONN, rsp, 7, NULL, NULL);
}

static void
engine_encryption(const uint8_t *p, size_t len, int refresh)
{
	struct hci_conn	*c;
	int		 on;

	if (len < 3 || (c = hci_conn_find(get16(p + 1) & 0x0fff)) == NULL)
		return;
	if (refresh)
		on = p[0] == 0;
	else
		on = len >= 4 && p[3] != 0;
	if (p[0] == 0)
		c->encrypted = on;
	if (c->link == LINK_LE)
		smp_encryption_changed(c, p[0], on);
	else
		ssp_encryption_changed(c, p[0], on);
}

static const char *
device_state_name(int state)
{
	switch (state) {
	case DEV_IDLE:
		return ("idle");
	case DEV_WAIT:
		return ("waiting");
	case DEV_CONNECTING:
		return ("connecting");
	case DEV_SECURING:
		return ("securing");
	case DEV_SETUP:
		return ("setting up");
	case DEV_READY:
		return ("ready");
	}
	return ("unknown");
}

static void
engine_device_ctl(struct device *dev, struct ctl_device *cd)
{
	struct hci_conn	*c = dev->conn;

	memset(cd, 0, sizeof(*cd));
	cd->kind = dev->kind == DEV_HID ? CTL_DEV_HID : CTL_DEV_HEADSET;
	cd->addr = dev->addr;
	strlcpy(cd->state, device_state_name(dev->state), sizeof(cd->state));
	cd->bonded = bond_find(dev->kind == DEV_HID ? BOND_LE : BOND_BR,
	    &dev->addr) != NULL;
	cd->passkey = dev->passkey;
	if (c != NULL) {
		cd->handle = c->handle;
		cd->peer = c->peer;
		cd->peer_type = c->peer_type;
		cd->encrypted = c->encrypted;
		cd->authenticated = smp_authenticated(c);
		cd->sc = smp_sc(c);
	}
	strlcpy(cd->info, dev->info, sizeof(cd->info));
}

void
engine_show_controller(pid_t pid)
{
	struct ctl_controller	 cc;
	struct hci_conn		*c;

	memset(&cc, 0, sizeof(cc));
	switch (hci.state) {
	case HCI_S_DOWN:
		strlcpy(cc.state, "down", sizeof(cc.state));
		break;
	case HCI_S_INIT:
		strlcpy(cc.state, "initializing", sizeof(cc.state));
		break;
	case HCI_S_FIRMWARE:
		strlcpy(cc.state, "loading firmware", sizeof(cc.state));
		break;
	case HCI_S_RUNNING:
		strlcpy(cc.state, "running", sizeof(cc.state));
		break;
	}
	cc.public = hci.bdaddr;
	cc.random = hci.random;
	cc.manufacturer = hci.manufacturer;
	cc.hci_ver = hci.hci_ver;
	cc.hci_rev = hci.hci_rev;
	cc.lmp_ver = hci.lmp_ver;
	cc.lmp_subver = hci.lmp_subver;
	cc.fw_version = hci.fw_version;
	cc.acl_len = hci.acl_len;
	cc.acl_num = hci.acl_num;
	cc.le_acl_len = hci.le_acl_len;
	cc.le_acl_num = hci.le_acl_num;
	cc.acl_free = hci.acl_free;
	cc.le_acl_free = hci.le_acl_free;
	cc.scanning = hci.scanning;
	TAILQ_FOREACH(c, &hci_conns, entry)
		cc.conns++;
	engine_imsg_compose_frontend(IMSG_CTL_CONTROLLER, pid, &cc,
	    sizeof(cc));
	engine_imsg_compose_frontend(IMSG_CTL_END, pid, NULL, 0);
}

void
engine_show_devices(pid_t pid)
{
	struct ctl_device	 cd;
	struct device		*dev;

	TAILQ_FOREACH(dev, &devices, entry) {
		engine_device_ctl(dev, &cd);
		engine_imsg_compose_frontend(IMSG_CTL_DEVICE, pid, &cd,
		    sizeof(cd));
	}
	engine_imsg_compose_frontend(IMSG_CTL_END, pid, NULL, 0);
}

void
engine_show_bonds(pid_t pid)
{
	struct ctl_bond	 cb;
	struct bond	*b;

	TAILQ_FOREACH(b, &engine_state.bonds, entry) {
		memset(&cb, 0, sizeof(cb));
		cb.type = b->type;
		cb.addr = b->addr;
		cb.addr_type = b->addr_type;
		cb.flags = b->flags;
		cb.linkkey_type = b->linkkey_type;
		engine_imsg_compose_frontend(IMSG_CTL_BOND, pid, &cb,
		    sizeof(cb));
	}
	engine_imsg_compose_frontend(IMSG_CTL_END, pid, NULL, 0);
}

struct device *
device_find(int kind, const struct bdaddr *addr)
{
	struct device	*dev;

	TAILQ_FOREACH(dev, &devices, entry)
		if (dev->kind == kind && bdaddr_cmp(&dev->addr, addr) == 0)
			return (dev);
	return (NULL);
}

static struct device *
device_new(int kind, const struct bdaddr *addr)
{
	struct device	*dev;

	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		fatal(NULL);
	dev->kind = kind;
	dev->addr = *addr;
	dev->state = DEV_WAIT;
	dev->passkey = -1;
	evtimer_set(&dev->retry, device_retry, dev);
	TAILQ_INSERT_TAIL(&devices, dev, entry);
	return (dev);
}

static void
device_free(struct device *dev)
{
	if (busy == dev)
		busy = NULL;
	evtimer_del(&dev->retry);
	TAILQ_REMOVE(&devices, dev, entry);
	free(dev);
}

void
device_reconf(void)
{
	struct btd_conf	*conf = engine_state.conf;
	struct hid_conf	*hid;
	struct device	*dev, *ndev;

	TAILQ_FOREACH(dev, &devices, entry)
		dev->removed = 1;
	TAILQ_FOREACH(hid, &conf->hid_list, entry) {
		if ((dev = device_find(DEV_HID, &hid->addr)) == NULL)
			dev = device_new(DEV_HID, &hid->addr);
		dev->removed = 0;
	}
	if (conf->headset != NULL) {
		if ((dev = device_find(DEV_HEADSET, &conf->headset->addr)) ==
		    NULL)
			dev = device_new(DEV_HEADSET, &conf->headset->addr);
		dev->removed = 0;
		dev->hs = *conf->headset;
	}
	TAILQ_FOREACH_SAFE(dev, &devices, entry, ndev) {
		if (!dev->removed)
			continue;
		if (dev->conn != NULL) {
			dev->conn->dev = NULL;
			hci_disconnect(dev->conn, HCI_ERR_REMOTE_USER);
			device_down(dev);
		}
		device_free(dev);
	}
	engine_schedule();
}

void
device_state(struct device *dev, int state)
{
	dev->state = state;
	if (state == DEV_READY && busy == dev)
		engine_release(dev);
}

static void
device_retry(int fd, short event, void *arg)
{
	struct device	*dev = arg;

	if (dev->state == DEV_IDLE)
		dev->state = DEV_WAIT;
	engine_schedule();
}

static void
device_idle(struct device *dev)
{
	struct timeval	 tv;

	dev->state = DEV_IDLE;
	tv.tv_sec = dev->kind == DEV_HID ? DEV_HID_RETRY : DEV_HEADSET_RETRY;
	tv.tv_usec = 0;
	evtimer_add(&dev->retry, &tv);
}

static void
device_down(struct device *dev)
{
	if (dev->kind == DEV_HID)
		hogp_down(dev);
	else
		a2dp_down(dev);
	if (dev->conn != NULL && dev->conn->att != NULL)
		att_free(dev->conn->att);
	dev->conn = NULL;
	dev->passkey = -1;
	dev->info[0] = '\0';
}

void
engine_release(struct device *dev)
{
	if (busy != dev)
		return;
	busy = NULL;
	evtimer_del(&connect_timer);
	engine_schedule();
}

void
engine_schedule(void)
{
	struct device	*dev;
	int		 want_scan = 0;

	if (hci.state != HCI_S_RUNNING)
		return;
	if (busy != NULL) {
		hci_scan(0);
		return;
	}
	TAILQ_FOREACH(dev, &devices, entry) {
		if (dev->state != DEV_WAIT)
			continue;
		if (dev->kind == DEV_HEADSET &&
		    hci_conn_find_addr(LINK_BR, &dev->addr) == NULL) {
			engine_connect(dev, &dev->addr, BDADDR_PUBLIC);
			return;
		}
		if (dev->kind == DEV_HID)
			want_scan = 1;
	}
	hci_scan(want_scan);
}

static void
engine_connect(struct device *dev, const struct bdaddr *addr, uint8_t type)
{
	struct timeval	 tv = { DEV_LE_CONNECT_TIMEOUT, 0 };

	busy = dev;
	dev->state = DEV_CONNECTING;
	hci_scan(0);
	if (dev->kind == DEV_HEADSET) {
		log_debug("%s: paging", bdaddr_ntoa(&dev->addr));
		hci_br_connect(addr);
		return;
	}
	log_debug("%s: connecting to %s (%s)", bdaddr_ntoa(&dev->addr),
	    bdaddr_ntoa(addr), type == BDADDR_RANDOM ? "random" : "public");
	hci_le_connect(addr, type);
	evtimer_add(&connect_timer, &tv);
}

static void
engine_connect_timeout(int fd, short event, void *arg)
{
	if (busy == NULL || busy->kind != DEV_HID)
		return;
	log_debug("%s: connection timed out", bdaddr_ntoa(&busy->addr));
	hci_le_connect_cancel();
}

void
engine_create_status(void *arg, uint8_t status, const uint8_t *rp,
    size_t len)
{
	struct device	*dev = busy;

	if (status == 0 || dev == NULL)
		return;
	log_warnx("%s: connection setup failed: 0x%02x",
	    bdaddr_ntoa(&dev->addr), status);
	device_idle(dev);
	engine_release(dev);
}

void
engine_conn_failed(int link, const struct bdaddr *addr, uint8_t status)
{
	struct device	*dev = busy;

	if (dev == NULL || dev->conn != NULL)
		return;
	if ((link == LINK_LE) != (dev->kind == DEV_HID))
		return;
	if (status != HCI_ERR_PAGE_TIMEOUT && status != HCI_ERR_UNKNOWN_CONN)
		log_info("%s: connection failed: 0x%02x",
		    bdaddr_ntoa(&dev->addr), status);
	device_idle(dev);
	engine_release(dev);
}

void
engine_conn_up(struct hci_conn *c)
{
	struct device	*dev;
	uint8_t		 ext[3];

	if (c->link == LINK_LE)
		dev = (busy != NULL && busy->kind == DEV_HID) ? busy : NULL;
	else
		dev = device_find(DEV_HEADSET, &c->peer);
	if (dev == NULL || dev->conn != NULL) {
		if (c->link == LINK_LE)
			att_new(c, NULL, NULL);
		log_info("%s: unexpected connection, disconnecting",
		    bdaddr_ntoa(&c->peer));
		hci_disconnect(c, HCI_ERR_REMOTE_USER);
		return;
	}
	if (busy == NULL)
		busy = dev;
	evtimer_del(&connect_timer);
	c->dev = dev;
	dev->conn = c;
	dev->state = DEV_SECURING;
	if (c->link == LINK_LE)
		att_new(c, NULL, NULL);
	log_info("%s: connected", bdaddr_ntoa(&dev->addr));
	if (c->link == LINK_LE)
		smp_le_secure(c);
	else {
		ext[0] = c->handle & 0xff;
		ext[1] = c->handle >> 8;
		ext[2] = 1;
		hci_cmd(HCI_CMD_READ_REMOTE_EXT_FEATURES, ext, 3, NULL, NULL);
		ext[2] = 2;
		hci_cmd(HCI_CMD_READ_REMOTE_EXT_FEATURES, ext, 3, NULL, NULL);
		ssp_secure(c);
	}
}

void
engine_conn_down(struct hci_conn *c, uint8_t reason)
{
	struct device	*dev = c->dev;

	if (c->smp != NULL)
		smp_free(c);
	if (dev == NULL) {
		if (c->att != NULL)
			att_free(c->att);
		return;
	}
	log_info("%s: disconnected, reason 0x%02x", bdaddr_ntoa(&dev->addr),
	    reason);
	device_down(dev);
	device_idle(dev);
	engine_release(dev);
}

void
engine_secured(struct hci_conn *c, int ok)
{
	struct device	*dev = c->dev;

	if (dev == NULL)
		return;
	if (!ok) {
		log_warnx("%s: securing the link failed",
		    bdaddr_ntoa(&dev->addr));
		hci_disconnect(c, HCI_ERR_AUTH_FAILURE);
		return;
	}
	log_info("%s: encrypted", bdaddr_ntoa(&dev->addr));
	dev->state = DEV_SETUP;
	engine_release(dev);
	if (dev->kind == DEV_HID)
		hogp_start(dev);
	else
		a2dp_start(dev);
}

void
engine_ready(void)
{
	struct device	*dev;

	TAILQ_FOREACH(dev, &devices, entry)
		if (dev->state == DEV_IDLE || dev->state == DEV_CONNECTING)
			dev->state = DEV_WAIT;
	busy = NULL;
	engine_schedule();
}

void
engine_scan_changed(void)
{
	if (hci.scanning != hci.scan_want)
		return;
	engine_schedule();
}

void
engine_adv_report(const struct bdaddr *addr, uint8_t type, int connectable,
    int rssi, const uint8_t *data, size_t len)
{
	struct device	*dev;
	struct bond	*b = NULL;

	if (log_getverbose() > 1)
		log_debug("adv %s (%s)%s rssi %d, %zu bytes", bdaddr_ntoa(addr),
		    type == BDADDR_RANDOM ? "random" : "public",
		    connectable ? " connectable" : "", rssi, len);
	if (busy != NULL || !connectable)
		return;
	TAILQ_FOREACH(dev, &devices, entry) {
		if (dev->kind != DEV_HID || dev->state != DEV_WAIT)
			continue;
		if (bdaddr_cmp(&dev->addr, addr) == 0)
			break;
		if ((b = bond_find(BOND_LE, &dev->addr)) == NULL)
			continue;
		if ((b->flags & BOND_F_IDENT) && bdaddr_cmp(&b->ident, addr) == 0)
			break;
		if (type == BDADDR_RANDOM && (addr->b[5] & 0xc0) == 0x40 &&
		    (b->flags & BOND_F_IRK) && smp_rpa_match(b->irk, addr))
			break;
	}
	if (dev == NULL)
		return;
	engine_connect(dev, addr, type);
}
