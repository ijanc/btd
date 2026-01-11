/*
 * Copyright (c) 2024-2026 Murilo Ijanc <murilo@ijanc.org>
 * Copyright (c) 2017 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
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

__dead void	 frontend_shutdown(void);
void		 frontend_sig_handler(int, short, void *);
void		 frontend_dispatch_main(int, short, void *);
void		 frontend_dispatch_engine(int, short, void *);

static struct imsgev	*iev_main;
static struct imsgev	*iev_engine;
static struct btd_conf	*frontend_conf, *nconf;

void
frontend_sig_handler(int sig, short event, void *bula)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		frontend_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
frontend(int debug, int verbose)
{
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pw = getpwnam(BTD_USER)) == NULL)
		fatal("getpwnam");

	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	/* libsndio finds the sndiod cookie in $HOME/.sndio. */
	if (setenv("HOME", _PATH_BTD_DB, 1) == -1)
		fatal("setenv");
	if (unveil(_PATH_SNDIO_SOCKDIR, "rw") == -1)
		fatal("unveil %s", _PATH_SNDIO_SOCKDIR);
	if (unveil(_PATH_SNDIO_COOKIEDIR, "r") == -1)
		fatal("unveil %s", _PATH_SNDIO_COOKIEDIR);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil");

	setproctitle("%s", "frontend");
	log_procinit("frontend");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio rpath unix recvfd", NULL) == -1)
		fatal("pledge");

	event_init();

	signal_set(&ev_sigint, SIGINT, frontend_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, frontend_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	if (imsgbuf_init(&iev_main->ibuf, 3) == -1)
		fatal(NULL);
	imsgbuf_allow_fdpass(&iev_main->ibuf);
	iev_main->handler = frontend_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	audio_init();

	event_dispatch();

	frontend_shutdown();
}

__dead void
frontend_shutdown(void)
{
	audio_stop();

	if (iev_engine != NULL) {
		imsgbuf_write(&iev_engine->ibuf);
		imsgbuf_clear(&iev_engine->ibuf);
		close(iev_engine->ibuf.fd);
		free(iev_engine);
	}
	imsgbuf_write(&iev_main->ibuf);
	imsgbuf_clear(&iev_main->ibuf);
	close(iev_main->ibuf.fd);
	free(iev_main);

	config_clear(frontend_conf);

	log_info("frontend exiting");
	exit(0);
}

int
frontend_imsg_compose_main(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data,
	    datalen));
}

int
frontend_imsg_compose_engine(int type, pid_t pid, void *data,
    uint16_t datalen)
{
	if (iev_engine == NULL)
		return (-1);
	return (imsg_compose_event(iev_engine, type, 0, pid, -1, data,
	    datalen));
}

void
frontend_dispatch_main(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct hid_conf		*hid;
	uint32_t		 type;
	int			 n, shut = 0, xfd;

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
			if (iev_engine != NULL)
				fatalx("%s: received unexpected imsg fd",
				    __func__);
			if ((xfd = imsg_get_fd(&imsg)) == -1)
				fatalx("%s: expected to receive imsg fd",
				    __func__);
			if ((iev_engine = malloc(sizeof(struct imsgev))) ==
			    NULL)
				fatal(NULL);
			if (imsgbuf_init(&iev_engine->ibuf, xfd) == -1)
				fatal(NULL);
			iev_engine->handler = frontend_dispatch_engine;
			iev_engine->events = EV_READ;
			event_set(&iev_engine->ev, iev_engine->ibuf.fd,
			    iev_engine->events, iev_engine->handler,
			    iev_engine);
			event_add(&iev_engine->ev, NULL);
			break;
		case IMSG_CONTROLFD:
			if ((xfd = imsg_get_fd(&imsg)) == -1)
				fatalx("%s: expected to receive imsg control "
				    "fd", __func__);
			control_listen(xfd);
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
			config_clear(frontend_conf);
			frontend_conf = nconf;
			nconf = NULL;
			break;
		case IMSG_STARTUP:
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
frontend_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct audio_params	 params;
	uint32_t		 type;
	int			 n, shut = 0, volume;

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
		case IMSG_CTL_CONTROLLER:
		case IMSG_CTL_DEVICE:
		case IMSG_CTL_BOND:
		case IMSG_CTL_END:
			control_imsg_relay(&imsg);
			break;
		case IMSG_AUDIO_START:
			if (imsg_get_data(&imsg, &params, sizeof(params)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			audio_start(&params);
			break;
		case IMSG_AUDIO_STOP:
			audio_stop();
			break;
		case IMSG_VOLUME_REMOTE:
			if (imsg_get_data(&imsg, &volume, sizeof(volume)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			audio_set_volume(volume);
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
