/*
 * Copyright (c) 2024 Murilo Ijanc <murilo@ijanc.org>
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
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/wait.h>

#include <dev/usb/usb.h>
#include <dev/wscons/wsconsio.h>

#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "btd.h"

#define	BUS_READSIZE	1024

__dead void	 bus_shutdown(void);
void		 bus_sig_handler(int, short, void *);
void		 bus_dispatch_main(int, short, void *);
void		 bus_dispatch_engine(int, short, void *);
void		 bus_startup(void);
void		 bus_intr(int, short, void *);
void		 bus_acl(int, short, void *);
__dead void	 bus_reader(int, int);
void		 bus_kill_reader(void);
void		 bus_cmd(uint8_t *, size_t);
void		 bus_write_acl(uint8_t *, size_t);
void		 bus_inject(int, struct wscons_event *, size_t);
void		 bus_inject_mouse(struct wscons_event *, size_t);

static struct imsgev	*iev_main;
static struct imsgev	*iev_engine;
static struct event	 ev_intr, ev_acl;
static int		 ctlfd = -1, intrfd = -1, bulkfd = -1, cfgfd = -1;
static pid_t		 reader_pid = -1;

void
bus_sig_handler(int sig, short event, void *bula)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		bus_shutdown();
	default:
		fatalx("unexpected signal");
	}
}

void
bus(int debug, int verbose)
{
	struct event	 ev_sigint, ev_sigterm;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (unveil(_PATH_WSMOUSE, "w") == -1)
		fatal("unveil %s", _PATH_WSMOUSE);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil");

	setproctitle("%s", "bus");
	log_procinit("bus");

	/* The interrupt endpoint queue is small: read it before it fills. */
	if (setpriority(PRIO_PROCESS, 0, -10) == -1)
		log_warn("setpriority");

	if (atexit(bus_kill_reader) == -1)
		fatal("atexit");

	event_init();

	signal_set(&ev_sigint, SIGINT, bus_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, bus_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	if ((iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	if (imsgbuf_init(&iev_main->ibuf, 3) == -1)
		fatal(NULL);
	imsgbuf_allow_fdpass(&iev_main->ibuf);
	iev_main->handler = bus_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	event_dispatch();

	bus_shutdown();
}

__dead void
bus_shutdown(void)
{
	bus_kill_reader();

	if (iev_engine != NULL) {
		imsgbuf_clear(&iev_engine->ibuf);
		close(iev_engine->ibuf.fd);
		free(iev_engine);
	}
	imsgbuf_clear(&iev_main->ibuf);
	close(iev_main->ibuf.fd);
	free(iev_main);

	log_info("bus exiting");
	exit(0);
}

void
bus_kill_reader(void)
{
	if (reader_pid <= 0)
		return;
	kill(reader_pid, SIGTERM);
	waitpid(reader_pid, NULL, 0);
	reader_pid = -1;
}

void
bus_dispatch_main(int fd, short event, void *bula)
{
	struct imsgev	*iev = bula;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	uint32_t	 type;
	int		 n, shut = 0, verbose, xfd;

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
		case IMSG_SOCKET_BUS:
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
			iev_engine->handler = bus_dispatch_engine;
			iev_engine->events = EV_READ;
			event_set(&iev_engine->ev, iev_engine->ibuf.fd,
			    iev_engine->events, iev_engine->handler,
			    iev_engine);
			event_add(&iev_engine->ev, NULL);
			break;
		case IMSG_DEVFD_CTL:
		case IMSG_DEVFD_INTR:
		case IMSG_DEVFD_BULK:
		case IMSG_DEVFD_WSCFG:
			if ((xfd = imsg_get_fd(&imsg)) == -1)
				fatalx("%s: expected to receive imsg fd",
				    __func__);
			if (type == IMSG_DEVFD_CTL)
				ctlfd = xfd;
			else if (type == IMSG_DEVFD_INTR)
				intrfd = xfd;
			else if (type == IMSG_DEVFD_BULK)
				bulkfd = xfd;
			else
				cfgfd = xfd;
			break;
		case IMSG_STARTUP:
			bus_startup();
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
bus_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct wscons_event	 ev[BTD_MAXEVENTS];
	uint8_t			 buf[MAX_IMSGSIZE];
	uint32_t		 type;
	size_t			 len;
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
		len = imsg_get_len(&imsg);
		switch (type) {
		case IMSG_HCI_CMD:
			if (len < 3 || len > 3 + 255 ||
			    imsg_get_data(&imsg, buf, len) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			bus_cmd(buf, len);
			break;
		case IMSG_HCI_ACL:
			if (len < 4 || imsg_get_data(&imsg, buf, len) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			bus_write_acl(buf, len);
			break;
		case IMSG_WSKBD:
		case IMSG_WSMOUSE:
			if (len == 0 || len > sizeof(ev) ||
			    len % sizeof(ev[0]) != 0 ||
			    imsg_get_data(&imsg, ev, len) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			if (type == IMSG_WSKBD)
				bus_inject(cfgfd, ev, len / sizeof(ev[0]));
			else
				bus_inject_mouse(ev, len / sizeof(ev[0]));
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
bus_startup(void)
{
	int	 sp[2];

	if (ctlfd == -1 || intrfd == -1 || bulkfd == -1 || cfgfd == -1 ||
	    iev_engine == NULL)
		fatalx("%s: missing descriptors", __func__);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, PF_UNSPEC, sp)
	    == -1)
		fatal("socketpair");

	switch (reader_pid = fork()) {
	case -1:
		fatal("fork");
	case 0:
		reader_pid = -1;
		bus_reader(bulkfd, sp[1]);
	default:
		break;
	}
	close(sp[1]);
	if (fcntl(sp[0], F_SETFL, O_NONBLOCK) == -1)
		fatal("fcntl");

	event_set(&ev_acl, sp[0], EV_READ | EV_PERSIST, bus_acl, NULL);
	event_add(&ev_acl, NULL);
	event_set(&ev_intr, intrfd, EV_READ | EV_PERSIST, bus_intr, NULL);
	event_add(&ev_intr, NULL);

	imsg_compose_event(iev_engine, IMSG_STARTUP, 0, 0, -1, NULL, 0);
}

/*
 * ugen(4) reports the bulk endpoint as always readable, so it gets a
 * process of its own blocked in read(2).
 */
__dead void
bus_reader(int fd, int out)
{
	uint8_t	 buf[BUS_READSIZE];
	ssize_t	 n;
	int	 one = 1;

	setproctitle("%s", "bus acl");
	log_procinit("acl");

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	if (dup2(fd, 3) == -1 || dup2(out, 4) == -1)
		fatal("dup2");
	closefrom(5);

	if (ioctl(3, USB_SET_SHORT_XFER, &one) == -1)
		fatal("USB_SET_SHORT_XFER");

	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	for (;;) {
		if ((n = read(3, buf, sizeof(buf))) == -1) {
			if (errno == EINTR)
				continue;
			fatal("acl read");
		}
		if (n == 0)
			continue;
		if (write(4, buf, n) != n)
			_exit(0);
	}
}

void
bus_intr(int fd, short event, void *bula)
{
	uint8_t	 buf[BUS_READSIZE];
	ssize_t	 n;

	if ((n = read(fd, buf, sizeof(buf))) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		fatal("event read");
	}
	if (n == 0)
		return;
	imsg_compose_event(iev_engine, IMSG_HCI_EVT, 0, 0, -1, buf, n);
}

void
bus_acl(int fd, short event, void *bula)
{
	uint8_t	 buf[BUS_READSIZE];
	ssize_t	 n;

	if ((n = read(fd, buf, sizeof(buf))) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		fatal("acl read");
	}
	if (n == 0)
		fatalx("acl reader exited");
	imsg_compose_event(iev_engine, IMSG_HCI_ACLDATA, 0, 0, -1, buf, n);
}

void
bus_cmd(uint8_t *p, size_t len)
{
	struct usb_ctl_request	 ucr;

	memset(&ucr, 0, sizeof(ucr));
	ucr.ucr_request.bmRequestType = UT_WRITE_CLASS_DEVICE;
	ucr.ucr_request.bRequest = 0;
	USETW(ucr.ucr_request.wValue, 0);
	USETW(ucr.ucr_request.wIndex, 0);
	USETW(ucr.ucr_request.wLength, len);
	ucr.ucr_data = p;
	if (ioctl(ctlfd, USB_DO_REQUEST, &ucr) == -1)
		log_warn("USB_DO_REQUEST");
}

void
bus_write_acl(uint8_t *p, size_t len)
{
	ssize_t	 n;

	if ((n = write(bulkfd, p, len)) == -1)
		log_warn("acl write");
	else if ((size_t)n != len)
		log_warnx("acl write: short write");
}

void
bus_inject(int fd, struct wscons_event *ev, size_t n)
{
	size_t	 i;

	for (i = 0; i < n; i++)
		if (ioctl(fd, WSMUXIO_INJECTEVENT, &ev[i]) == -1 &&
		    errno != ENOSPC)
			log_warn("WSMUXIO_INJECTEVENT");
}

/*
 * A write-only opener that closes the mouse mux last leaves it busy, so
 * it is held only for the duration of one report.
 */
void
bus_inject_mouse(struct wscons_event *ev, size_t n)
{
	int	 fd;

	if ((fd = open(_PATH_WSMOUSE, O_WRONLY | O_CLOEXEC)) == -1) {
		log_warn("%s", _PATH_WSMOUSE);
		return;
	}
	bus_inject(fd, ev, n);
	close(fd);
}
