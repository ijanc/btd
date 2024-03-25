/*
 * Copyright (c) 2024 Murilo Ijanc <murilo@ijanc.org>
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
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/wait.h>

#include <dev/usb/usb.h>
#include <dev/wscons/wsconsio.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "btd.h"

enum btd_process {
	PROC_MAIN,
	PROC_BUS,
	PROC_ENGINE,
	PROC_FRONTEND
};

struct usb_dongle {
	uint16_t	 vendor;
	uint16_t	 product;
	const char	*firmware;
};

static const struct usb_dongle dongles[] = {
	{ 0x2357, 0x0604, "rtl8761bu" },
};

#define	FW_MAXSIZE	(1024 * 1024)

__dead void	 usage(void);
__dead void	 main_shutdown(void);
void		 main_sig_handler(int, short, void *);
static pid_t	 start_child(enum btd_process, char *, int, int, int);
void		 main_dispatch_bus(int, short, void *);
void		 main_dispatch_engine(int, short, void *);
void		 main_dispatch_frontend(int, short, void *);
static int	 main_imsg_send_ipc_sockets(void);
int		 main_reload(void);
int		 main_sendall(enum imsg_type, void *, uint16_t);
void		 main_send_config(struct imsgev *, struct btd_conf *);
void		 main_send_bonds(void);
void		 main_send_firmware(const char *);
void		 main_send_file(const char *, enum imsg_type);
void		 main_bond_save(struct bond *);
void		 main_bond_delete(struct bond *);
void		 main_bond_local_save(struct bond_local *);
int		 find_dongle(char *, size_t);
int		 open_ep(const char *, int, int);
int		 kbd_type(void);

static struct imsgev	*iev_bus;
static struct imsgev	*iev_engine;
static struct imsgev	*iev_frontend;
static struct btd_conf	*main_conf;
static char		*conffile;
static struct bond_list	 bonds = TAILQ_HEAD_INITIALIZER(bonds);
static struct bond_local bond_local;
static int		 have_local;

pid_t	 bus_pid;
pid_t	 engine_pid;
pid_t	 frontend_pid;

void
main_sig_handler(int sig, short event, void *arg)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		main_shutdown();
	case SIGHUP:
		if (main_reload() == -1)
			log_warnx("configuration reload failed");
		else
			log_debug("configuration reloaded");
		break;
	default:
		fatalx("unexpected signal");
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file] [-s socket]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event		 ev_sigint, ev_sigterm, ev_sighup;
	struct usb_device_info	 udi;
	int			 ch, debug = 0, verbose = 0, noaction = 0;
	int			 bus_flag = 0, engine_flag = 0, frontend_flag = 0;
	int			 pipe_main2bus[2], pipe_main2engine[2];
	int			 pipe_main2frontend[2];
	int			 lockfd, control_fd, ctlfd, intrfd, bulkfd, cfgfd;
	int			 kbdtype;
	char			 execpath[PATH_MAX], device[16];
	char			*csock = _PATH_BTD_SOCKET;
	const char		*firmware;
	size_t			 i;

	conffile = _PATH_CONF_FILE;

	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	while ((ch = getopt(argc, argv, "BdEFf:ns:v")) != -1) {
		switch (ch) {
		case 'B':
			bus_flag = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'E':
			engine_flag = 1;
			break;
		case 'F':
			frontend_flag = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			noaction = 1;
			break;
		case 's':
			csock = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || bus_flag + engine_flag + frontend_flag > 1)
		usage();

	if (bus_flag)
		bus(debug, verbose);
	else if (engine_flag)
		engine(debug, verbose);
	else if (frontend_flag)
		frontend(debug, verbose);

	log_setverbose(verbose);
	if ((main_conf = parse_config(conffile)) == NULL)
		exit(1);

	if (noaction) {
		if (verbose)
			print_config(main_conf);
		else
			fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	if (geteuid())
		errx(1, "need root privileges");

	lockfd = open(_PATH_LOCKFILE, O_CREAT|O_RDWR|O_EXLOCK|O_NONBLOCK, 0600);
	if (lockfd == -1) {
		if (errno == EAGAIN)
			errx(1, "already running");
		err(1, "%s", _PATH_LOCKFILE);
	}

	if (getpwnam(BTD_USER) == NULL)
		errx(1, "unknown user %s", BTD_USER);

	if (getexecpath(execpath, sizeof(execpath)) != 0)
		errx(1, "getexecpath");

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (main_conf->device[0] != '\0')
		strlcpy(device, main_conf->device, sizeof(device));
	else if (find_dongle(device, sizeof(device)) == -1)
		fatalx("no Bluetooth controller found");

	ctlfd = open_ep(device, 0, O_RDWR);
	intrfd = open_ep(device, 1, O_RDONLY | O_NONBLOCK);
	bulkfd = open_ep(device, 2, O_RDWR);
	if ((cfgfd = open(_PATH_WSCFG, O_WRONLY | O_CLOEXEC)) == -1)
		fatal("%s", _PATH_WSCFG);
	kbdtype = kbd_type();

	memset(&udi, 0, sizeof(udi));
	if (ioctl(ctlfd, USB_GET_DEVICEINFO, &udi) == -1)
		fatal("USB_GET_DEVICEINFO");
	firmware = main_conf->firmware[0] != '\0' ? main_conf->firmware : NULL;
	for (i = 0; firmware == NULL && i < nitems(dongles); i++)
		if (dongles[i].vendor == udi.udi_vendorNo &&
		    dongles[i].product == udi.udi_productNo)
			firmware = dongles[i].firmware;
	log_info("%s: %04x:%04x \"%s\"%s%s", device, udi.udi_vendorNo,
	    udi.udi_productNo, udi.udi_product, firmware ? ", firmware " : "",
	    firmware ? firmware : "");

	if (bond_read(_PATH_BONDS, &bonds, &bond_local) == 1)
		have_local = 1;

	if (!debug)
		daemon(0, 0);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2bus) == -1)
		fatal("main2bus socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2engine) == -1)
		fatal("main2engine socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2frontend) == -1)
		fatal("main2frontend socketpair");

	bus_pid = start_child(PROC_BUS, execpath, pipe_main2bus[1], debug,
	    verbose);
	engine_pid = start_child(PROC_ENGINE, execpath, pipe_main2engine[1],
	    debug, verbose);
	frontend_pid = start_child(PROC_FRONTEND, execpath,
	    pipe_main2frontend[1], debug, verbose);

	log_procinit("main");

	event_init();

	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	if ((iev_bus = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_engine = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_frontend = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	if (imsgbuf_init(&iev_bus->ibuf, pipe_main2bus[0]) == -1 ||
	    imsgbuf_init(&iev_engine->ibuf, pipe_main2engine[0]) == -1 ||
	    imsgbuf_init(&iev_frontend->ibuf, pipe_main2frontend[0]) == -1)
		fatal(NULL);
	imsgbuf_allow_fdpass(&iev_bus->ibuf);
	imsgbuf_allow_fdpass(&iev_engine->ibuf);
	imsgbuf_allow_fdpass(&iev_frontend->ibuf);
	iev_bus->handler = main_dispatch_bus;
	iev_engine->handler = main_dispatch_engine;
	iev_frontend->handler = main_dispatch_frontend;

	iev_bus->events = EV_READ;
	event_set(&iev_bus->ev, iev_bus->ibuf.fd, iev_bus->events,
	    iev_bus->handler, iev_bus);
	event_add(&iev_bus->ev, NULL);

	iev_engine->events = EV_READ;
	event_set(&iev_engine->ev, iev_engine->ibuf.fd, iev_engine->events,
	    iev_engine->handler, iev_engine);
	event_add(&iev_engine->ev, NULL);

	iev_frontend->events = EV_READ;
	event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
	    iev_frontend->events, iev_frontend->handler, iev_frontend);
	event_add(&iev_frontend->ev, NULL);

	if (main_imsg_send_ipc_sockets() == -1)
		fatal("could not establish imsg links");

	if ((control_fd = control_init(csock)) == -1)
		fatalx("control socket setup failed");

	if (firmware != NULL)
		main_send_firmware(firmware);
	imsg_compose_event(iev_engine, IMSG_FIRMWARE_END, 0, 0, -1, NULL, 0);

	if (unveil(conffile, "r") == -1)
		fatal("unveil %s", conffile);
	if (unveil(_PATH_BTD_DB, "rwc") == -1)
		fatal("unveil %s", _PATH_BTD_DB);
	if (unveil(NULL, NULL) == -1)
		fatal("unveil");

	if (pledge("stdio rpath wpath cpath sendfd", NULL) == -1)
		fatal("pledge");

	imsg_compose_event(iev_bus, IMSG_DEVFD_CTL, 0, 0, ctlfd, NULL, 0);
	imsg_compose_event(iev_bus, IMSG_DEVFD_INTR, 0, 0, intrfd, NULL, 0);
	imsg_compose_event(iev_bus, IMSG_DEVFD_BULK, 0, 0, bulkfd, NULL, 0);
	imsg_compose_event(iev_bus, IMSG_DEVFD_WSCFG, 0, 0, cfgfd, NULL, 0);
	imsg_compose_event(iev_bus, IMSG_STARTUP, 0, 0, -1, NULL, 0);

	imsg_compose_event(iev_frontend, IMSG_CONTROLFD, 0, 0, control_fd,
	    NULL, 0);

	imsg_compose_event(iev_engine, IMSG_KBDTYPE, 0, 0, -1, &kbdtype,
	    sizeof(kbdtype));
	main_send_bonds();
	main_send_config(iev_engine, main_conf);
	main_send_config(iev_frontend, main_conf);
	imsg_compose_event(iev_engine, IMSG_STARTUP, 0, 0, -1, NULL, 0);
	imsg_compose_event(iev_frontend, IMSG_STARTUP, 0, 0, -1, NULL, 0);

	event_dispatch();

	main_shutdown();
	return (0);
}

__dead void
main_shutdown(void)
{
	pid_t	 pid;
	int	 status;

	imsgbuf_clear(&iev_bus->ibuf);
	close(iev_bus->ibuf.fd);
	imsgbuf_clear(&iev_engine->ibuf);
	close(iev_engine->ibuf.fd);
	imsgbuf_clear(&iev_frontend->ibuf);
	close(iev_frontend->ibuf.fd);

	config_clear(main_conf);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
			    pid == bus_pid ? "bus" : pid == engine_pid ?
			    "engine" : "frontend", WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(iev_bus);
	free(iev_engine);
	free(iev_frontend);

	log_info("terminating");
	exit(0);
}

static pid_t
start_child(enum btd_process p, char *execpath, int fd, int debug,
    int verbose)
{
	char	*argv[7];
	int	 argc = 0;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (fd != 3) {
		if (dup2(fd, 3) == -1)
			fatal("cannot setup imsg fd");
	} else if (fcntl(fd, F_SETFD, 0) == -1)
		fatal("cannot setup imsg fd");

	argv[argc++] = execpath;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_BUS:
		argv[argc++] = "-B";
		break;
	case PROC_ENGINE:
		argv[argc++] = "-E";
		break;
	case PROC_FRONTEND:
		argv[argc++] = "-F";
		break;
	}
	if (debug)
		argv[argc++] = "-d";
	if (verbose)
		argv[argc++] = "-v";
	if (verbose > 1)
		argv[argc++] = "-v";
	if (verbose > 2)
		argv[argc++] = "-v";
	argv[argc++] = NULL;

	execv(execpath, argv);
	fatal("execv");
}

void
main_dispatch_bus(int fd, short event, void *bula)
{
	struct imsgev	*iev = bula;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	int		 n, shut = 0;

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
		log_debug("%s: error handling imsg %d", __func__,
		    imsg_get_type(&imsg));
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
main_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	struct bond		 bond;
	struct bond_local	 local;
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
		case IMSG_BOND_SAVE:
			if (imsg_get_data(&imsg, &bond, sizeof(bond)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			main_bond_save(&bond);
			break;
		case IMSG_BOND_DELETE:
			if (imsg_get_data(&imsg, &bond, sizeof(bond)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			main_bond_delete(&bond);
			break;
		case IMSG_BOND_LOCAL_SAVE:
			if (imsg_get_data(&imsg, &local, sizeof(local)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			main_bond_local_save(&local);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__, type);
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
main_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev	*iev = bula;
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	uint32_t	 type;
	int		 n, shut = 0, verbose;

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
		case IMSG_CTL_LOG_VERBOSE:
			if (imsg_get_data(&imsg, &verbose,
			    sizeof(verbose)) == -1)
				fatalx("%s: invalid %s", __func__, i2s(type));
			log_setverbose(verbose);
			imsg_compose_event(iev_bus, type, 0, 0, -1, &verbose,
			    sizeof(verbose));
			break;
		case IMSG_CTL_RELOAD:
			if (main_reload() == -1)
				log_warnx("configuration reload failed");
			else
				log_info("configuration reloaded");
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__, type);
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

static int
main_imsg_send_ipc_sockets(void)
{
	int	 pipe_frontend2engine[2], pipe_bus2engine[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_frontend2engine) == -1)
		return (-1);
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_bus2engine) == -1)
		return (-1);

	if (imsg_compose(&iev_frontend->ibuf, IMSG_SOCKET_IPC, 0, 0,
	    pipe_frontend2engine[0], NULL, 0) == -1)
		return (-1);
	imsgbuf_flush(&iev_frontend->ibuf);
	if (imsg_compose(&iev_engine->ibuf, IMSG_SOCKET_IPC, 0, 0,
	    pipe_frontend2engine[1], NULL, 0) == -1)
		return (-1);
	if (imsg_compose(&iev_engine->ibuf, IMSG_SOCKET_BUS, 0, 0,
	    pipe_bus2engine[1], NULL, 0) == -1)
		return (-1);
	imsgbuf_flush(&iev_engine->ibuf);
	if (imsg_compose(&iev_bus->ibuf, IMSG_SOCKET_BUS, 0, 0,
	    pipe_bus2engine[0], NULL, 0) == -1)
		return (-1);
	imsgbuf_flush(&iev_bus->ibuf);
	return (0);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf) > 0)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, uint16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data,
	    datalen)) != -1)
		imsg_event_add(iev);

	return (ret);
}

int
imsg_forward_event(struct imsgev *iev, struct imsg *imsg)
{
	int	ret;

	if ((ret = imsg_forward(&iev->ibuf, imsg)) != -1)
		imsg_event_add(iev);

	return (ret);
}

const char *
bdaddr_ntoa(const struct bdaddr *a)
{
	static char	 buf[4][18];
	static int	 idx;
	char		*s;

	s = buf[idx++ & 3];
	snprintf(s, sizeof(buf[0]), "%02X:%02X:%02X:%02X:%02X:%02X",
	    a->b[5], a->b[4], a->b[3], a->b[2], a->b[1], a->b[0]);
	return (s);
}

int
bdaddr_aton(const char *s, struct bdaddr *a)
{
	unsigned int	 v[6];
	char		 c;
	int		 i;

	if (strlen(s) != 17)
		return (-1);
	if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", &v[0], &v[1], &v[2],
	    &v[3], &v[4], &v[5], &c) != 6)
		return (-1);
	for (i = 0; i < 6; i++)
		a->b[5 - i] = v[i];
	return (0);
}

int
bdaddr_cmp(const struct bdaddr *a, const struct bdaddr *b)
{
	return (memcmp(a->b, b->b, sizeof(a->b)));
}

#define	I2S(x) case x: return #x

const char *
i2s(uint32_t type)
{
	static char	unknown[sizeof("IMSG_4294967295")];

	switch (type) {
	I2S(IMSG_NONE);
	I2S(IMSG_CTL_LOG_VERBOSE);
	I2S(IMSG_CTL_RELOAD);
	I2S(IMSG_CTL_SHOW_CONTROLLER);
	I2S(IMSG_CTL_SHOW_DEVICES);
	I2S(IMSG_CTL_SHOW_BONDS);
	I2S(IMSG_CTL_CONTROLLER);
	I2S(IMSG_CTL_DEVICE);
	I2S(IMSG_CTL_BOND);
	I2S(IMSG_CTL_END);
	I2S(IMSG_SOCKET_IPC);
	I2S(IMSG_SOCKET_BUS);
	I2S(IMSG_CONTROLFD);
	I2S(IMSG_DEVFD_CTL);
	I2S(IMSG_DEVFD_INTR);
	I2S(IMSG_DEVFD_BULK);
	I2S(IMSG_DEVFD_WSCFG);
	I2S(IMSG_KBDTYPE);
	I2S(IMSG_FIRMWARE);
	I2S(IMSG_FIRMWARE_CONFIG);
	I2S(IMSG_FIRMWARE_END);
	I2S(IMSG_BOND);
	I2S(IMSG_BOND_LOCAL);
	I2S(IMSG_BOND_SAVE);
	I2S(IMSG_BOND_DELETE);
	I2S(IMSG_BOND_LOCAL_SAVE);
	I2S(IMSG_BONDS_END);
	I2S(IMSG_RECONF_CONF);
	I2S(IMSG_RECONF_HID);
	I2S(IMSG_RECONF_HEADSET);
	I2S(IMSG_RECONF_END);
	I2S(IMSG_STARTUP);
	I2S(IMSG_HCI_CMD);
	I2S(IMSG_HCI_ACL);
	I2S(IMSG_HCI_EVT);
	I2S(IMSG_HCI_ACLDATA);
	I2S(IMSG_WSKBD);
	I2S(IMSG_WSMOUSE);
	I2S(IMSG_AUDIO_START);
	I2S(IMSG_AUDIO_STOP);
	I2S(IMSG_AUDIO_FRAME);
	I2S(IMSG_VOLUME_LOCAL);
	I2S(IMSG_VOLUME_REMOTE);
	default:
		snprintf(unknown, sizeof(unknown), "IMSG_%u", type);
		return (unknown);
	}
}
#undef	I2S
