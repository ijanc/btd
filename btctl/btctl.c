/*
 * Copyright (c) 2024-2026 Murilo Ijanc <murilo@ijanc.org>
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
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "btd.h"
#include "parser.h"

__dead void	 usage(void);
int		 show_controller_msg(struct imsg *);
int		 show_device_msg(struct imsg *);
int		 show_bond_msg(struct imsg *);
const char	*bt_version(uint8_t);

struct imsgbuf	*ibuf;

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-s socket] command [argument ...]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un	 sun;
	struct parse_result	*res;
	struct imsg		 imsg;
	int			 ctl_sock;
	int			 done = 0;
	int			 n, verbose = 0;
	int			 ch;
	char			*sockname;

	sockname = _PATH_BTD_SOCKET;
	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			sockname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if ((res = parse(argc, argv)) == NULL)
		exit(1);

	if ((ctl_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, sockname, sizeof(sun.sun_path));

	if (connect(ctl_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", sockname);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	if ((ibuf = malloc(sizeof(struct imsgbuf))) == NULL)
		err(1, NULL);
	if (imsgbuf_init(ibuf, ctl_sock) == -1)
		err(1, NULL);
	done = 0;

	switch (res->action) {
	case SHOW_DEVICES:
		imsg_compose(ibuf, IMSG_CTL_SHOW_DEVICES, 0, 0, -1, NULL, 0);
		break;
	case SHOW_CONTROLLER:
		imsg_compose(ibuf, IMSG_CTL_SHOW_CONTROLLER, 0, 0, -1, NULL,
		    0);
		break;
	case SHOW_BONDS:
		imsg_compose(ibuf, IMSG_CTL_SHOW_BONDS, 0, 0, -1, NULL, 0);
		break;
	case LOG_VERBOSE:
		verbose = 2;
		/* FALLTHROUGH */
	case LOG_BRIEF:
		imsg_compose(ibuf, IMSG_CTL_LOG_VERBOSE, 0, 0, -1,
		    &verbose, sizeof(verbose));
		printf("logging request sent.\n");
		done = 1;
		break;
	case RELOAD:
		imsg_compose(ibuf, IMSG_CTL_RELOAD, 0, 0, -1, NULL, 0);
		printf("reload request sent.\n");
		done = 1;
		break;
	default:
		usage();
	}

	if (imsgbuf_flush(ibuf) == -1)
		err(1, "write error");

	while (!done) {
		if ((n = imsgbuf_read(ibuf)) == -1)
			err(1, "read error");
		if (n == 0)
			errx(1, "pipe closed");

		while (!done) {
			if ((n = imsgbuf_get(ibuf, &imsg)) == -1)
				errx(1, "imsgbuf_get error");
			if (n == 0)
				break;

			switch (res->action) {
			case SHOW_DEVICES:
				done = show_device_msg(&imsg);
				break;
			case SHOW_CONTROLLER:
				done = show_controller_msg(&imsg);
				break;
			case SHOW_BONDS:
				done = show_bond_msg(&imsg);
				break;
			default:
				break;
			}
			imsg_free(&imsg);
		}
	}
	close(ctl_sock);
	free(ibuf);

	return (0);
}

const char *
bt_version(uint8_t v)
{
	static const char *versions[] = {
		"1.0b", "1.1", "1.2", "2.0", "2.1", "3.0", "4.0", "4.1",
		"4.2", "5.0", "5.1", "5.2", "5.3", "5.4", "6.0"
	};

	if (v < nitems(versions))
		return (versions[v]);
	return ("?");
}

int
show_controller_msg(struct imsg *imsg)
{
	struct ctl_controller	 cc;

	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_CONTROLLER:
		if (imsg_get_data(imsg, &cc, sizeof(cc)) == -1)
			errx(1, "invalid controller message");
		printf("controller: %s\n", cc.state);
		printf("\taddress %s, identity %s\n", bdaddr_ntoa(&cc.public),
		    bdaddr_ntoa(&cc.random));
		printf("\tmanufacturer 0x%04x\n", cc.manufacturer);
		printf("\tHCI %s (0x%02x), revision 0x%04x\n",
		    bt_version(cc.hci_ver), cc.hci_ver, cc.hci_rev);
		printf("\tLMP %s (0x%02x), subversion 0x%04x\n",
		    bt_version(cc.lmp_ver), cc.lmp_ver, cc.lmp_subver);
		if (cc.fw_version != 0)
			printf("\tfirmware 0x%08x\n", cc.fw_version);
		printf("\tACL %u x %u bytes, %d free\n", cc.acl_num,
		    cc.acl_len, cc.acl_free);
		if (cc.le_acl_num != 0)
			printf("\tLE ACL %u x %u bytes, %d free\n",
			    cc.le_acl_num, cc.le_acl_len, cc.le_acl_free);
		printf("\tscanning %s, %d connection%s\n",
		    cc.scanning ? "yes" : "no", cc.conns,
		    cc.conns == 1 ? "" : "s");
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}
	return (0);
}

int
show_device_msg(struct imsg *imsg)
{
	struct ctl_device	 cd;

	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_DEVICE:
		if (imsg_get_data(imsg, &cd, sizeof(cd)) == -1)
			errx(1, "invalid device message");
		printf("%s %s: %s\n", cd.kind == CTL_DEV_HID ? "hid" :
		    "headset", bdaddr_ntoa(&cd.addr), cd.state);
		if (cd.handle != 0)
			printf("\thandle 0x%04x, peer %s (%s)\n", cd.handle,
			    bdaddr_ntoa(&cd.peer), cd.peer_type ==
			    BDADDR_RANDOM ? "random" : "public");
		printf("\t%sbonded%s%s%s\n", cd.bonded ? "" : "not ",
		    cd.encrypted ? ", encrypted" : "",
		    cd.authenticated ? ", authenticated" : "",
		    cd.sc ? ", secure connections" : "");
		if (cd.passkey != -1)
			printf("\tpasskey %06d\n", cd.passkey);
		if (cd.info[0] != '\0')
			printf("\t%s\n", cd.info);
		if (cd.battery != -1)
			printf("\tbattery %d%%\n", cd.battery);
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}
	return (0);
}

int
show_bond_msg(struct imsg *imsg)
{
	struct ctl_bond	 cb;

	switch (imsg_get_type(imsg)) {
	case IMSG_CTL_BOND:
		if (imsg_get_data(imsg, &cb, sizeof(cb)) == -1)
			errx(1, "invalid bond message");
		if (cb.type == BOND_BR)
			printf("br %s link key type %u\n",
			    bdaddr_ntoa(&cb.addr), cb.linkkey_type);
		else
			printf("le %s %s%s%s%s%s\n", bdaddr_ntoa(&cb.addr),
			    cb.addr_type == BDADDR_RANDOM ? "random" :
			    "public", cb.flags & BOND_F_LTK ? " ltk" : "",
			    cb.flags & BOND_F_IRK ? " irk" : "",
			    cb.flags & BOND_F_AUTH ? " auth" : "",
			    cb.flags & BOND_F_SC ? " sc" : "");
		break;
	case IMSG_CTL_END:
		return (1);
	default:
		break;
	}
	return (0);
}

const char *
bdaddr_ntoa(const struct bdaddr *a)
{
	static char	 buf[2][18];
	static int	 idx;
	char		*s;

	s = buf[idx++ & 1];
	snprintf(s, sizeof(buf[0]), "%02X:%02X:%02X:%02X:%02X:%02X",
	    a->b[5], a->b[4], a->b[3], a->b[2], a->b[1], a->b[0]);
	return (s);
}
