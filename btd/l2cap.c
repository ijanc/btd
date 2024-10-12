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
#include <sys/queue.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "btd.h"

#define	L2CAP_CMD_REJECT		0x01
#define	L2CAP_CONN_REQ			0x02
#define	L2CAP_CONN_RSP			0x03
#define	L2CAP_CONFIG_REQ		0x04
#define	L2CAP_CONFIG_RSP		0x05
#define	L2CAP_DISCONN_REQ		0x06
#define	L2CAP_DISCONN_RSP		0x07
#define	L2CAP_ECHO_REQ			0x08
#define	L2CAP_ECHO_RSP			0x09
#define	L2CAP_INFO_REQ			0x0a
#define	L2CAP_INFO_RSP			0x0b
#define	L2CAP_PARAM_UPDATE_REQ		0x12
#define	L2CAP_PARAM_UPDATE_RSP		0x13

#define	L2CAP_CONN_SUCCESS		0x0000
#define	L2CAP_CONN_PENDING		0x0001
#define	L2CAP_CONN_BAD_PSM		0x0002
#define	L2CAP_CONN_NO_RESOURCES		0x0004

#define	L2CAP_CFG_SUCCESS		0x0000
#define	L2CAP_CFG_UNACCEPTABLE		0x0001
#define	L2CAP_CFG_UNKNOWN		0x0003

#define	L2CAP_OPT_MTU			0x01
#define	L2CAP_OPT_RFC			0x04

#define	L2CAP_CFG_IN			0x01
#define	L2CAP_CFG_OUT			0x02

#define	L2CAP_MTU			1024
#define	L2CAP_MIN_MTU			48
#define	L2CAP_CONNLESS_MTU		1024
#define	L2CAP_RTX			10

static void	 l2cap_signal(struct hci_conn *, const uint8_t *, size_t);
static void	 l2cap_le_signal(struct hci_conn *, const uint8_t *, size_t);
static void	 l2cap_cmd(struct hci_conn *, uint16_t, uint8_t, uint8_t,
		    const uint8_t *, size_t);
static void	 l2cap_reject(struct hci_conn *, uint16_t, uint8_t);
static void	 l2cap_conn_req(struct hci_conn *, uint8_t, const uint8_t *,
		    size_t);
static void	 l2cap_conn_rsp(struct hci_conn *, const uint8_t *, size_t);
static void	 l2cap_config_req(struct hci_conn *, uint8_t, const uint8_t *,
		    size_t);
static void	 l2cap_config_rsp(struct hci_conn *, const uint8_t *, size_t);
static void	 l2cap_disconn_req(struct hci_conn *, uint8_t, const uint8_t *,
		    size_t);
static void	 l2cap_disconn_rsp(struct hci_conn *, const uint8_t *, size_t);
static void	 l2cap_info_req(struct hci_conn *, uint8_t, const uint8_t *,
		    size_t);
static void	 l2cap_send_config(struct l2cap_chan *);
static void	 l2cap_opened(struct l2cap_chan *);
static void	 l2cap_free(struct l2cap_chan *, int);
static void	 l2cap_timeout(int, short, void *);
static struct l2cap_chan *l2cap_chan_new(struct hci_conn *, uint16_t,
		    const struct l2cap_proto *, void *);
static struct l2cap_chan *l2cap_find_lcid(struct hci_conn *, uint16_t);

static const struct l2cap_proto	*servers[8];

void
l2cap_register(const struct l2cap_proto *proto)
{
	size_t	 i;

	for (i = 0; i < nitems(servers); i++)
		if (servers[i] == NULL) {
			servers[i] = proto;
			return;
		}
	fatalx("%s: too many servers", __func__);
}

void
l2cap_input(struct hci_conn *c, uint16_t cid, const uint8_t *p, size_t len)
{
	struct l2cap_chan	*ch;

	switch (cid) {
	case L2CAP_CID_SIGNAL:
		if (c->link == LINK_BR)
			l2cap_signal(c, p, len);
		return;
	case L2CAP_CID_LE_SIGNAL:
		if (c->link == LINK_LE)
			l2cap_le_signal(c, p, len);
		return;
	case L2CAP_CID_ATT:
		if (c->link == LINK_LE)
			att_input(c, p, len);
		return;
	case L2CAP_CID_SMP:
		if (c->link == LINK_LE)
			smp_input(c, p, len);
		return;
	}
	if ((ch = l2cap_find_lcid(c, cid)) == NULL ||
	    ch->state != L2CAP_S_OPEN) {
		log_debug("%s: data for unknown channel 0x%04x",
		    bdaddr_ntoa(&c->peer), cid);
		return;
	}
	ch->proto->input(ch, p, len);
}

void
l2cap_send_fixed(struct hci_conn *c, uint16_t cid, const uint8_t *p,
    size_t len)
{
	uint8_t	*buf;

	if ((buf = malloc(4 + len)) == NULL)
		fatal(NULL);
	put16(buf, len);
	put16(buf + 2, cid);
	memcpy(buf + 4, p, len);
	hci_acl_send(c, buf, 4 + len);
	free(buf);
}

static void
l2cap_cmd(struct hci_conn *c, uint16_t cid, uint8_t code, uint8_t ident,
    const uint8_t *p, size_t len)
{
	uint8_t	 buf[4 + 64];

	if (len > sizeof(buf) - 4)
		fatalx("%s: command too long", __func__);
	buf[0] = code;
	buf[1] = ident;
	put16(buf + 2, len);
	if (len > 0)
		memcpy(buf + 4, p, len);
	l2cap_send_fixed(c, cid, buf, 4 + len);
}

static uint8_t
l2cap_ident(struct hci_conn *c)
{
	if (++c->sig_ident == 0)
		c->sig_ident = 1;
	return (c->sig_ident);
}

static void
l2cap_reject(struct hci_conn *c, uint16_t cid, uint8_t ident)
{
	uint8_t	 p[2];

	put16(p, 0x0000);
	l2cap_cmd(c, cid, L2CAP_CMD_REJECT, ident, p, sizeof(p));
}

static void
l2cap_le_signal(struct hci_conn *c, const uint8_t *p, size_t len)
{
	uint8_t		 rsp[2], cmd[14];
	uint16_t	 clen;

	if (len < 4)
		return;
	clen = get16(p + 2);
	if (4 + (size_t)clen > len)
		return;
	switch (p[0]) {
	case L2CAP_PARAM_UPDATE_REQ:
		if (clen < 8)
			return;
		log_debug("%s: connection parameters %u-%u, latency %u, "
		    "timeout %u", bdaddr_ntoa(&c->peer), get16(p + 4),
		    get16(p + 6), get16(p + 8), get16(p + 10));
		put16(rsp, 0x0000);
		l2cap_cmd(c, L2CAP_CID_LE_SIGNAL, L2CAP_PARAM_UPDATE_RSP,
		    p[1], rsp, sizeof(rsp));
		put16(cmd, c->handle);
		memcpy(cmd + 2, p + 4, 8);
		put16(cmd + 10, 0);
		put16(cmd + 12, 0);
		hci_cmd(HCI_CMD_LE_CONN_UPDATE, cmd, sizeof(cmd), NULL, NULL);
		break;
	case L2CAP_CMD_REJECT:
	case L2CAP_PARAM_UPDATE_RSP:
		break;
	default:
		l2cap_reject(c, L2CAP_CID_LE_SIGNAL, p[1]);
		break;
	}
}

