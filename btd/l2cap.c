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

int
l2cap_send(struct l2cap_chan *ch, const uint8_t *p, size_t len)
{
	if (ch->state != L2CAP_S_OPEN)
		return (-1);
	if (len > ch->omtu) {
		log_debug("%s: psm 0x%04x: %zu bytes over mtu %u",
		    bdaddr_ntoa(&ch->conn->peer), ch->psm, len, ch->omtu);
		return (-1);
	}
	l2cap_send_fixed(ch->conn, ch->rcid, p, len);
	return (0);
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
l2cap_signal(struct hci_conn *c, const uint8_t *p, size_t len)
{
	uint16_t	 clen;
	uint8_t		 code, ident;

	while (len >= 4) {
		code = p[0];
		ident = p[1];
		clen = get16(p + 2);
		if (4 + (size_t)clen > len)
			return;
		switch (code) {
		case L2CAP_CMD_REJECT:
			log_debug("%s: command rejected", bdaddr_ntoa(&c->peer));
			break;
		case L2CAP_CONN_REQ:
			l2cap_conn_req(c, ident, p + 4, clen);
			break;
		case L2CAP_CONN_RSP:
			l2cap_conn_rsp(c, p + 4, clen);
			break;
		case L2CAP_CONFIG_REQ:
			l2cap_config_req(c, ident, p + 4, clen);
			break;
		case L2CAP_CONFIG_RSP:
			l2cap_config_rsp(c, p + 4, clen);
			break;
		case L2CAP_DISCONN_REQ:
			l2cap_disconn_req(c, ident, p + 4, clen);
			break;
		case L2CAP_DISCONN_RSP:
			l2cap_disconn_rsp(c, p + 4, clen);
			break;
		case L2CAP_ECHO_REQ:
			l2cap_cmd(c, L2CAP_CID_SIGNAL, L2CAP_ECHO_RSP, ident,
			    NULL, 0);
			break;
		case L2CAP_INFO_REQ:
			l2cap_info_req(c, ident, p + 4, clen);
			break;
		case L2CAP_ECHO_RSP:
		case L2CAP_INFO_RSP:
			break;
		default:
			l2cap_reject(c, L2CAP_CID_SIGNAL, ident);
			break;
		}
		p += 4 + clen;
		len -= 4 + clen;
	}
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

static struct l2cap_chan *
l2cap_chan_new(struct hci_conn *c, uint16_t psm,
    const struct l2cap_proto *proto, void *arg)
{
	struct l2cap_chan	*ch;

	if ((ch = calloc(1, sizeof(*ch))) == NULL)
		fatal(NULL);
	ch->conn = c;
	ch->psm = psm;
	ch->lcid = c->next_cid++;
	if (c->next_cid == 0)
		c->next_cid = L2CAP_CID_DYN;
	ch->imtu = L2CAP_MTU;
	ch->omtu = 672;
	ch->proto = proto;
	ch->arg = arg;
	evtimer_set(&ch->timer, l2cap_timeout, ch);
	TAILQ_INSERT_TAIL(&c->chans, ch, entry);
	return (ch);
}

static struct l2cap_chan *
l2cap_find_lcid(struct hci_conn *c, uint16_t cid)
{
	struct l2cap_chan	*ch;

	TAILQ_FOREACH(ch, &c->chans, entry)
		if (ch->lcid == cid)
			return (ch);
	return (NULL);
}

static void
l2cap_timer(struct l2cap_chan *ch)
{
	struct timeval	 tv = { L2CAP_RTX, 0 };

	evtimer_add(&ch->timer, &tv);
}

static void
l2cap_timeout(int fd, short event, void *arg)
{
	struct l2cap_chan	*ch = arg;

	log_warnx("%s: psm 0x%04x: signalling timeout",
	    bdaddr_ntoa(&ch->conn->peer), ch->psm);
	l2cap_free(ch, 1);
}

struct l2cap_chan *
l2cap_connect(struct hci_conn *c, uint16_t psm,
    const struct l2cap_proto *proto, void *arg)
{
	struct l2cap_chan	*ch;
	uint8_t			 p[4];

	ch = l2cap_chan_new(c, psm, proto, arg);
	ch->state = L2CAP_S_WAIT_CONNECT;
	ch->ident = l2cap_ident(c);
	put16(p, psm);
	put16(p + 2, ch->lcid);
	l2cap_cmd(c, L2CAP_CID_SIGNAL, L2CAP_CONN_REQ, ch->ident, p,
	    sizeof(p));
	l2cap_timer(ch);
	return (ch);
}

void
l2cap_close(struct l2cap_chan *ch)
{
	uint8_t	 p[4];

	if (ch->state != L2CAP_S_OPEN && ch->state != L2CAP_S_CONFIG) {
		l2cap_free(ch, 0);
		return;
	}
	ch->state = L2CAP_S_WAIT_DISCONNECT;
	ch->ident = l2cap_ident(ch->conn);
	put16(p, ch->rcid);
	put16(p + 2, ch->lcid);
	l2cap_cmd(ch->conn, L2CAP_CID_SIGNAL, L2CAP_DISCONN_REQ, ch->ident,
	    p, sizeof(p));
	l2cap_timer(ch);
}

static void
l2cap_free(struct l2cap_chan *ch, int notify)
{
	evtimer_del(&ch->timer);
	TAILQ_REMOVE(&ch->conn->chans, ch, entry);
	if (notify && ch->proto->close != NULL)
		ch->proto->close(ch);
	free(ch);
}

void
l2cap_conn_free(struct hci_conn *c)
{
	struct l2cap_chan	*ch;

	while ((ch = TAILQ_FIRST(&c->chans)) != NULL)
		l2cap_free(ch, 1);
}

static void
l2cap_conn_req(struct hci_conn *c, uint8_t ident, const uint8_t *p,
    size_t len)
{
	const struct l2cap_proto	*proto = NULL;
	struct l2cap_chan		*ch = NULL;
	void				*arg = NULL;
	uint16_t			 psm, scid, result;
	uint8_t				 rsp[8];
	size_t				 i;

	if (len < 4)
		return;
	psm = get16(p);
	scid = get16(p + 2);
	for (i = 0; i < nitems(servers); i++)
		if (servers[i] != NULL && servers[i]->psm == psm) {
			proto = servers[i];
			break;
		}
	if (proto == NULL)
		result = L2CAP_CONN_BAD_PSM;
	else if ((arg = proto->accept(c)) == NULL)
		result = L2CAP_CONN_NO_RESOURCES;
	else {
		result = L2CAP_CONN_SUCCESS;
		ch = l2cap_chan_new(c, psm, proto, arg);
		ch->rcid = scid;
		ch->state = L2CAP_S_CONFIG;
	}
	log_debug("%s: incoming channel psm 0x%04x: %s",
	    bdaddr_ntoa(&c->peer), psm, result == 0 ? "accepted" : "refused");

	put16(rsp, ch != NULL ? ch->lcid : 0);
	put16(rsp + 2, scid);
	put16(rsp + 4, result);
	put16(rsp + 6, 0);
	l2cap_cmd(c, L2CAP_CID_SIGNAL, L2CAP_CONN_RSP, ident, rsp,
	    sizeof(rsp));
	if (ch != NULL)
		l2cap_send_config(ch);
}

static void
l2cap_conn_rsp(struct hci_conn *c, const uint8_t *p, size_t len)
{
	struct l2cap_chan	*ch;
	uint16_t		 result;

	if (len < 8)
		return;
	if ((ch = l2cap_find_lcid(c, get16(p + 2))) == NULL ||
	    ch->state != L2CAP_S_WAIT_CONNECT)
		return;
	result = get16(p + 4);
	if (result == L2CAP_CONN_PENDING)
		return;
	if (result != L2CAP_CONN_SUCCESS) {
		log_warnx("%s: psm 0x%04x refused: 0x%04x",
		    bdaddr_ntoa(&c->peer), ch->psm, result);
		l2cap_free(ch, 1);
		return;
	}
	ch->rcid = get16(p);
	ch->state = L2CAP_S_CONFIG;
	l2cap_send_config(ch);
}

static void
l2cap_send_config(struct l2cap_chan *ch)
{
	uint8_t	 p[8];

	ch->ident = l2cap_ident(ch->conn);
	put16(p, ch->rcid);
	put16(p + 2, 0);
	p[4] = L2CAP_OPT_MTU;
	p[5] = 2;
	put16(p + 6, ch->imtu);
	l2cap_cmd(ch->conn, L2CAP_CID_SIGNAL, L2CAP_CONFIG_REQ, ch->ident, p,
	    sizeof(p));
	l2cap_timer(ch);
}

static void
l2cap_config_req(struct hci_conn *c, uint8_t ident, const uint8_t *p,
    size_t len)
{
	struct l2cap_chan	*ch;
	uint8_t			 rsp[64];
	uint16_t		 result = L2CAP_CFG_SUCCESS, mtu;
	size_t			 off, rlen = 6;
	uint8_t			 type, olen;

	if (len < 4)
		return;
	if ((ch = l2cap_find_lcid(c, get16(p))) == NULL ||
	    (ch->state != L2CAP_S_CONFIG && ch->state != L2CAP_S_OPEN)) {
		l2cap_reject(c, L2CAP_CID_SIGNAL, ident);
		return;
	}
	for (off = 4; off + 2 <= len; off += 2 + olen) {
		type = p[off];
		olen = p[off + 1];
		if (off + 2 + olen > len)
			break;
		switch (type & 0x7f) {
		case L2CAP_OPT_MTU:
			if (olen != 2)
				break;
			mtu = get16(p + off + 2);
			if (mtu < L2CAP_MIN_MTU) {
				result = L2CAP_CFG_UNACCEPTABLE;
				break;
			}
			ch->omtu = mtu;
			break;
		case L2CAP_OPT_RFC:
			if (olen >= 1 && p[off + 2] != 0 &&
			    rlen + 2 + olen <= sizeof(rsp)) {
				result = L2CAP_CFG_UNACCEPTABLE;
				rsp[rlen] = L2CAP_OPT_RFC;
				rsp[rlen + 1] = olen;
				memset(rsp + rlen + 2, 0, olen);
				rlen += 2 + olen;
			}
			break;
		case 0x02:
		case 0x03:
		case 0x05:
		case 0x06:
			break;
		default:
			if (type & 0x80)
				break;
			if (result == L2CAP_CFG_SUCCESS)
				rlen = 6;
			result = L2CAP_CFG_UNKNOWN;
			if (rlen + 2 + olen <= sizeof(rsp)) {
				memcpy(rsp + rlen, p + off, 2 + olen);
				rlen += 2 + olen;
			}
			break;
		}
	}
	put16(rsp, ch->rcid);
	put16(rsp + 2, 0);
	put16(rsp + 4, result);
	l2cap_cmd(c, L2CAP_CID_SIGNAL, L2CAP_CONFIG_RSP, ident, rsp, rlen);
	if (result != L2CAP_CFG_SUCCESS || (get16(p + 2) & 1))
		return;
	ch->cfg |= L2CAP_CFG_IN;
	if (ch->cfg == (L2CAP_CFG_IN | L2CAP_CFG_OUT))
		l2cap_opened(ch);
}

static void
l2cap_config_rsp(struct hci_conn *c, const uint8_t *p, size_t len)
{
	struct l2cap_chan	*ch;
	uint16_t		 result;

	if (len < 6)
		return;
	if ((ch = l2cap_find_lcid(c, get16(p))) == NULL ||
	    ch->state != L2CAP_S_CONFIG)
		return;
	result = get16(p + 4);
	if (result != L2CAP_CFG_SUCCESS) {
		log_warnx("%s: psm 0x%04x: configuration refused: 0x%04x",
		    bdaddr_ntoa(&c->peer), ch->psm, result);
		l2cap_close(ch);
		return;
	}
	evtimer_del(&ch->timer);
	ch->cfg |= L2CAP_CFG_OUT;
	if (ch->cfg == (L2CAP_CFG_IN | L2CAP_CFG_OUT))
		l2cap_opened(ch);
}

static void
l2cap_opened(struct l2cap_chan *ch)
{
	if (ch->state == L2CAP_S_OPEN)
		return;
	evtimer_del(&ch->timer);
	ch->state = L2CAP_S_OPEN;
	log_debug("%s: channel psm 0x%04x open, cid 0x%04x/0x%04x, mtu %u/%u",
	    bdaddr_ntoa(&ch->conn->peer), ch->psm, ch->lcid, ch->rcid,
	    ch->imtu, ch->omtu);
	if (ch->proto->open != NULL)
		ch->proto->open(ch);
}

static void
l2cap_disconn_req(struct hci_conn *c, uint8_t ident, const uint8_t *p,
    size_t len)
{
	struct l2cap_chan	*ch;
	uint8_t			 rsp[4];

	if (len < 4)
		return;
	if ((ch = l2cap_find_lcid(c, get16(p))) == NULL) {
		l2cap_reject(c, L2CAP_CID_SIGNAL, ident);
		return;
	}
	put16(rsp, ch->lcid);
	put16(rsp + 2, ch->rcid);
	l2cap_cmd(c, L2CAP_CID_SIGNAL, L2CAP_DISCONN_RSP, ident, rsp,
	    sizeof(rsp));
	log_debug("%s: channel psm 0x%04x closed by peer",
	    bdaddr_ntoa(&c->peer), ch->psm);
	l2cap_free(ch, 1);
}

static void
l2cap_disconn_rsp(struct hci_conn *c, const uint8_t *p, size_t len)
{
	struct l2cap_chan	*ch;

	if (len < 4)
		return;
	if ((ch = l2cap_find_lcid(c, get16(p + 2))) == NULL ||
	    ch->state != L2CAP_S_WAIT_DISCONNECT)
		return;
	l2cap_free(ch, 1);
}

static void
l2cap_info_req(struct hci_conn *c, uint8_t ident, const uint8_t *p,
    size_t len)
{
	uint8_t		 rsp[12];
	uint16_t	 type;
	size_t		 rlen = 4;

	if (len < 2)
		return;
	type = get16(p);
	put16(rsp, type);
	put16(rsp + 2, 0x0000);
	switch (type) {
	case 0x0001:
		put16(rsp + 4, L2CAP_CONNLESS_MTU);
		rlen += 2;
		break;
	case 0x0002:
		put32(rsp + 4, 0x00000080);
		rlen += 4;
		break;
	case 0x0003:
		put64(rsp + 4, 1ULL << L2CAP_CID_SIGNAL);
		rlen += 8;
		break;
	default:
		put16(rsp + 2, 0x0001);
		break;
	}
	l2cap_cmd(c, L2CAP_CID_SIGNAL, L2CAP_INFO_RSP, ident, rsp, rlen);
}
