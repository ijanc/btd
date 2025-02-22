/*
 * Copyright (c) 2025 Murilo Ijanc <murilo@ijanc.org>
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

#define	ATT_TIMEOUT		30
#define	ATT_DEFAULT_MTU		23
#define	ATT_MAX_MTU		247
#define	ATT_MAX_PDU		(ATT_MAX_MTU + 8)

struct att_req {
	TAILQ_ENTRY(att_req)	 entry;
	uint8_t			 pdu[ATT_MAX_PDU];
	size_t			 len;
	att_cb			 cb;
	void			*arg;
};

struct att {
	struct hci_conn		*conn;
	uint16_t		 mtu;
	struct att_req		*cur;
	TAILQ_HEAD(, att_req)	 queue;
	struct event		 timer;
	att_notify_cb		 notify;
	void			*arg;
};

static void	 att_kick(struct att *);
static void	 att_timeout(int, short, void *);
static void	 att_error_rsp(struct att *, uint8_t, uint16_t, uint8_t);
static void	 att_server(struct att *, const uint8_t *, size_t);

struct att *
att_new(struct hci_conn *c, att_notify_cb notify, void *arg)
{
	struct att	*att;

	if ((att = calloc(1, sizeof(*att))) == NULL)
		fatal(NULL);
	att->conn = c;
	att->mtu = ATT_DEFAULT_MTU;
	att->notify = notify;
	att->arg = arg;
	TAILQ_INIT(&att->queue);
	evtimer_set(&att->timer, att_timeout, att);
	c->att = att;
	return (att);
}

void
att_set_notify(struct att *att, att_notify_cb notify, void *arg)
{
	att->notify = notify;
	att->arg = arg;
}

void
att_free(struct att *att)
{
	struct att_req	*r;

	if (att == NULL)
		return;
	evtimer_del(&att->timer);
	free(att->cur);
	while ((r = TAILQ_FIRST(&att->queue)) != NULL) {
		TAILQ_REMOVE(&att->queue, r, entry);
		free(r);
	}
	if (att->conn != NULL)
		att->conn->att = NULL;
	free(att);
}

uint16_t
att_mtu(struct att *att)
{
	return (att->mtu);
}

void
att_request(struct att *att, const uint8_t *pdu, size_t len, att_cb cb,
    void *arg)
{
	struct att_req	*r;

	if (len > att->mtu || len > sizeof(r->pdu))
		fatalx("%s: request too long", __func__);
	if ((r = calloc(1, sizeof(*r))) == NULL)
		fatal(NULL);
	memcpy(r->pdu, pdu, len);
	r->len = len;
	r->cb = cb;
	r->arg = arg;
	TAILQ_INSERT_TAIL(&att->queue, r, entry);
	att_kick(att);
}

static void
att_kick(struct att *att)
{
	struct timeval	 tv = { ATT_TIMEOUT, 0 };
	struct att_req	*r;

	if (att->cur != NULL || (r = TAILQ_FIRST(&att->queue)) == NULL)
		return;
	TAILQ_REMOVE(&att->queue, r, entry);
	att->cur = r;
	l2cap_send_fixed(att->conn, L2CAP_CID_ATT, r->pdu, r->len);
	evtimer_add(&att->timer, &tv);
}

static void
att_timeout(int fd, short event, void *arg)
{
	struct att	*att = arg;

	log_warnx("%s: attribute protocol timeout",
	    bdaddr_ntoa(&att->conn->peer));
	hci_disconnect(att->conn, HCI_ERR_REMOTE_USER);
}

static void
att_error_rsp(struct att *att, uint8_t op, uint16_t handle, uint8_t err)
{
	uint8_t	 p[5];

	p[0] = ATT_OP_ERROR_RSP;
	p[1] = op;
	put16(p + 2, handle);
	p[4] = err;
	l2cap_send_fixed(att->conn, L2CAP_CID_ATT, p, sizeof(p));
}

void
att_input(struct hci_conn *c, const uint8_t *p, size_t len)
{
	struct att	*att = c->att;
	struct att_req	*r;
	uint8_t		 op, rop, confirm;

	if (len < 1 || att == NULL)
		return;
	op = p[0];

	switch (op) {
	case ATT_OP_NOTIFY:
		if (len >= 3 && att->notify != NULL)
			att->notify(att->arg, get16(p + 1), p + 3, len - 3);
		return;
	case ATT_OP_INDICATE:
		confirm = ATT_OP_CONFIRM;
		l2cap_send_fixed(c, L2CAP_CID_ATT, &confirm, 1);
		if (len >= 3 && att->notify != NULL)
			att->notify(att->arg, get16(p + 1), p + 3, len - 3);
		return;
	}

	if ((r = att->cur) == NULL || !(op == ATT_OP_ERROR_RSP ||
	    op == r->pdu[0] + 1)) {
		att_server(att, p, len);
		return;
	}
	if (op == ATT_OP_ERROR_RSP && (len < 5 || p[1] != r->pdu[0])) {
		att_server(att, p, len);
		return;
	}
	evtimer_del(&att->timer);
	att->cur = NULL;
	rop = r->pdu[0];
	if (rop == ATT_OP_MTU_REQ && op == ATT_OP_MTU_RSP && len >= 3) {
		att->mtu = get16(p + 1);
		if (att->mtu > ATT_MAX_MTU)
			att->mtu = ATT_MAX_MTU;
		if (att->mtu < ATT_DEFAULT_MTU)
			att->mtu = ATT_DEFAULT_MTU;
	}
	if (r->cb != NULL) {
		if (op == ATT_OP_ERROR_RSP)
			r->cb(r->arg, p[4], NULL, 0);
		else
			r->cb(r->arg, 0, p + 1, len - 1);
	}
	free(r);
	if (c->att == att)
		att_kick(att);
}

/*
 * We serve no attributes; peers that look anyway get the matching
 * error, and a larger MTU if they ask for one.
 */
static void
att_server(struct att *att, const uint8_t *p, size_t len)
{
	uint8_t		 rsp[3];
	uint16_t	 mtu;

	switch (p[0]) {
	case ATT_OP_MTU_REQ:
		if (len < 3)
			return;
		mtu = get16(p + 1);
		rsp[0] = ATT_OP_MTU_RSP;
		put16(rsp + 1, ATT_MAX_MTU);
		l2cap_send_fixed(att->conn, L2CAP_CID_ATT, rsp, sizeof(rsp));
		if (mtu > ATT_MAX_MTU)
			mtu = ATT_MAX_MTU;
		if (mtu >= ATT_DEFAULT_MTU)
			att->mtu = mtu;
		break;
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_READ_BY_GROUP_REQ:
		att_error_rsp(att, p[0], len >= 3 ? get16(p + 1) : 0,
		    ATT_ERR_NOT_FOUND);
		break;
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_WRITE_REQ:
		att_error_rsp(att, p[0], len >= 3 ? get16(p + 1) : 0,
		    ATT_ERR_INVALID_HANDLE);
		break;
	case ATT_OP_CONFIRM:
		break;
	default:
		if (!(p[0] & ATT_OP_COMMAND) && (p[0] & 1) == 0 &&
		    p[0] != ATT_OP_CONFIRM)
			att_error_rsp(att, p[0], 0, ATT_ERR_NOT_SUPPORTED);
		break;
	}
}
