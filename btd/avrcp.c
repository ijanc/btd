/*
 * Copyright (c) 2026 Murilo Ijanc <murilo@ijanc.org>
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
#include <sys/time.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "btd.h"

#define	AVCTP_PID		0x110e
#define	AVCTP_RESPONSE		0x02
#define	AVCTP_IPID		0x01

#define	AVC_CONTROL		0x00
#define	AVC_STATUS		0x01
#define	AVC_NOTIFY		0x03
#define	AVC_NOT_IMPLEMENTED	0x08
#define	AVC_ACCEPTED		0x09
#define	AVC_REJECTED		0x0a
#define	AVC_STABLE		0x0c
#define	AVC_CHANGED		0x0d
#define	AVC_INTERIM		0x0f

#define	AVC_PANEL		0x48
#define	AVC_OP_VENDOR		0x00
#define	AVC_OP_UNIT_INFO	0x30
#define	AVC_OP_SUBUNIT_INFO	0x31
#define	AVC_OP_PASS_THROUGH	0x7c

#define	AVRCP_GET_CAPABILITIES	0x10
#define	AVRCP_REGISTER_NOTIFY	0x31
#define	AVRCP_SET_ABS_VOLUME	0x50
#define	AVRCP_CAP_COMPANY	0x02
#define	AVRCP_CAP_EVENTS	0x03
#define	AVRCP_EVENT_VOLUME	0x0d
#define	AVRCP_ERR_INVALID_CMD	0x00

#define	AVRCP_MAX_VOLUME	127
#define	AVRCP_OPEN_WAIT		2000
#define	AVRCP_SETTLE		100
#define	AVRCP_ECHO		500

struct avrcp {
	struct device		*dev;
	struct l2cap_chan	*chan;
	struct event		 open_timer;
	struct event		 settle_timer;
	uint8_t			 label;
	int			 started;
	int			 absolute;
	int			 volume;
	int			 sent;
	struct timespec		 echo_until;
};

static struct avrcp	*avrcp_get(struct device *);
static void		 avrcp_open_timeout(int, short, void *);
static void		 avrcp_settle(int, short, void *);
static void		 avrcp_send(struct avrcp *, uint8_t, uint8_t,
			    const uint8_t *, size_t);
static void		 avrcp_reply(struct avrcp *, uint8_t, const uint8_t *,
			    size_t);
static void		 avrcp_set_volume(struct avrcp *);
static void		 avrcp_register(struct avrcp *);
static void		 avrcp_response(struct avrcp *, const uint8_t *,
			    size_t);
static void		 avrcp_command(struct avrcp *, uint8_t,
			    const uint8_t *, size_t);
static void		*avctp_accept(struct hci_conn *);
static void		 avctp_open(struct l2cap_chan *);
static void		 avctp_input(struct l2cap_chan *, const uint8_t *,
			    size_t);
static void		 avctp_close(struct l2cap_chan *);

static const struct l2cap_proto avctp_proto = {
	L2CAP_PSM_AVCTP, avctp_accept, avctp_open, avctp_input, avctp_close
};

static struct avrcp	*avrcp_session;
static int		 local_volume = AVRCP_MAX_VOLUME;

void
avrcp_init(void)
{
	l2cap_register(&avctp_proto);
}

static struct avrcp *
avrcp_get(struct device *dev)
{
	struct avrcp	*av;

	if (avrcp_session != NULL && avrcp_session->dev == dev)
		return (avrcp_session);
	if (avrcp_session != NULL)
		avrcp_down(avrcp_session->dev);
	if ((av = calloc(1, sizeof(*av))) == NULL)
		fatal(NULL);
	av->dev = dev;
	av->volume = -1;
	av->sent = -1;
	evtimer_set(&av->open_timer, avrcp_open_timeout, av);
	evtimer_set(&av->settle_timer, avrcp_settle, av);
	avrcp_session = av;
	return (av);
}

void
avrcp_start(struct device *dev)
{
	struct avrcp	*av = avrcp_get(dev);
	struct timeval	 tv = { AVRCP_OPEN_WAIT / 1000, 0 };
	uint8_t		 p[1];

	if (av->started)
		return;
	av->started = 1;
	if (av->chan == NULL) {
		evtimer_add(&av->open_timer, &tv);
		return;
	}
	if (av->chan->state != L2CAP_S_OPEN)
		return;
	p[0] = AVRCP_CAP_EVENTS;
	avrcp_send(av, AVC_STATUS, AVRCP_GET_CAPABILITIES, p, 1);
}

void
avrcp_down(struct device *dev)
{
	struct avrcp	*av = avrcp_session;

	if (av == NULL || av->dev != dev)
		return;
	evtimer_del(&av->open_timer);
	evtimer_del(&av->settle_timer);
	if (av->chan != NULL)
		av->chan->arg = NULL;
	free(av);
	avrcp_session = NULL;
}

int
avrcp_volume(struct device *dev)
{
	struct avrcp	*av = avrcp_session;

	if (av == NULL || av->dev != dev || !av->absolute)
		return (-1);
	return (av->volume);
}

static void
avrcp_open_timeout(int fd, short event, void *arg)
{
	struct avrcp	*av = arg;

	if (av->chan != NULL || av->dev->conn == NULL)
		return;
	av->chan = l2cap_connect(av->dev->conn, L2CAP_PSM_AVCTP, &avctp_proto,
	    av);
}

static void
avrcp_send(struct avrcp *av, uint8_t ctype, uint8_t pdu, const uint8_t *p,
    size_t len)
{
	uint8_t	 buf[32];

	if (av->chan == NULL || 13 + len > sizeof(buf))
		return;
	av->label = (av->label + 1) & 0x0f;
	buf[0] = av->label << 4;
	buf[1] = AVCTP_PID >> 8;
	buf[2] = AVCTP_PID & 0xff;
	buf[3] = ctype;
	buf[4] = AVC_PANEL;
	buf[5] = AVC_OP_VENDOR;
	buf[6] = 0x00;
	buf[7] = 0x19;
	buf[8] = 0x58;
	buf[9] = pdu;
	buf[10] = 0;
	buf[11] = len >> 8;
	buf[12] = len;
	memcpy(buf + 13, p, len);
	l2cap_send(av->chan, buf, 13 + len);
}

static void
avrcp_set_volume(struct avrcp *av)
{
	uint8_t	 v;

	if (!av->absolute || local_volume == av->volume)
		return;
	av->volume = local_volume;
	v = local_volume;
	avrcp_send(av, AVC_CONTROL, AVRCP_SET_ABS_VOLUME, &v, 1);
}

static void
avrcp_register(struct avrcp *av)
{
	uint8_t	 p[5];

	p[0] = AVRCP_EVENT_VOLUME;
	memset(p + 1, 0, 4);
	avrcp_send(av, AVC_NOTIFY, AVRCP_REGISTER_NOTIFY, p, sizeof(p));
}

void
avrcp_local_volume(int volume)
{
	struct avrcp	*av = avrcp_session;
	struct timeval	 tv = { 0, AVRCP_SETTLE * 1000 };
	struct timespec	 now;

	if (volume < 0 || volume > AVRCP_MAX_VOLUME)
		return;
	if (volume != local_volume)
		log_debug("local volume %d", volume);
	local_volume = volume;
	if (av == NULL || !av->absolute)
		return;
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (timespeccmp(&now, &av->echo_until, <))
		return;
	evtimer_del(&av->settle_timer);
	evtimer_add(&av->settle_timer, &tv);
}

static void
avrcp_settle(int fd, short event, void *arg)
{
	avrcp_set_volume(arg);
}

static void
avrcp_response(struct avrcp *av, const uint8_t *p, size_t len)
{
	struct timespec	 now, echo = { 0, AVRCP_ECHO * 1000000L };
	const uint8_t	*par;
	size_t		 plen, i;
	uint8_t		 rtype, pdu;
	int		 v;

	if (len < 10 || p[2] != AVC_OP_VENDOR)
		return;
	rtype = p[0] & 0x0f;
	pdu = p[6];
	plen = p[8] << 8 | p[9];
	if (10 + plen > len)
		return;
	par = p + 10;

	switch (pdu) {
	case AVRCP_GET_CAPABILITIES:
		if (rtype != AVC_STABLE || plen < 2 ||
		    par[0] != AVRCP_CAP_EVENTS)
			break;
		for (i = 0; i < par[1] && 2 + i < plen; i++)
			if (par[2 + i] == AVRCP_EVENT_VOLUME)
				av->absolute = 1;
		if (!av->absolute) {
			log_info("%s: no absolute volume",
			    bdaddr_ntoa(&av->dev->addr));
			break;
		}
		avrcp_set_volume(av);
		avrcp_register(av);
		break;
	case AVRCP_SET_ABS_VOLUME:
		if (rtype != AVC_ACCEPTED || plen < 1)
			break;
		av->volume = par[0] & 0x7f;
		log_info("%s: volume %d", bdaddr_ntoa(&av->dev->addr),
		    av->volume);
		a2dp_info_update(av->dev);
		break;
	case AVRCP_REGISTER_NOTIFY:
		if (plen < 2 || par[0] != AVRCP_EVENT_VOLUME)
			break;
		if (rtype != AVC_INTERIM && rtype != AVC_CHANGED)
			break;
		v = par[1] & 0x7f;
		if (rtype == AVC_CHANGED)
			avrcp_register(av);
		if (v == av->volume)
			break;
		av->volume = v;
		clock_gettime(CLOCK_MONOTONIC, &now);
		timespecadd(&now, &echo, &av->echo_until);
		evtimer_del(&av->settle_timer);
		log_info("%s: headset volume %d", bdaddr_ntoa(&av->dev->addr),
		    v);
		engine_imsg_compose_frontend(IMSG_VOLUME_REMOTE, 0, &v,
		    sizeof(v));
		a2dp_info_update(av->dev);
		break;
	}
}

static void
avrcp_reply(struct avrcp *av, uint8_t label, const uint8_t *p, size_t len)
{
	uint8_t	 buf[64];

	if (av->chan == NULL || 3 + len > sizeof(buf))
		return;
	buf[0] = label << 4 | AVCTP_RESPONSE;
	buf[1] = AVCTP_PID >> 8;
	buf[2] = AVCTP_PID & 0xff;
	memcpy(buf + 3, p, len);
	l2cap_send(av->chan, buf, 3 + len);
}

static void
avrcp_command(struct avrcp *av, uint8_t label, const uint8_t *p, size_t len)
{
	uint8_t	 rsp[32];
	size_t	 n;

	if (len < 3 || len > sizeof(rsp))
		return;
	memcpy(rsp, p, len);
	n = len;
	switch (p[2]) {
	case AVC_OP_UNIT_INFO:
		rsp[0] = AVC_STABLE;
		if (n < 8)
			n = 8;
		rsp[3] = 0x07;
		rsp[4] = AVC_PANEL;
		rsp[5] = 0x00;
		rsp[6] = 0x19;
		rsp[7] = 0x58;
		break;
	case AVC_OP_SUBUNIT_INFO:
		rsp[0] = AVC_STABLE;
		if (n < 8)
			n = 8;
		rsp[3] = 0x07;
		rsp[4] = AVC_PANEL;
		memset(rsp + 5, 0xff, 3);
		break;
	case AVC_OP_PASS_THROUGH:
		rsp[0] = AVC_ACCEPTED;
		if (len >= 4)
			log_debug("%s: pass through 0x%02x",
			    bdaddr_ntoa(&av->dev->addr), p[3]);
		break;
	case AVC_OP_VENDOR:
		if (len >= 11 && p[6] == AVRCP_GET_CAPABILITIES &&
		    p[10] == AVRCP_CAP_COMPANY) {
			rsp[0] = AVC_STABLE;
			rsp[8] = 0;
			rsp[9] = 5;
			rsp[10] = AVRCP_CAP_COMPANY;
			rsp[11] = 1;
			rsp[12] = 0x00;
			rsp[13] = 0x19;
			rsp[14] = 0x58;
			n = 15;
		} else if (len >= 11 && p[6] == AVRCP_GET_CAPABILITIES) {
			rsp[0] = AVC_STABLE;
			rsp[8] = 0;
			rsp[9] = 2;
			rsp[10] = p[10];
			rsp[11] = 0;
			n = 12;
		} else if (len >= 10) {
			rsp[0] = AVC_REJECTED;
			rsp[8] = 0;
			rsp[9] = 1;
			rsp[10] = AVRCP_ERR_INVALID_CMD;
			n = 11;
		} else
			rsp[0] = AVC_NOT_IMPLEMENTED;
		break;
	default:
		rsp[0] = AVC_NOT_IMPLEMENTED;
		break;
	}
	avrcp_reply(av, label, rsp, n);
}

static void *
avctp_accept(struct hci_conn *c)
{
	struct avrcp	*av;

	if (c->dev == NULL || c->dev->kind != DEV_HEADSET ||
	    c->dev->state < DEV_SETUP)
		return (NULL);
	av = avrcp_get(c->dev);
	if (av->chan != NULL)
		return (NULL);
	return (av);
}

static void
avctp_open(struct l2cap_chan *ch)
{
	struct avrcp	*av = ch->arg;
	uint8_t		 p[1];

	if (av == NULL)
		return;
	av->chan = ch;
	evtimer_del(&av->open_timer);
	log_debug("%s: AVRCP channel open", bdaddr_ntoa(&av->dev->addr));
	if (!av->started)
		return;
	p[0] = AVRCP_CAP_EVENTS;
	avrcp_send(av, AVC_STATUS, AVRCP_GET_CAPABILITIES, p, 1);
}

static void
avctp_input(struct l2cap_chan *ch, const uint8_t *p, size_t len)
{
	struct avrcp	*av = ch->arg;
	uint8_t		 rsp[3];

	if (av == NULL || len < 3)
		return;
	if (((p[0] >> 2) & 3) != 0)
		return;
	if ((p[1] << 8 | p[2]) != AVCTP_PID) {
		if (p[0] & AVCTP_RESPONSE)
			return;
		rsp[0] = (p[0] & 0xf0) | AVCTP_RESPONSE | AVCTP_IPID;
		rsp[1] = p[1];
		rsp[2] = p[2];
		l2cap_send(ch, rsp, sizeof(rsp));
		return;
	}
	if (p[0] & AVCTP_RESPONSE)
		avrcp_response(av, p + 3, len - 3);
	else
		avrcp_command(av, p[0] >> 4, p + 3, len - 3);
}

static void
avctp_close(struct l2cap_chan *ch)
{
	struct avrcp	*av = ch->arg;

	if (av == NULL || av->chan != ch)
		return;
	av->chan = NULL;
	av->absolute = 0;
}
