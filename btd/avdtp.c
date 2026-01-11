/*
 * Copyright (c) 2025-2026 Murilo Ijanc <murilo@ijanc.org>
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

#define	AVDTP_DISCOVER			0x01
#define	AVDTP_GET_CAPABILITIES		0x02
#define	AVDTP_SET_CONFIGURATION		0x03
#define	AVDTP_GET_CONFIGURATION		0x04
#define	AVDTP_RECONFIGURE		0x05
#define	AVDTP_OPEN			0x06
#define	AVDTP_START			0x07
#define	AVDTP_CLOSE			0x08
#define	AVDTP_SUSPEND			0x09
#define	AVDTP_ABORT			0x0a
#define	AVDTP_SECURITY_CONTROL		0x0b
#define	AVDTP_GET_ALL_CAPABILITIES	0x0c
#define	AVDTP_DELAYREPORT		0x0d

#define	AVDTP_MSG_COMMAND		0
#define	AVDTP_MSG_GENERAL_REJECT	1
#define	AVDTP_MSG_ACCEPT		2
#define	AVDTP_MSG_REJECT		3

#define	AVDTP_CAT_MEDIA_TRANSPORT	0x01
#define	AVDTP_CAT_MEDIA_CODEC		0x07

#define	AVDTP_ERR_BAD_ACP_SEID		0x12
#define	AVDTP_ERR_SEP_IN_USE		0x13
#define	AVDTP_ERR_NOT_SUPPORTED		0x19
#define	AVDTP_ERR_BAD_STATE		0x31
#define	AVDTP_ERR_BAD_CONFIG		0x29

#define	A2DP_CODEC_SBC			0x00
#define	A2DP_LOCAL_SEID			1
#define	A2DP_TSEP_SNK			1
#define	A2DP_MAX_BITPOOL		53
#define	A2DP_MIN_BITPOOL		2
#define	A2DP_TIMEOUT			5
#define	A2DP_STATS			10
#define	A2DP_MAXSEPS			16

#define	SBC_RATE_16000			0x80
#define	SBC_RATE_32000			0x40
#define	SBC_RATE_44100			0x20
#define	SBC_RATE_48000			0x10
#define	SBC_CM_STEREO			0x02
#define	SBC_BL_16			0x10
#define	SBC_SB_8			0x04
#define	SBC_AM_SNR			0x02
#define	SBC_AM_LOUDNESS			0x01

enum a2dp_state {
	A2DP_S_SDP,
	A2DP_S_SIGNAL,
	A2DP_S_DISCOVER,
	A2DP_S_GETCAP,
	A2DP_S_SETCONF,
	A2DP_S_OPEN,
	A2DP_S_MEDIA,
	A2DP_S_START,
	A2DP_S_STREAMING,
	A2DP_S_SUSPENDED,
	A2DP_S_PEER
};

struct a2dp {
	struct device		*dev;
	enum a2dp_state		 state;
	int			 version;
	struct l2cap_chan	*sig;
	struct l2cap_chan	*media;
	struct event		 timer;
	struct event		 stats;
	uint8_t			 label;
	uint8_t			 pending;
	uint8_t			 seps[A2DP_MAXSEPS];
	int			 nseps;
	int			 sepi;
	uint8_t			 acp_seid;
	uint8_t			 caps[4];
	int			 configured;
	struct audio_params	 params;
};

static struct a2dp	*a2dp_get(struct device *);
static void		 a2dp_fail(struct a2dp *, const char *);
static void		 a2dp_sdp(struct device *, int);
static void		 a2dp_command(struct a2dp *, uint8_t, const uint8_t *,
			    size_t);
static void		 a2dp_reply(struct a2dp *, uint8_t, uint8_t, uint8_t,
			    const uint8_t *, size_t);
static void		 a2dp_timeout(int, short, void *);
static void		 a2dp_stats(int, short, void *);
static void		 a2dp_discover(struct a2dp *);
static void		 a2dp_getcap(struct a2dp *);
static void		 a2dp_response(struct a2dp *, uint8_t, uint8_t,
			    const uint8_t *, size_t);
static int		 a2dp_choose(struct a2dp *, const uint8_t *, size_t);
static int		 a2dp_parse_config(struct a2dp *, const uint8_t *,
			    size_t);
static void		 a2dp_set_config(struct a2dp *);
static void		 a2dp_streaming(struct a2dp *);
static void		 a2dp_stop(struct a2dp *);
static void		 a2dp_info(struct a2dp *);
static size_t		 a2dp_local_caps(uint8_t *);
static size_t		 a2dp_config_caps(struct a2dp *, uint8_t *);
static void		 a2dp_peer_command(struct a2dp *, uint8_t, uint8_t,
			    const uint8_t *, size_t);
static void		*avdtp_accept(struct hci_conn *);
static void		 avdtp_open(struct l2cap_chan *);
static void		 avdtp_input(struct l2cap_chan *, const uint8_t *,
			    size_t);
static void		 avdtp_close(struct l2cap_chan *);

static const struct l2cap_proto avdtp_proto = {
	L2CAP_PSM_AVDTP, avdtp_accept, avdtp_open, avdtp_input, avdtp_close
};

void
avdtp_init(void)
{
	l2cap_register(&avdtp_proto);
}

static struct a2dp *
a2dp_get(struct device *dev)
{
	struct a2dp	*a;

	if (dev->proto != NULL)
		return (dev->proto);
	if ((a = calloc(1, sizeof(*a))) == NULL)
		fatal(NULL);
	a->dev = dev;
	a->state = A2DP_S_SDP;
	evtimer_set(&a->timer, a2dp_timeout, a);
	evtimer_set(&a->stats, a2dp_stats, a);
	dev->proto = a;
	return (a);
}

void
a2dp_start(struct device *dev)
{
	struct a2dp	*a = a2dp_get(dev);

	if (a->state == A2DP_S_PEER)
		return;
	a->state = A2DP_S_SDP;
	sdp_query_avdtp(dev, a2dp_sdp);
}

void
a2dp_down(struct device *dev)
{
	struct a2dp	*a = dev->proto;

	if (a == NULL)
		return;
	a2dp_stop(a);
	avrcp_down(dev);
	evtimer_del(&a->timer);
	evtimer_del(&a->stats);
	if (a->sig != NULL)
		a->sig->arg = NULL;
	if (a->media != NULL)
		a->media->arg = NULL;
	free(a);
	dev->proto = NULL;
}

static void
a2dp_fail(struct a2dp *a, const char *why)
{
	log_warnx("%s: %s", bdaddr_ntoa(&a->dev->addr), why);
	if (a->dev->conn != NULL)
		hci_disconnect(a->dev->conn, HCI_ERR_REMOTE_USER);
}

static void
a2dp_sdp(struct device *dev, int version)
{
	struct a2dp	*a = dev->proto;

	if (a == NULL || dev->conn == NULL)
		return;
	if (version == -1) {
		a2dp_fail(a, "no A2DP sink service");
		return;
	}
	a->version = version;
	log_debug("%s: AVDTP %u.%u", bdaddr_ntoa(&dev->addr), version >> 8,
	    version & 0xff);
	if (a->sig != NULL && a->sig->state == L2CAP_S_OPEN) {
		if (a->state == A2DP_S_SDP)
			a2dp_discover(a);
		return;
	}
	a->state = A2DP_S_SIGNAL;
	a->sig = l2cap_connect(dev->conn, L2CAP_PSM_AVDTP, &avdtp_proto, a);
}

static void
a2dp_timeout(int fd, short event, void *arg)
{
	struct a2dp	*a = arg;

	a2dp_fail(a, "AVDTP signalling timeout");
}

static void
a2dp_command(struct a2dp *a, uint8_t signal, const uint8_t *p, size_t len)
{
	struct timeval	 tv = { A2DP_TIMEOUT, 0 };
	uint8_t		 buf[64];

	if (a->sig == NULL || 2 + len > sizeof(buf))
		return;
	a->label = (a->label + 1) & 0x0f;
	a->pending = signal;
	buf[0] = a->label << 4 | AVDTP_MSG_COMMAND;
	buf[1] = signal;
	memcpy(buf + 2, p, len);
	l2cap_send(a->sig, buf, 2 + len);
	evtimer_add(&a->timer, &tv);
}

static void
a2dp_reply(struct a2dp *a, uint8_t label, uint8_t type, uint8_t signal,
    const uint8_t *p, size_t len)
{
	uint8_t	 buf[64];

	if (a->sig == NULL || 2 + len > sizeof(buf))
		return;
	buf[0] = label << 4 | type;
	buf[1] = signal;
	memcpy(buf + 2, p, len);
	l2cap_send(a->sig, buf, 2 + len);
}

static void
a2dp_discover(struct a2dp *a)
{
	a->state = A2DP_S_DISCOVER;
	a->nseps = 0;
	a2dp_command(a, AVDTP_DISCOVER, NULL, 0);
}

static void
a2dp_getcap(struct a2dp *a)
{
	uint8_t	 p[1];

	if (a->sepi >= a->nseps) {
		if (a->acp_seid == 0) {
			a2dp_fail(a, "no SBC sink");
			return;
		}
		a2dp_set_config(a);
		return;
	}
	a->state = A2DP_S_GETCAP;
	p[0] = a->seps[a->sepi++] << 2;
	a2dp_command(a, a->version >= 0x0103 ? AVDTP_GET_ALL_CAPABILITIES :
	    AVDTP_GET_CAPABILITIES, p, 1);
}

static int
a2dp_choose(struct a2dp *a, const uint8_t *p, size_t len)
{
	size_t	 off;

	for (off = 0; off + 2 <= len; off += 2 + p[off + 1]) {
		if (off + 2 + p[off + 1] > len)
			return (0);
		if (p[off] != AVDTP_CAT_MEDIA_CODEC || p[off + 1] < 6)
			continue;
		if ((p[off + 2] >> 4) != 0 || p[off + 3] != A2DP_CODEC_SBC)
			continue;
		memcpy(a->caps, p + off + 4, 4);
		return (1);
	}
	return (0);
}

static void
a2dp_set_config(struct a2dp *a)
{
	struct headset_conf	*hs = &a->dev->hs;
	struct audio_params	*par = &a->params;
	uint8_t			 p[16];
	int			 rate, bitpool;

	log_debug("%s: sink seid %u SBC %02x%02x, bitpool %u-%u",
	    bdaddr_ntoa(&a->dev->addr), a->acp_seid, a->caps[0], a->caps[1],
	    a->caps[2], a->caps[3]);
	rate = hs->rate;
	if (rate == 48000 && !(a->caps[0] & SBC_RATE_48000))
		rate = 44100;
	if ((rate == 44100 && !(a->caps[0] & SBC_RATE_44100)) ||
	    !(a->caps[0] & SBC_CM_STEREO) || !(a->caps[1] & SBC_BL_16) ||
	    !(a->caps[1] & SBC_SB_8) || !(a->caps[1] & SBC_AM_LOUDNESS)) {
		a2dp_fail(a, "sink lacks a supported SBC configuration");
		return;
	}
	bitpool = hs->bitpool;
	if (bitpool > a->caps[3])
		bitpool = a->caps[3];
	if (bitpool < a->caps[2] || bitpool < A2DP_MIN_BITPOOL) {
		a2dp_fail(a, "no usable bitpool");
		return;
	}
	memset(par, 0, sizeof(*par));
	par->rate = rate;
	par->channels = 2;
	par->mode = SBC_MODE_STEREO;
	par->blocks = 16;
	par->subbands = 8;
	par->alloc = SBC_ALLOC_LOUDNESS;
	par->bitpool = bitpool;

	p[0] = a->acp_seid << 2;
	p[1] = A2DP_LOCAL_SEID << 2;
	a->state = A2DP_S_SETCONF;
	a2dp_command(a, AVDTP_SET_CONFIGURATION, p,
	    2 + a2dp_config_caps(a, p + 2));
}

static size_t
a2dp_config_caps(struct a2dp *a, uint8_t *p)
{
	struct audio_params	*par = &a->params;

	p[0] = AVDTP_CAT_MEDIA_TRANSPORT;
	p[1] = 0;
	p[2] = AVDTP_CAT_MEDIA_CODEC;
	p[3] = 6;
	p[4] = 0x00;
	p[5] = A2DP_CODEC_SBC;
	p[6] = (par->rate == 48000 ? SBC_RATE_48000 : SBC_RATE_44100) |
	    SBC_CM_STEREO;
	p[7] = SBC_BL_16 | SBC_SB_8 | (par->alloc == SBC_ALLOC_SNR ?
	    SBC_AM_SNR : SBC_AM_LOUDNESS);
	p[8] = a->caps[2] > A2DP_MIN_BITPOOL ? a->caps[2] : A2DP_MIN_BITPOOL;
	p[9] = par->bitpool;
	return (10);
}

static size_t
a2dp_local_caps(uint8_t *p)
{
	p[0] = AVDTP_CAT_MEDIA_TRANSPORT;
	p[1] = 0;
	p[2] = AVDTP_CAT_MEDIA_CODEC;
	p[3] = 6;
	p[4] = 0x00;
	p[5] = A2DP_CODEC_SBC;
	p[6] = SBC_RATE_44100 | SBC_RATE_48000 | SBC_CM_STEREO;
	p[7] = SBC_BL_16 | SBC_SB_8 | SBC_AM_SNR | SBC_AM_LOUDNESS;
	p[8] = A2DP_MIN_BITPOOL;
	p[9] = A2DP_MAX_BITPOOL;
	return (10);
}

static int
a2dp_parse_config(struct a2dp *a, const uint8_t *p, size_t len)
{
	struct audio_params	*par = &a->params;
	size_t			 off;
	const uint8_t		*c = NULL;

	for (off = 0; off + 2 <= len; off += 2 + p[off + 1]) {
		if (off + 2 + p[off + 1] > len)
			return (-1);
		if (p[off] == AVDTP_CAT_MEDIA_CODEC && p[off + 1] >= 6 &&
		    p[off + 3] == A2DP_CODEC_SBC)
			c = p + off + 4;
	}
	if (c == NULL || c[0] & ~(SBC_RATE_44100 | SBC_RATE_48000 |
	    SBC_CM_STEREO) || (c[0] & 0x0f) != SBC_CM_STEREO ||
	    c[1] != (SBC_BL_16 | SBC_SB_8 | (c[1] & 0x03)) ||
	    (c[1] & 0x03) == 0 || (c[1] & 0x03) == 0x03 ||
	    c[3] < A2DP_MIN_BITPOOL)
		return (-1);
	memset(par, 0, sizeof(*par));
	par->rate = c[0] & SBC_RATE_48000 ? 48000 : 44100;
	par->channels = 2;
	par->mode = SBC_MODE_STEREO;
	par->blocks = 16;
	par->subbands = 8;
	par->alloc = c[1] & SBC_AM_SNR ? SBC_ALLOC_SNR : SBC_ALLOC_LOUDNESS;
	par->bitpool = c[3] > A2DP_MAX_BITPOOL ? A2DP_MAX_BITPOOL : c[3];
	memcpy(a->caps, c, 4);
	return (0);
}

static void
a2dp_response(struct a2dp *a, uint8_t type, uint8_t signal, const uint8_t *p,
    size_t len)
{
	size_t	 i;
	uint8_t	 seid[1];

	if (signal != a->pending)
		return;
	evtimer_del(&a->timer);
	a->pending = 0;
	if (type != AVDTP_MSG_ACCEPT) {
		log_warnx("%s: AVDTP signal 0x%02x rejected: 0x%02x",
		    bdaddr_ntoa(&a->dev->addr), signal,
		    len > 0 ? p[len - 1] : 0);
		if (signal == AVDTP_GET_CAPABILITIES ||
		    signal == AVDTP_GET_ALL_CAPABILITIES) {
			a2dp_getcap(a);
			return;
		}
		a2dp_fail(a, "stream setup failed");
		return;
	}

	switch (signal) {
	case AVDTP_DISCOVER:
		for (i = 0; i + 2 <= len; i += 2) {
			if (p[i] & 0x02)
				continue;
			if ((p[i + 1] >> 4) != 0 ||
			    ((p[i + 1] >> 3) & 1) != A2DP_TSEP_SNK)
				continue;
			if (a->nseps < A2DP_MAXSEPS)
				a->seps[a->nseps++] = p[i] >> 2;
		}
		a->sepi = 0;
		a->acp_seid = 0;
		a2dp_getcap(a);
		break;
	case AVDTP_GET_CAPABILITIES:
	case AVDTP_GET_ALL_CAPABILITIES:
		if (a->acp_seid == 0 && a2dp_choose(a, p, len))
			a->acp_seid = a->seps[a->sepi - 1];
		a2dp_getcap(a);
		break;
	case AVDTP_SET_CONFIGURATION:
		a->configured = 1;
		a->state = A2DP_S_OPEN;
		seid[0] = a->acp_seid << 2;
		a2dp_command(a, AVDTP_OPEN, seid, 1);
		break;
	case AVDTP_OPEN:
		a->state = A2DP_S_MEDIA;
		a->media = l2cap_connect(a->dev->conn, L2CAP_PSM_AVDTP,
		    &avdtp_proto, a);
		break;
	case AVDTP_START:
		a2dp_streaming(a);
		break;
	case AVDTP_SUSPEND:
	case AVDTP_CLOSE:
	case AVDTP_ABORT:
		break;
	}
}

static void
a2dp_streaming(struct a2dp *a)
{
	struct timeval	 tv = { A2DP_STATS, 0 };

	if (a->media == NULL || a->media->state != L2CAP_S_OPEN)
		return;
	a->state = A2DP_S_STREAMING;
	rtp_start(a->media, &a->params);
	engine_imsg_compose_frontend(IMSG_AUDIO_START, 0, &a->params,
	    sizeof(a->params));
	a2dp_info(a);
	log_info("%s: %s", bdaddr_ntoa(&a->dev->addr), a->dev->info);
	device_state(a->dev, DEV_READY);
	evtimer_add(&a->stats, &tv);
	avrcp_start(a->dev);
}

static void
a2dp_stop(struct a2dp *a)
{
	if (a->state != A2DP_S_STREAMING)
		return;
	rtp_stop();
	engine_imsg_compose_frontend(IMSG_AUDIO_STOP, 0, NULL, 0);
	evtimer_del(&a->stats);
}

static void
a2dp_peer_command(struct a2dp *a, uint8_t label, uint8_t signal,
    const uint8_t *p, size_t len)
{
	uint8_t	 rsp[32];
	size_t	 n;

	switch (signal) {
	case AVDTP_DISCOVER:
		rsp[0] = A2DP_LOCAL_SEID << 2 | (a->configured ? 0x02 : 0);
		rsp[1] = 0x00;
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, rsp, 2);
		return;
	case AVDTP_GET_CAPABILITIES:
	case AVDTP_GET_ALL_CAPABILITIES:
		if (len < 1 || (p[0] >> 2) != A2DP_LOCAL_SEID)
			break;
		n = a2dp_local_caps(rsp);
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, rsp, n);
		return;
	case AVDTP_SET_CONFIGURATION:
		if (len < 2 || (p[0] >> 2) != A2DP_LOCAL_SEID)
			break;
		if (a->configured) {
			rsp[0] = 0;
			rsp[1] = AVDTP_ERR_SEP_IN_USE;
			a2dp_reply(a, label, AVDTP_MSG_REJECT, signal, rsp, 2);
			return;
		}
		if (a2dp_parse_config(a, p + 2, len - 2) == -1) {
			rsp[0] = AVDTP_CAT_MEDIA_CODEC;
			rsp[1] = AVDTP_ERR_BAD_CONFIG;
			a2dp_reply(a, label, AVDTP_MSG_REJECT, signal, rsp, 2);
			return;
		}
		a->configured = 1;
		a->acp_seid = p[1] >> 2;
		a->state = A2DP_S_PEER;
		evtimer_del(&a->timer);
		log_debug("%s: configured by peer, %d Hz, bitpool %d",
		    bdaddr_ntoa(&a->dev->addr), a->params.rate,
		    a->params.bitpool);
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, NULL, 0);
		return;
	case AVDTP_GET_CONFIGURATION:
		if (!a->configured)
			break;
		n = a2dp_config_caps(a, rsp);
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, rsp, n);
		return;
	case AVDTP_OPEN:
		if (!a->configured)
			break;
		a->state = A2DP_S_PEER;
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, NULL, 0);
		return;
	case AVDTP_START:
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, NULL, 0);
		if (a->state != A2DP_S_STREAMING)
			a2dp_streaming(a);
		return;
	case AVDTP_SUSPEND:
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, NULL, 0);
		if (a->state == A2DP_S_STREAMING) {
			a2dp_stop(a);
			a->state = A2DP_S_SUSPENDED;
			a2dp_info(a);
			log_info("%s: suspended by peer",
			    bdaddr_ntoa(&a->dev->addr));
		}
		return;
	case AVDTP_CLOSE:
	case AVDTP_ABORT:
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, NULL, 0);
		a2dp_stop(a);
		a->configured = 0;
		a->state = A2DP_S_PEER;
		return;
	case AVDTP_DELAYREPORT:
		a2dp_reply(a, label, AVDTP_MSG_ACCEPT, signal, NULL, 0);
		return;
	case AVDTP_RECONFIGURE:
	case AVDTP_SECURITY_CONTROL:
		rsp[0] = AVDTP_ERR_NOT_SUPPORTED;
		a2dp_reply(a, label, AVDTP_MSG_REJECT, signal, rsp, 1);
		return;
	default:
		a2dp_reply(a, label, AVDTP_MSG_GENERAL_REJECT, signal, NULL,
		    0);
		return;
	}
	rsp[0] = AVDTP_ERR_BAD_ACP_SEID;
	a2dp_reply(a, label, AVDTP_MSG_REJECT, signal, rsp, 1);
}

static void *
avdtp_accept(struct hci_conn *c)
{
	struct a2dp	*a;

	if (c->dev == NULL || c->dev->kind != DEV_HEADSET ||
	    c->dev->state < DEV_SETUP)
		return (NULL);
	a = a2dp_get(c->dev);
	if (a->sig != NULL && a->media != NULL)
		return (NULL);
	return (a);
}

static void
avdtp_open(struct l2cap_chan *ch)
{
	struct a2dp	*a = ch->arg;
	uint8_t		 seid[1];

	if (a == NULL)
		return;
	if (a->sig == NULL)
		a->sig = ch;
	else if (a->sig != ch && a->media == NULL)
		a->media = ch;

	if (ch == a->sig) {
		if (a->state == A2DP_S_SIGNAL)
			a2dp_discover(a);
		return;
	}
	if (ch != a->media)
		return;
	if (a->state == A2DP_S_MEDIA || a->state == A2DP_S_PEER) {
		a->state = A2DP_S_START;
		seid[0] = a->acp_seid << 2;
		a2dp_command(a, AVDTP_START, seid, 1);
	}
}

static void
avdtp_input(struct l2cap_chan *ch, const uint8_t *p, size_t len)
{
	struct a2dp	*a = ch->arg;
	uint8_t		 label, type;

	if (a == NULL || ch != a->sig || len < 2)
		return;
	if (((p[0] >> 2) & 3) != 0) {
		log_debug("%s: fragmented AVDTP message ignored",
		    bdaddr_ntoa(&a->dev->addr));
		return;
	}
	label = p[0] >> 4;
	type = p[0] & 3;
	if (type == AVDTP_MSG_COMMAND)
		a2dp_peer_command(a, label, p[1] & 0x3f, p + 2, len - 2);
	else if (label == a->label)
		a2dp_response(a, type, p[1] & 0x3f, p + 2, len - 2);
}

static void
avdtp_close(struct l2cap_chan *ch)
{
	struct a2dp	*a = ch->arg;

	if (a == NULL)
		return;
	if (ch == a->media) {
		a->media = NULL;
		a2dp_stop(a);
		a->state = A2DP_S_PEER;
		a->configured = 0;
	} else if (ch == a->sig) {
		a->sig = NULL;
		a2dp_fail(a, "AVDTP signalling channel closed");
	}
}
