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
#include <string.h>

#include "log.h"
#include "btd.h"

#define	RTP_HEADER		12
#define	RTP_VERSION		0x80
#define	RTP_PAYLOAD_TYPE	96
#define	RTP_MAX_FRAMES		15
#define	RTP_MAX_PENDING		8
#define	RTP_MAXPKT		2048

struct rtp {
	struct l2cap_chan	*chan;
	uint16_t		 seq;
	uint32_t		 timestamp;
	uint32_t		 samples;
	uint8_t			 pkt[RTP_MAXPKT];
	size_t			 len;
	int			 frames;
	uint64_t		 sent;
	uint64_t		 dropped;
	uint64_t		 reported;
};

static void	 rtp_send(void);

static struct rtp	 rtp;

void
rtp_start(struct l2cap_chan *chan, const struct audio_params *par)
{
	memset(&rtp, 0, sizeof(rtp));
	rtp.chan = chan;
	rtp.samples = par->blocks * par->subbands;
	rtp.len = RTP_HEADER + 1;
}

void
rtp_stop(void)
{
	rtp.chan = NULL;
}

int
rtp_stats(uint64_t *sent, uint64_t *dropped)
{
	*sent = rtp.sent;
	*dropped = rtp.dropped;
	if (rtp.dropped == rtp.reported)
		return (0);
	rtp.reported = rtp.dropped;
	return (1);
}

/*
 * Frames go out as soon as the next one does not fit; sndiod is the
 * clock and the sink follows the timestamps.  With the controller
 * queue backed up, packets are dropped instead of adding latency.
 */
void
rtp_frame(const uint8_t *frame, size_t len)
{
	size_t	 room;

	if (rtp.chan == NULL || rtp.chan->state != L2CAP_S_OPEN)
		return;
	room = rtp.chan->omtu;
	if (room > sizeof(rtp.pkt))
		room = sizeof(rtp.pkt);
	if (RTP_HEADER + 1 + len > room)
		return;
	if (rtp.frames > 0 && (rtp.len + len > room ||
	    rtp.frames == RTP_MAX_FRAMES))
		rtp_send();
	memcpy(rtp.pkt + rtp.len, frame, len);
	rtp.len += len;
	rtp.frames++;
}

static void
rtp_send(void)
{
	uint8_t	*p = rtp.pkt;

	if (hci_acl_pending(LINK_BR) > RTP_MAX_PENDING)
		rtp.dropped++;
	else {
		p[0] = RTP_VERSION;
		p[1] = RTP_PAYLOAD_TYPE;
		p[2] = rtp.seq >> 8;
		p[3] = rtp.seq;
		p[4] = rtp.timestamp >> 24;
		p[5] = rtp.timestamp >> 16;
		p[6] = rtp.timestamp >> 8;
		p[7] = rtp.timestamp;
		memset(p + 8, 0, 4);
		p[12] = rtp.frames;
		if (l2cap_send(rtp.chan, p, rtp.len) == 0)
			rtp.sent++;
	}
	rtp.seq++;
	rtp.timestamp += rtp.frames * rtp.samples;
	rtp.len = RTP_HEADER + 1;
	rtp.frames = 0;
}
