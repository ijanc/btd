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

#define	SDP_ERROR_RSP		0x01
#define	SDP_SEARCH_REQ		0x02
#define	SDP_SEARCH_RSP		0x03
#define	SDP_ATTR_REQ		0x04
#define	SDP_ATTR_RSP		0x05
#define	SDP_SEARCH_ATTR_REQ	0x06
#define	SDP_SEARCH_ATTR_RSP	0x07

#define	SDP_ERR_BAD_HANDLE	0x0002
#define	SDP_ERR_BAD_SYNTAX	0x0003
#define	SDP_ERR_BAD_CONT	0x0005

#define	DE_UINT			1
#define	DE_UUID			3
#define	DE_SEQ			6

#define	UUID_AUDIO_SINK		0x110b
#define	UUID_AVDTP		0x0019
#define	ATTR_PROTOCOL_LIST	0x0004

#define	SDP_MAXUUIDS		12
#define	SDP_MAXCONT		16
#define	SDP_MAXRSP		2048

struct sdp_attr {
	uint16_t	 id;
	const uint8_t	*val;
	size_t		 len;
};

struct sdp_record {
	uint32_t		 handle;
	const struct sdp_attr	*attrs;
	size_t			 nattrs;
};

struct sdp_query {
	struct device	*dev;
	void		(*cb)(struct device *, int);
	uint8_t		 buf[SDP_MAXRSP];
	size_t		 len;
	uint16_t	 tid;
	int		 done;
};

#define	A(id, ...)	{ id, (const uint8_t []){ __VA_ARGS__ }, \
			    sizeof((const uint8_t []){ __VA_ARGS__ }) }

static const struct sdp_attr source_attrs[] = {
	A(0x0000, 0x0a, 0x00, 0x01, 0x00, 0x01),
	A(0x0001, 0x35, 0x03, 0x19, 0x11, 0x0a),
	A(0x0004, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x19,
	    0x35, 0x06, 0x19, 0x00, 0x19, 0x09, 0x01, 0x03),
	A(0x0005, 0x35, 0x03, 0x19, 0x10, 0x02),
	A(0x0009, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0d, 0x09, 0x01, 0x03),
};

static const struct sdp_attr controller_attrs[] = {
	A(0x0000, 0x0a, 0x00, 0x01, 0x00, 0x02),
	A(0x0001, 0x35, 0x06, 0x19, 0x11, 0x0e, 0x19, 0x11, 0x0f),
	A(0x0004, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x17,
	    0x35, 0x06, 0x19, 0x00, 0x17, 0x09, 0x01, 0x04),
	A(0x0005, 0x35, 0x03, 0x19, 0x10, 0x02),
	A(0x0009, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0e, 0x09, 0x01, 0x06),
	A(0x0311, 0x09, 0x00, 0x03),
};

static const struct sdp_attr target_attrs[] = {
	A(0x0000, 0x0a, 0x00, 0x01, 0x00, 0x03),
	A(0x0001, 0x35, 0x03, 0x19, 0x11, 0x0c),
	A(0x0004, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x17,
	    0x35, 0x06, 0x19, 0x00, 0x17, 0x09, 0x01, 0x04),
	A(0x0005, 0x35, 0x03, 0x19, 0x10, 0x02),
	A(0x0009, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0e, 0x09, 0x01, 0x06),
	A(0x0311, 0x09, 0x00, 0x01),
};

static const struct sdp_record records[] = {
	{ 0x00010001, source_attrs, nitems(source_attrs) },
	{ 0x00010002, controller_attrs, nitems(controller_attrs) },
	{ 0x00010003, target_attrs, nitems(target_attrs) },
};

static int	 de_header(const uint8_t *, size_t, int *, size_t *,
		    size_t *);
static int	 de_uuid(const uint8_t *, size_t, uint32_t *);
static int	 de_uuids(const uint8_t *, size_t, uint32_t *, int *);
static int	 record_has_uuid(const struct sdp_record *, uint32_t);
static int	 value_has_uuid(const uint8_t *, size_t, uint32_t);
static int	 attr_wanted(const uint8_t *, size_t, uint16_t);
static size_t	 record_attrs(const struct sdp_record *, const uint8_t *,
		    size_t, uint8_t *, size_t);
static void	 sdp_error(struct l2cap_chan *, uint16_t, uint16_t);
static void	 sdp_send(struct l2cap_chan *, uint8_t, uint16_t,
		    const uint8_t *, size_t, const uint8_t *, size_t, int);
static void	*sdp_accept(struct hci_conn *);
static void	 sdp_input(struct l2cap_chan *, const uint8_t *, size_t);
static void	 sdp_search(struct l2cap_chan *, uint16_t, const uint8_t *,
		    size_t);
static void	 sdp_attr(struct l2cap_chan *, uint16_t, uint8_t,
		    const uint8_t *, size_t);
static void	 sdpc_open(struct l2cap_chan *);
static void	 sdpc_request(struct l2cap_chan *, const uint8_t *, size_t);
static void	 sdpc_input(struct l2cap_chan *, const uint8_t *, size_t);
static void	 sdpc_close(struct l2cap_chan *);
static int	 sdpc_version(const uint8_t *, size_t);

static const struct l2cap_proto sdp_server = {
	L2CAP_PSM_SDP, sdp_accept, NULL, sdp_input, NULL
};

static const struct l2cap_proto sdp_client = {
	L2CAP_PSM_SDP, NULL, sdpc_open, sdpc_input, sdpc_close
};

void
sdp_init(void)
{
	l2cap_register(&sdp_server);
}

static int
de_header(const uint8_t *p, size_t len, int *type, size_t *hlen,
    size_t *dlen)
{
	int	 sz;

	if (len < 1)
		return (-1);
	*type = p[0] >> 3;
	sz = p[0] & 7;
	if (*type == 0) {
		*hlen = 1;
		*dlen = 0;
	} else if (sz < 5) {
		*hlen = 1;
		*dlen = 1 << sz;
	} else if (sz == 5) {
		if (len < 2)
			return (-1);
		*hlen = 2;
		*dlen = p[1];
	} else if (sz == 6) {
		if (len < 3)
			return (-1);
		*hlen = 3;
		*dlen = (size_t)p[1] << 8 | p[2];
	} else {
		if (len < 5)
			return (-1);
		*hlen = 5;
		*dlen = (size_t)p[1] << 24 | (size_t)p[2] << 16 |
		    (size_t)p[3] << 8 | p[4];
	}
	if (*dlen > len - *hlen)
		return (-1);
	return (0);
}

/* UUIDs on the Bluetooth base reduce to 32 bits, others never match. */
static int
de_uuid(const uint8_t *p, size_t len, uint32_t *uuid)
{
	static const uint8_t	 base[12] = { 0x00, 0x00, 0x10, 0x00, 0x80,
	    0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb };

	switch (len) {
	case 2:
		*uuid = p[0] << 8 | p[1];
		return (0);
	case 4:
		*uuid = (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
		return (0);
	case 16:
		if (memcmp(p + 4, base, sizeof(base)) != 0) {
			*uuid = 0xffffffff;
			return (0);
		}
		*uuid = (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
		return (0);
	}
	return (-1);
}

static int
de_uuids(const uint8_t *p, size_t len, uint32_t *uuids, int *n)
{
	size_t	 hlen, dlen, off, h, d;
	int	 type, t;

	if (de_header(p, len, &type, &hlen, &dlen) == -1 || type != DE_SEQ)
		return (-1);
	*n = 0;
	for (off = hlen; off < hlen + dlen; off += h + d) {
		if (de_header(p + off, hlen + dlen - off, &t, &h, &d) == -1 ||
		    t != DE_UUID || *n == SDP_MAXUUIDS)
			return (-1);
		if (de_uuid(p + off + h, d, &uuids[(*n)++]) == -1)
			return (-1);
	}
	return (*n > 0 ? 0 : -1);
}

static int
value_has_uuid(const uint8_t *p, size_t len, uint32_t uuid)
{
	size_t	 hlen, dlen, off = 0;
	uint32_t u;
	int	 type;

	while (off < len) {
		if (de_header(p + off, len - off, &type, &hlen, &dlen) == -1)
			return (0);
		if (type == DE_UUID && de_uuid(p + off + hlen, dlen, &u) == 0 &&
		    u == uuid)
			return (1);
		if ((type == DE_SEQ || type == 7) &&
		    value_has_uuid(p + off + hlen, dlen, uuid))
			return (1);
		off += hlen + dlen;
	}
	return (0);
}

static int
record_has_uuid(const struct sdp_record *r, uint32_t uuid)
{
	size_t	 i;

	for (i = 0; i < r->nattrs; i++)
		if (value_has_uuid(r->attrs[i].val, r->attrs[i].len, uuid))
			return (1);
	return (0);
}

static int
attr_wanted(const uint8_t *list, size_t len, uint16_t id)
{
	size_t	 hlen, dlen, off, h, d;
	int	 type, t;

	if (de_header(list, len, &type, &hlen, &dlen) == -1 || type != DE_SEQ)
		return (0);
	for (off = hlen; off < hlen + dlen; off += h + d) {
		if (de_header(list + off, hlen + dlen - off, &t, &h, &d) == -1 ||
		    t != DE_UINT)
			return (0);
		if (d == 2 && (list[off + 1] << 8 | list[off + 2]) == id)
			return (1);
		if (d == 4 && id >= (list[off + 1] << 8 | list[off + 2]) &&
		    id <= (list[off + 3] << 8 | list[off + 4]))
			return (1);
	}
	return (0);
}

static size_t
record_attrs(const struct sdp_record *r, const uint8_t *list, size_t llen,
    uint8_t *out, size_t outlen)
{
	size_t	 i, off = 3;

	for (i = 0; i < r->nattrs; i++) {
		if (!attr_wanted(list, llen, r->attrs[i].id))
			continue;
		if (off + 3 + r->attrs[i].len > outlen)
			break;
		out[off] = 0x09;
		out[off + 1] = r->attrs[i].id >> 8;
		out[off + 2] = r->attrs[i].id;
		memcpy(out + off + 3, r->attrs[i].val, r->attrs[i].len);
		off += 3 + r->attrs[i].len;
	}
	out[0] = 0x36;
	out[1] = (off - 3) >> 8;
	out[2] = off - 3;
	return (off);
}

static void *
sdp_accept(struct hci_conn *c)
{
	static int	 token;

	return (&token);
}

static void
sdp_error(struct l2cap_chan *ch, uint16_t tid, uint16_t err)
{
	uint8_t	 p[7];

	p[0] = SDP_ERROR_RSP;
	p[1] = tid >> 8;
	p[2] = tid;
	p[3] = 0;
	p[4] = 2;
	p[5] = err >> 8;
	p[6] = err;
	l2cap_send(ch, p, sizeof(p));
}

/*
 * Send what fits of a response, with the offset of the rest as
 * continuation state.
 */
static void
sdp_send(struct l2cap_chan *ch, uint8_t pdu, uint16_t tid, const uint8_t *hdr,
    size_t hlen, const uint8_t *body, size_t blen, int max)
{
	uint8_t	 p[SDP_MAXRSP + 32];
	size_t	 room, n, plen;

	room = ch->omtu - 5 - hlen - 2 - 3;
	if (max > 0 && (size_t)max < room)
		room = max;
	n = blen < room ? blen : room;
	plen = hlen + 2 + n + (n < blen ? 3 : 1);
	if (5 + plen > sizeof(p))
		return;
	p[0] = pdu;
	p[1] = tid >> 8;
	p[2] = tid;
	p[3] = plen >> 8;
	p[4] = plen;
	memcpy(p + 5, hdr, hlen);
	p[5 + hlen] = n >> 8;
	p[6 + hlen] = n;
	memcpy(p + 7 + hlen, body, n);
	if (n < blen) {
		p[7 + hlen + n] = 2;
		p[8 + hlen + n] = n >> 8;
		p[9 + hlen + n] = n;
	} else
		p[7 + hlen + n] = 0;
	l2cap_send(ch, p, 5 + plen);
}

static void
sdp_input(struct l2cap_chan *ch, const uint8_t *p, size_t len)
{
	uint16_t	 tid, plen;

	if (len < 5)
		return;
	tid = p[1] << 8 | p[2];
	plen = p[3] << 8 | p[4];
	if ((size_t)plen + 5 != len) {
		sdp_error(ch, tid, SDP_ERR_BAD_SYNTAX);
		return;
	}
	switch (p[0]) {
	case SDP_SEARCH_REQ:
		sdp_search(ch, tid, p + 5, plen);
		break;
	case SDP_ATTR_REQ:
	case SDP_SEARCH_ATTR_REQ:
		sdp_attr(ch, tid, p[0], p + 5, plen);
		break;
	default:
		sdp_error(ch, tid, SDP_ERR_BAD_SYNTAX);
		break;
	}
}

static void
sdp_search(struct l2cap_chan *ch, uint16_t tid, const uint8_t *p, size_t len)
{
	uint32_t	 uuids[SDP_MAXUUIDS];
	uint8_t		 rsp[10 + 4 * nitems(records)];
	size_t		 i, hlen, dlen, off;
	int		 n, j, type, max, cnt = 0;

	if (de_header(p, len, &type, &hlen, &dlen) == -1 ||
	    de_uuids(p, hlen + dlen, uuids, &n) == -1 ||
	    hlen + dlen + 2 > len) {
		sdp_error(ch, tid, SDP_ERR_BAD_SYNTAX);
		return;
	}
	max = p[hlen + dlen] << 8 | p[hlen + dlen + 1];
	off = 9;
	for (i = 0; i < nitems(records) && cnt < max; i++) {
		for (j = 0; j < n; j++)
			if (!record_has_uuid(&records[i], uuids[j]))
				break;
		if (j < n)
			continue;
		rsp[off++] = records[i].handle >> 24;
		rsp[off++] = records[i].handle >> 16;
		rsp[off++] = records[i].handle >> 8;
		rsp[off++] = records[i].handle;
		cnt++;
	}
	rsp[off] = 0;
	rsp[0] = SDP_SEARCH_RSP;
	rsp[1] = tid >> 8;
	rsp[2] = tid;
	rsp[3] = (off + 1 - 5) >> 8;
	rsp[4] = off + 1 - 5;
	rsp[5] = 0;
	rsp[6] = cnt;
	rsp[7] = 0;
	rsp[8] = cnt;
	l2cap_send(ch, rsp, off + 1);
}

static void
sdp_attr(struct l2cap_chan *ch, uint16_t tid, uint8_t pdu, const uint8_t *p,
    size_t len)
{
	uint32_t	 uuids[SDP_MAXUUIDS], handle;
	uint8_t		 body[SDP_MAXRSP], one[SDP_MAXRSP];
	const uint8_t	*list;
	size_t		 i, hlen, dlen, off, blen, llen, n1;
	int		 n = 0, j, type, max, cont = 0;

	off = 0;
	if (pdu == SDP_ATTR_REQ) {
		if (len < 4)
			goto bad;
		handle = (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
		off = 4;
	} else {
		if (de_header(p, len, &type, &hlen, &dlen) == -1 ||
		    de_uuids(p, hlen + dlen, uuids, &n) == -1)
			goto bad;
		off = hlen + dlen;
	}
	if (off + 2 > len)
		goto bad;
	max = p[off] << 8 | p[off + 1];
	off += 2;
	list = p + off;
	if (de_header(list, len - off, &type, &hlen, &dlen) == -1)
		goto bad;
	llen = hlen + dlen;
	off += llen;
	if (off >= len)
		goto bad;
	if (p[off] == 2 && off + 3 <= len)
		cont = p[off + 1] << 8 | p[off + 2];
	else if (p[off] != 0) {
		sdp_error(ch, tid, SDP_ERR_BAD_CONT);
		return;
	}

	if (pdu == SDP_ATTR_REQ) {
		for (i = 0; i < nitems(records); i++)
			if (records[i].handle == handle)
				break;
		if (i == nitems(records)) {
			sdp_error(ch, tid, SDP_ERR_BAD_HANDLE);
			return;
		}
		blen = record_attrs(&records[i], list, llen, body,
		    sizeof(body));
	} else {
		blen = 3;
		for (i = 0; i < nitems(records); i++) {
			for (j = 0; j < n; j++)
				if (!record_has_uuid(&records[i], uuids[j]))
					break;
			if (j < n)
				continue;
			n1 = record_attrs(&records[i], list, llen, one,
			    sizeof(one));
			if (blen + n1 > sizeof(body))
				break;
			memcpy(body + blen, one, n1);
			blen += n1;
		}
		body[0] = 0x36;
		body[1] = (blen - 3) >> 8;
		body[2] = blen - 3;
	}
	if ((size_t)cont > blen) {
		sdp_error(ch, tid, SDP_ERR_BAD_CONT);
		return;
	}
	sdp_send(ch, pdu + 1, tid, NULL, 0, body + cont, blen - cont, max);
	return;
 bad:
	sdp_error(ch, tid, SDP_ERR_BAD_SYNTAX);
}

void
sdp_query_avdtp(struct device *dev, void (*cb)(struct device *, int))
{
	struct sdp_query	*q;

	if ((q = calloc(1, sizeof(*q))) == NULL)
		fatal(NULL);
	q->dev = dev;
	q->cb = cb;
	l2cap_connect(dev->conn, L2CAP_PSM_SDP, &sdp_client, q);
}

static void
sdpc_request(struct l2cap_chan *ch, const uint8_t *cont, size_t clen)
{
	struct sdp_query	*q = ch->arg;
	uint8_t			 p[20 + SDP_MAXCONT];
	size_t			 len;

	q->tid++;
	p[0] = SDP_SEARCH_ATTR_REQ;
	p[1] = q->tid >> 8;
	p[2] = q->tid;
	len = 5;
	p[len++] = 0x35;
	p[len++] = 3;
	p[len++] = 0x19;
	p[len++] = UUID_AUDIO_SINK >> 8;
	p[len++] = UUID_AUDIO_SINK & 0xff;
	p[len++] = 0x04;
	p[len++] = 0x00;
	p[len++] = 0x35;
	p[len++] = 5;
	p[len++] = 0x0a;
	p[len++] = 0x00;
	p[len++] = 0x00;
	p[len++] = 0xff;
	p[len++] = 0xff;
	p[len++] = clen;
	memcpy(p + len, cont, clen);
	len += clen;
	p[3] = (len - 5) >> 8;
	p[4] = len - 5;
	l2cap_send(ch, p, len);
}

static void
sdpc_open(struct l2cap_chan *ch)
{
	sdpc_request(ch, NULL, 0);
}

static void
sdpc_input(struct l2cap_chan *ch, const uint8_t *p, size_t len)
{
	struct sdp_query	*q = ch->arg;
	size_t			 n, clen;

	if (len < 7 || p[0] != SDP_SEARCH_ATTR_RSP ||
	    (p[1] << 8 | p[2]) != q->tid) {
		l2cap_close(ch);
		return;
	}
	n = p[5] << 8 | p[6];
	if (7 + n + 1 > len) {
		l2cap_close(ch);
		return;
	}
	clen = p[7 + n];
	if (clen > SDP_MAXCONT || 7 + n + 1 + clen > len ||
	    q->len + n > sizeof(q->buf)) {
		l2cap_close(ch);
		return;
	}
	memcpy(q->buf + q->len, p + 7, n);
	q->len += n;
	if (clen > 0) {
		sdpc_request(ch, p + 8 + n, clen);
		return;
	}
	q->done = 1;
	l2cap_close(ch);
}

static void
sdpc_close(struct l2cap_chan *ch)
{
	struct sdp_query	*q = ch->arg;
	int			 version = -1;

	if (q->done)
		version = sdpc_version(q->buf, q->len);
	q->cb(q->dev, version);
	free(q);
}

/*
 * Walk the attribute lists for the protocol descriptor list and take
 * the version that follows the AVDTP UUID.
 */
static int
sdpc_version(const uint8_t *p, size_t len)
{
	size_t		 hlen, dlen, off, h, d, o2, h2, d2, o3, h3, d3;
	uint32_t	 uuid;
	uint16_t	 id;
	int		 type, t, t2, t3;

	if (de_header(p, len, &type, &hlen, &dlen) == -1 || type != DE_SEQ)
		return (-1);
	for (off = hlen; off < hlen + dlen; off += h + d) {
		if (de_header(p + off, hlen + dlen - off, &t, &h, &d) == -1 ||
		    t != DE_SEQ)
			return (-1);
		for (o2 = off + h; o2 + 3 <= off + h + d; ) {
			if (p[o2] != 0x09)
				break;
			id = p[o2 + 1] << 8 | p[o2 + 2];
			o2 += 3;
			if (de_header(p + o2, off + h + d - o2, &t2, &h2, &d2)
			    == -1)
				break;
			if (id == ATTR_PROTOCOL_LIST && t2 == DE_SEQ) {
				for (o3 = o2 + h2; o3 < o2 + h2 + d2;
				    o3 += h3 + d3) {
					if (de_header(p + o3, o2 + h2 + d2 - o3,
					    &t3, &h3, &d3) == -1 || t3 != DE_SEQ)
						break;
					if (d3 >= 6 && p[o3 + h3] == 0x19 &&
					    de_uuid(p + o3 + h3 + 1, 2, &uuid)
					    == 0 && uuid == UUID_AVDTP &&
					    p[o3 + h3 + 3] == 0x09)
						return (p[o3 + h3 + 4] << 8 |
						    p[o3 + h3 + 5]);
				}
			}
			o2 += h2 + d2;
		}
	}
	return (-1);
}
