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

#define	UUID_PRIMARY_SERVICE	0x2800
#define	UUID_CHARACTERISTIC	0x2803
#define	UUID_CCCD		0x2902
#define	UUID_REPORT_REFERENCE	0x2908
#define	UUID_HID_SERVICE	0x1812
#define	UUID_REPORT_MAP		0x2a4b
#define	UUID_REPORT		0x2a4d

#define	HOGP_MAXCHARS		32
#define	HOGP_MAXREPORTS		16
#define	HOGP_MAXMAP		4096

#define	REPORT_INPUT		1

struct hogp_char {
	uint16_t		 decl;
	uint16_t		 value;
	uint16_t		 uuid;
};

struct hogp_report {
	uint16_t		 value;
	uint16_t		 ref;
	uint16_t		 cccd;
	uint8_t			 id;
	uint8_t			 type;
};

struct hogp {
	struct device		*dev;
	struct att		*att;
	uint16_t		 start;
	uint16_t		 end;
	struct hogp_char	 chars[HOGP_MAXCHARS];
	int			 nchars;
	struct hogp_report	 reports[HOGP_MAXREPORTS];
	int			 nreports;
	int			 idx;
	uint16_t		 map_handle;
	uint8_t			*map;
	size_t			 maplen;
	struct hid		*hid;
	int			 ready;
};

static void	 hogp_fail(struct hogp *, const char *);
static void	 hogp_find_service(struct hogp *);
static void	 hogp_service(void *, uint8_t, const uint8_t *, size_t);
static void	 hogp_find_chars(struct hogp *, uint16_t);
static void	 hogp_chars(void *, uint8_t, const uint8_t *, size_t);
static void	 hogp_find_descs(struct hogp *, uint16_t);
static void	 hogp_descs(void *, uint8_t, const uint8_t *, size_t);
static void	 hogp_next_report(struct hogp *);
static void	 hogp_read_map(struct hogp *);
static void	 hogp_map(void *, uint8_t, const uint8_t *, size_t);
static void	 hogp_read_refs(struct hogp *);
static void	 hogp_ref(void *, uint8_t, const uint8_t *, size_t);
static void	 hogp_subscribe(struct hogp *);
static void	 hogp_subscribed(void *, uint8_t, const uint8_t *, size_t);
static void	 hogp_ready(struct hogp *);
static void	 hogp_notify(void *, uint16_t, const uint8_t *, size_t);

void
hogp_start(struct device *dev)
{
	struct hogp	*hogp;

	if ((hogp = calloc(1, sizeof(*hogp))) == NULL)
		fatal(NULL);
	hogp->dev = dev;
	hogp->att = dev->conn->att;
	dev->proto = hogp;
	att_set_notify(hogp->att, hogp_notify, hogp);
	hogp_find_service(hogp);
}

void
hogp_down(struct device *dev)
{
	struct hogp	*hogp = dev->proto;

	if (hogp == NULL)
		return;
	if (hogp->att != NULL)
		att_set_notify(hogp->att, NULL, NULL);
	if (hogp->hid != NULL) {
		hid_reset(hogp->hid);
		hid_free(hogp->hid);
	}
	free(hogp->map);
	free(hogp);
	dev->proto = NULL;
}

static void
hogp_fail(struct hogp *hogp, const char *why)
{
	log_warnx("%s: %s", bdaddr_ntoa(&hogp->dev->addr), why);
	hci_disconnect(hogp->dev->conn, HCI_ERR_REMOTE_USER);
}

static void
hogp_find_service(struct hogp *hogp)
{
	uint8_t	 p[9];

	p[0] = ATT_OP_FIND_BY_TYPE_REQ;
	put16(p + 1, 0x0001);
	put16(p + 3, 0xffff);
	put16(p + 5, UUID_PRIMARY_SERVICE);
	put16(p + 7, UUID_HID_SERVICE);
	att_request(hogp->att, p, sizeof(p), hogp_service, hogp);
}

static void
hogp_service(void *arg, uint8_t err, const uint8_t *p, size_t len)
{
	struct hogp	*hogp = arg;

	if (err != 0 || len < 4) {
		hogp_fail(hogp, "no HID service");
		return;
	}
	hogp->start = get16(p);
	hogp->end = get16(p + 2);
	log_debug("%s: HID service 0x%04x-0x%04x",
	    bdaddr_ntoa(&hogp->dev->addr), hogp->start, hogp->end);
	hogp_find_chars(hogp, hogp->start);
}

static void
hogp_find_chars(struct hogp *hogp, uint16_t start)
{
	uint8_t	 p[7];

	p[0] = ATT_OP_READ_BY_TYPE_REQ;
	put16(p + 1, start);
	put16(p + 3, hogp->end);
	put16(p + 5, UUID_CHARACTERISTIC);
	att_request(hogp->att, p, sizeof(p), hogp_chars, hogp);
}

static void
hogp_chars(void *arg, uint8_t err, const uint8_t *p, size_t len)
{
	struct hogp		*hogp = arg;
	struct hogp_char	*ch;
	size_t			 ilen, off;
	uint16_t		 last = 0;

	if (err == ATT_ERR_NOT_FOUND)
		goto done;
	if (err != 0 || len < 1 || (ilen = p[0]) < 7) {
		hogp_fail(hogp, "characteristic discovery failed");
		return;
	}
	for (off = 1; off + ilen <= len; off += ilen) {
		last = get16(p + off);
		if (hogp->nchars == HOGP_MAXCHARS)
			continue;
		ch = &hogp->chars[hogp->nchars++];
		ch->decl = last;
		ch->value = get16(p + off + 3);
		ch->uuid = ilen == 7 ? get16(p + off + 5) : 0;
	}
	if (last != 0 && last < hogp->end) {
		hogp_find_chars(hogp, last + 1);
		return;
	}
 done:
	hogp->idx = -1;
	hogp_next_report(hogp);
}

static void
hogp_next_report(struct hogp *hogp)
{
	struct hogp_char	*ch;
	uint16_t		 end;

	while (++hogp->idx < hogp->nchars) {
		ch = &hogp->chars[hogp->idx];
		if (ch->uuid == UUID_REPORT_MAP)
			hogp->map_handle = ch->value;
		if (ch->uuid != UUID_REPORT ||
		    hogp->nreports == HOGP_MAXREPORTS)
			continue;
		hogp->reports[hogp->nreports++].value = ch->value;
		end = hogp->idx + 1 < hogp->nchars ?
		    hogp->chars[hogp->idx + 1].decl - 1 : hogp->end;
		if (ch->value < end) {
			hogp_find_descs(hogp, ch->value + 1);
			return;
		}
	}
	hogp_read_map(hogp);
}

static void
hogp_find_descs(struct hogp *hogp, uint16_t start)
{
	uint8_t		 p[5];
	uint16_t	 end;

	end = hogp->idx + 1 < hogp->nchars ?
	    hogp->chars[hogp->idx + 1].decl - 1 : hogp->end;
	p[0] = ATT_OP_FIND_INFO_REQ;
	put16(p + 1, start);
	put16(p + 3, end);
	att_request(hogp->att, p, sizeof(p), hogp_descs, hogp);
}

static void
hogp_descs(void *arg, uint8_t err, const uint8_t *p, size_t len)
{
	struct hogp		*hogp = arg;
	struct hogp_report	*r = &hogp->reports[hogp->nreports - 1];
	size_t			 ilen, off;
	uint16_t		 h = 0, end;

	if (err != 0 || len < 1) {
		hogp_next_report(hogp);
		return;
	}
	ilen = p[0] == 1 ? 4 : 18;
	for (off = 1; off + ilen <= len; off += ilen) {
		h = get16(p + off);
		if (ilen != 4)
			continue;
		if (get16(p + off + 2) == UUID_REPORT_REFERENCE)
			r->ref = h;
		else if (get16(p + off + 2) == UUID_CCCD)
			r->cccd = h;
	}
	end = hogp->idx + 1 < hogp->nchars ?
	    hogp->chars[hogp->idx + 1].decl - 1 : hogp->end;
	if (h != 0 && h < end) {
		hogp_find_descs(hogp, h + 1);
		return;
	}
	hogp_next_report(hogp);
}

static void
hogp_read_map(struct hogp *hogp)
{
	uint8_t	 p[5];

	if (hogp->map_handle == 0) {
		hogp_fail(hogp, "no report map");
		return;
	}
	if (hogp->maplen == 0) {
		p[0] = ATT_OP_READ_REQ;
		put16(p + 1, hogp->map_handle);
		att_request(hogp->att, p, 3, hogp_map, hogp);
	} else {
		p[0] = ATT_OP_READ_BLOB_REQ;
		put16(p + 1, hogp->map_handle);
		put16(p + 3, hogp->maplen);
		att_request(hogp->att, p, 5, hogp_map, hogp);
	}
}

static void
hogp_map(void *arg, uint8_t err, const uint8_t *p, size_t len)
{
	struct hogp	*hogp = arg;
	uint8_t		*nmap;

	if (err == ATT_ERR_INVALID_OFFSET && hogp->maplen > 0)
		len = 0;
	else if (err != 0) {
		hogp_fail(hogp, "cannot read report map");
		return;
	}
	if (len > 0) {
		if (hogp->maplen + len > HOGP_MAXMAP) {
			hogp_fail(hogp, "report map too long");
			return;
		}
		if ((nmap = realloc(hogp->map, hogp->maplen + len)) == NULL)
			fatal(NULL);
		hogp->map = nmap;
		memcpy(hogp->map + hogp->maplen, p, len);
		hogp->maplen += len;
	}
	if (len == (size_t)att_mtu(hogp->att) - 1) {
		hogp_read_map(hogp);
		return;
	}
	log_debug("%s: report map %zu bytes", bdaddr_ntoa(&hogp->dev->addr),
	    hogp->maplen);
	hogp->idx = -1;
	hogp_read_refs(hogp);
}

static void
hogp_read_refs(struct hogp *hogp)
{
	uint8_t	 p[3];

	while (++hogp->idx < hogp->nreports) {
		if (hogp->reports[hogp->idx].ref == 0)
			continue;
		p[0] = ATT_OP_READ_REQ;
		put16(p + 1, hogp->reports[hogp->idx].ref);
		att_request(hogp->att, p, sizeof(p), hogp_ref, hogp);
		return;
	}
	if ((hogp->hid = hid_new(hogp->map, hogp->maplen,
	    engine_state.kbdtype)) == NULL) {
		hogp_fail(hogp, "cannot parse report map");
		return;
	}
	hogp->idx = -1;
	hogp_subscribe(hogp);
}

static void
hogp_ref(void *arg, uint8_t err, const uint8_t *p, size_t len)
{
	struct hogp		*hogp = arg;
	struct hogp_report	*r = &hogp->reports[hogp->idx];

	if (err == 0 && len >= 2) {
		r->id = p[0];
		r->type = p[1];
		log_debug("%s: report handle 0x%04x id %u type %u",
		    bdaddr_ntoa(&hogp->dev->addr), r->value, r->id, r->type);
	}
	hogp_read_refs(hogp);
}

static void
hogp_subscribe(struct hogp *hogp)
{
	struct hogp_report	*r;
	uint8_t			 p[5];

	while (++hogp->idx < hogp->nreports) {
		r = &hogp->reports[hogp->idx];
		if (r->type != REPORT_INPUT || r->cccd == 0)
			continue;
		p[0] = ATT_OP_WRITE_REQ;
		put16(p + 1, r->cccd);
		put16(p + 3, 0x0001);
		att_request(hogp->att, p, sizeof(p), hogp_subscribed, hogp);
		return;
	}
	hogp_ready(hogp);
}

static void
hogp_subscribed(void *arg, uint8_t err, const uint8_t *p, size_t len)
{
	struct hogp	*hogp = arg;

	if (err != 0)
		log_warnx("%s: cannot subscribe to report %u: 0x%02x",
		    bdaddr_ntoa(&hogp->dev->addr),
		    hogp->reports[hogp->idx].id, err);
	hogp_subscribe(hogp);
}

static void
hogp_ready(struct hogp *hogp)
{
	struct device	*dev = hogp->dev;
	int		 i, n = 0;

	for (i = 0; i < hogp->nreports; i++)
		if (hogp->reports[i].type == REPORT_INPUT)
			n++;
	hogp->ready = 1;
	snprintf(dev->info, sizeof(dev->info), "%d input report%s, %s", n,
	    n == 1 ? "" : "s", hid_describe(hogp->hid));
	log_info("%s: ready, %s", bdaddr_ntoa(&dev->addr), dev->info);
	device_state(dev, DEV_READY);
}

static void
hogp_notify(void *arg, uint16_t handle, const uint8_t *p, size_t len)
{
	struct hogp	*hogp = arg;
	int		 i;

	if (hogp == NULL || !hogp->ready)
		return;
	for (i = 0; i < hogp->nreports; i++) {
		if (hogp->reports[i].value != handle)
			continue;
		if (log_getverbose() > 2)
			log_debug("%s: report %u, %zu bytes",
			    bdaddr_ntoa(&hogp->dev->addr),
			    hogp->reports[i].id, len);
		hid_report(hogp->hid, hogp->reports[i].id, p, len);
		return;
	}
}
