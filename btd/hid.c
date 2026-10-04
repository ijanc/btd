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
#include <sys/time.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>
#include <dev/wscons/wsconsio.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <usbhid.h>

#include "log.h"
#include "btd.h"

#define	HID_PAGE_DESKTOP	0x01
#define	HID_PAGE_KEYBOARD	0x07
#define	HID_PAGE_LED		0x08
#define	HID_PAGE_BUTTON		0x09
#define	HID_PAGE_CONSUMER	0x0c

#define	HID_USAGE_X		0x30
#define	HID_USAGE_Y		0x31
#define	HID_USAGE_WHEEL		0x38
#define	HID_USAGE_AC_PAN	0x238

#define	HID_MOD_FIRST		0xe0
#define	HID_MAXFIELDS		128
#define	HID_MAXIDS		16
#define	HID_MAXBUTTONS		32
#define	HID_MAXLED		4
#define	HID_MAXREPORT		64

#define	NN			0

/* HID keyboard usage to XT scancode, extended keys with bit 7 set. */
static const uint8_t hid_xt[256] = {
	  NN,   NN,   NN,   NN, 0x1e, 0x30, 0x2e, 0x20,
	0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26,
	0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f, 0x14,
	0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c, 0x02, 0x03,
	0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x1c, 0x01, 0x0e, 0x0f, 0x39, 0x0c, 0x0d, 0x1a,
	0x1b, 0x2b, 0x2b, 0x27, 0x28, 0x29, 0x33, 0x34,
	0x35, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	0x41, 0x42, 0x43, 0x44, 0x57, 0x58, 0xb7, 0x46,
	0x7f, 0xd2, 0xc7, 0xc9, 0xd3, 0xcf, 0xd1, 0xcd,
	0xcb, 0xd0, 0xc8, 0x45, 0xb5, 0x37, 0x4a, 0x4e,
	0x9c, 0x4f, 0x50, 0x51, 0x4b, 0x4c, 0x4d, 0x47,
	0x48, 0x49, 0x52, 0x53, 0x56, 0xdd, 0xde, 0x59,
	0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
	0x6c, 0x6d, 0x6e, 0x76, 0x97,   NN, 0x93, 0x95,
	0x91, 0x92, 0x94, 0x9a, 0x96, 0x98, 0x99, 0xa0,
	0xb0, 0xae,   NN,   NN,   NN, 0x7e,   NN, 0x73,
	0x70, 0x7d, 0x79, 0x7b, 0x5c,   NN,   NN,   NN,
	  NN,   NN, 0x78, 0x77, 0x76,   NN,   NN,   NN,
	[0xe0] = 0x1d, 0x2a, 0x38, 0xdb, 0x9d, 0x36, 0xb8, 0xdc,
};

struct hid_field {
	int		 id;
	uint16_t	 page;
	uint16_t	 usage;
	uint16_t	 umin;
	int		 variable;
	hid_item_t	 item;
};

struct hid_state {
	int		 id;
	uint8_t		 keys[32];
	uint32_t	 buttons;
};

struct hid {
	struct hid_field	 fields[HID_MAXFIELDS];
	int			 nfields;
	struct hid_state	 state[HID_MAXIDS];
	int			 nstate;
	int			 xt;
	int			 kbd;
	int			 mouse;
	hid_item_t		 led[HID_MAXLED + 1];
	int			 ledmask;
	int			 ledid;
	int			 ledlen;
};

struct hid_events {
	struct wscons_event	 ev[BTD_MAXEVENTS];
	int			 n;
};

static struct hid_state	*hid_state(struct hid *, int);
static void		 hid_key(struct hid *, struct hid_events *, int, int);
static void		 hid_event(struct hid_events *, u_int, int);
static void		 hid_flush(int, struct hid_events *);
static int		 hid_fits(const hid_item_t *, size_t);

#define	KEY_SET(k, u)	((k)[(u) >> 3] |= 1 << ((u) & 7))
#define	KEY_ISSET(k, u)	((k)[(u) >> 3] & (1 << ((u) & 7)))

/*
 * The report map comes from the device: only keep items whose bits lie
 * within a report of len bytes.
 */
static int
hid_fits(const hid_item_t *item, size_t len)
{
	if (item->report_size < 1 || item->report_size > 32 ||
	    item->report_count < 0)
		return (0);
	return ((uint64_t)item->pos +
	    (uint64_t)item->report_size * item->report_count <= len * 8);
}

struct hid *
hid_new(uint8_t *map, size_t len, int kbdtype)
{
	struct hid		*hid;
	struct hid_field	*f;
	report_desc_t		 rd;
	hid_data_t		 hd;
	hid_item_t		 item;
	int			 u;

	if ((rd = hid_use_report_desc(map, len)) == NULL)
		return (NULL);
	if ((hid = calloc(1, sizeof(*hid))) == NULL)
		fatal(NULL);
	hid->xt = kbdtype != -1 && kbdtype != WSKBD_TYPE_USB;
	if ((hd = hid_start_parse(rd, 1 << hid_input, -1)) == NULL)
		fatal(NULL);
	while (hid_get_item(hd, &item) > 0) {
		if (item.kind != hid_input || (item.flags & HIO_CONST) ||
		    !hid_fits(&item, HID_MAXREPORT))
			continue;
		if (hid->nfields == HID_MAXFIELDS)
			break;
		f = &hid->fields[hid->nfields++];
		f->id = item.report_ID;
		f->item = item;
		f->variable = (item.flags & HIO_VARIABLE) != 0;
		if (f->variable) {
			f->page = HID_PAGE(item.usage);
			f->usage = HID_USAGE(item.usage);
		} else {
			f->page = HID_PAGE(item.usage_minimum);
			if (f->page == 0)
				f->page = HID_PAGE(item._usage_page);
			f->umin = HID_USAGE(item.usage_minimum);
		}
		if (f->page == HID_PAGE_KEYBOARD)
			hid->kbd = 1;
		else if (f->page == HID_PAGE_BUTTON && f->variable)
			hid->mouse = 1;
	}
	hid_end_parse(hd);

	if ((hd = hid_start_parse(rd, 1 << hid_output, -1)) == NULL)
		fatal(NULL);
	while (hid_get_item(hd, &item) > 0) {
		if (item.kind != hid_output || (item.flags & HIO_CONST) ||
		    !(item.flags & HIO_VARIABLE) ||
		    HID_PAGE(item.usage) != HID_PAGE_LED)
			continue;
		u = HID_USAGE(item.usage);
		if (u < 1 || u > HID_MAXLED)
			continue;
		if (hid->ledmask == 0) {
			hid->ledid = item.report_ID;
			hid->ledlen = hid_report_size(rd, hid_output,
			    item.report_ID);
		} else if (item.report_ID != hid->ledid)
			continue;
		if (item.report_size != 1 || hid->ledlen <= 0 ||
		    !hid_fits(&item, hid->ledlen))
			continue;
		hid->led[u] = item;
		hid->ledmask |= 1 << u;
	}
	hid_end_parse(hd);
	hid_dispose_report_desc(rd);
	return (hid);
}

void
hid_free(struct hid *hid)
{
	free(hid);
}

const char *
hid_describe(struct hid *hid)
{
	static char	 buf[64];

	snprintf(buf, sizeof(buf), "%s%s%s", hid->kbd ? (hid->xt ?
	    "keyboard (XT)" : "keyboard (USB)") : "",
	    hid->kbd && hid->mouse ? ", " : "", hid->mouse ? "mouse" : "");
	if (!hid->kbd && !hid->mouse)
		strlcpy(buf, "no keyboard or mouse", sizeof(buf));
	return (buf);
}

static struct hid_state *
hid_state(struct hid *hid, int id)
{
	int	 i;

	for (i = 0; i < hid->nstate; i++)
		if (hid->state[i].id == id)
			return (&hid->state[i]);
	if (hid->nstate == HID_MAXIDS)
		return (NULL);
	hid->state[hid->nstate].id = id;
	return (&hid->state[hid->nstate++]);
}

static void
hid_event(struct hid_events *e, u_int type, int value)
{
	if (e->n == BTD_MAXEVENTS)
		return;
	memset(&e->ev[e->n], 0, sizeof(e->ev[0]));
	e->ev[e->n].type = type;
	e->ev[e->n].value = value;
	e->n++;
}

static void
hid_flush(int type, struct hid_events *e)
{
	if (e->n == 0)
		return;
	engine_imsg_compose_bus(type, e->ev, e->n * sizeof(e->ev[0]));
	e->n = 0;
}

static void
hid_key(struct hid *hid, struct hid_events *e, int usage, int down)
{
	int	 code = usage;

	if (hid->xt)
		code = usage < 256 ? hid_xt[usage] : 0;
	if (code == 0)
		return;
	hid_event(e, down ? WSCONS_EVENT_KEY_DOWN : WSCONS_EVENT_KEY_UP, code);
}

void
hid_report(struct hid *hid, uint8_t id, const uint8_t *data, size_t len)
{
	struct hid_field	*f;
	struct hid_state	*st;
	struct hid_events	 e;
	hid_item_t		 item;
	uint8_t			 buf[HID_MAXREPORT + 1], keys[32];
	uint32_t		 buttons = 0, b;
	int32_t			 v, dx = 0, dy = 0, dz = 0, dw = 0;
	int			 i, j, u, is_kbd = 0, is_mouse = 0, found = 0;

	memset(buf, 0, sizeof(buf));
	memcpy(buf, data, len < HID_MAXREPORT ? len : HID_MAXREPORT);
	memset(keys, 0, sizeof(keys));

	for (i = 0; i < hid->nfields; i++) {
		f = &hid->fields[i];
		if (f->id != id)
			continue;
		found = 1;
		item = f->item;
		switch (f->page) {
		case HID_PAGE_KEYBOARD:
			is_kbd = 1;
			if (f->variable) {
				if (hid_get_data(buf, &item) != 0 &&
				    f->usage < 256)
					KEY_SET(keys, f->usage);
				break;
			}
			for (j = 0; j < item.report_count; j++) {
				v = hid_get_data(buf, &item);
				item.pos += item.report_size;
				if (v <= 0)
					continue;
				u = f->umin + v - item.logical_minimum;
				if (u >= 4 && u < 256)
					KEY_SET(keys, u);
			}
			break;
		case HID_PAGE_BUTTON:
			if (!f->variable)
				break;
			is_mouse = 1;
			if (f->usage >= 1 && f->usage <= HID_MAXBUTTONS &&
			    hid_get_data(buf, &item) != 0)
				buttons |= 1U << (f->usage - 1);
			break;
		case HID_PAGE_DESKTOP:
			if (!f->variable)
				break;
			v = hid_get_data(buf, &item);
			if (f->usage == HID_USAGE_X)
				dx = v;
			else if (f->usage == HID_USAGE_Y)
				dy = v;
			else if (f->usage == HID_USAGE_WHEEL)
				dz = v;
			break;
		case HID_PAGE_CONSUMER:
			if (f->variable && f->usage == HID_USAGE_AC_PAN)
				dw = hid_get_data(buf, &item);
			break;
		}
	}
	if (!found || (st = hid_state(hid, id)) == NULL)
		return;

	e.n = 0;
	if (is_kbd && hid->kbd) {
		for (u = 255; u >= 0; u--)
			if (u < HID_MOD_FIRST && KEY_ISSET(st->keys, u) &&
			    !KEY_ISSET(keys, u))
				hid_key(hid, &e, u, 0);
		for (u = 255; u >= HID_MOD_FIRST; u--)
			if (KEY_ISSET(st->keys, u) && !KEY_ISSET(keys, u))
				hid_key(hid, &e, u, 0);
		for (u = HID_MOD_FIRST; u < 256; u++)
			if (KEY_ISSET(keys, u) && !KEY_ISSET(st->keys, u))
				hid_key(hid, &e, u, 1);
		for (u = 0; u < HID_MOD_FIRST; u++)
			if (KEY_ISSET(keys, u) && !KEY_ISSET(st->keys, u))
				hid_key(hid, &e, u, 1);
		memcpy(st->keys, keys, sizeof(keys));
		hid_flush(IMSG_WSKBD, &e);
	}
	if (is_mouse && hid->mouse) {
		for (i = 0; i < HID_MAXBUTTONS; i++) {
			b = 1U << i;
			if ((buttons & b) && !(st->buttons & b))
				hid_event(&e, WSCONS_EVENT_MOUSE_DOWN, i);
		}
		for (i = 0; i < HID_MAXBUTTONS; i++) {
			b = 1U << i;
			if (!(buttons & b) && (st->buttons & b))
				hid_event(&e, WSCONS_EVENT_MOUSE_UP, i);
		}
		st->buttons = buttons;
		if (dx)
			hid_event(&e, WSCONS_EVENT_MOUSE_DELTA_X, dx);
		if (dy)
			hid_event(&e, WSCONS_EVENT_MOUSE_DELTA_Y, -dy);
		if (dz)
			hid_event(&e, WSCONS_EVENT_MOUSE_DELTA_Z, -dz);
		if (dw)
			hid_event(&e, WSCONS_EVENT_MOUSE_DELTA_W, -dw);
		hid_event(&e, WSCONS_EVENT_SYNC, 0);
		hid_flush(IMSG_WSMOUSE, &e);
	}
}

void
hid_reset(struct hid *hid)
{
	struct hid_events	 e;
	struct hid_state	*st;
	int			 i, u, n;

	e.n = 0;
	for (i = 0; i < hid->nstate; i++) {
		st = &hid->state[i];
		for (u = 0; u < 256; u++)
			if (KEY_ISSET(st->keys, u))
				hid_key(hid, &e, u, 0);
		memset(st->keys, 0, sizeof(st->keys));
	}
	hid_flush(IMSG_WSKBD, &e);
	for (i = 0, n = 0; i < hid->nstate; i++) {
		st = &hid->state[i];
		for (u = 0; u < HID_MAXBUTTONS; u++)
			if (st->buttons & (1U << u)) {
				hid_event(&e, WSCONS_EVENT_MOUSE_UP, u);
				n++;
			}
		st->buttons = 0;
	}
	if (n > 0) {
		hid_event(&e, WSCONS_EVENT_SYNC, 0);
		hid_flush(IMSG_WSMOUSE, &e);
	}
}

/* Build the output report that drives the keyboard LEDs. */
int
hid_leds(struct hid *hid, int leds, uint8_t *id, uint8_t *buf, size_t len)
{
	static const int	 wsled[HID_MAXLED + 1] = {
		0, WSKBD_LED_NUM, WSKBD_LED_CAPS, WSKBD_LED_SCROLL,
		WSKBD_LED_COMPOSE,
	};
	uint8_t			 out[HID_MAXREPORT + 1];
	int			 u;

	if (hid->ledmask == 0 || hid->ledlen == 0 ||
	    (size_t)hid->ledlen > len || hid->ledlen > HID_MAXREPORT)
		return (-1);
	/* hid_set_data touches the byte after the last bit. */
	memset(out, 0, sizeof(out));
	for (u = 1; u <= HID_MAXLED; u++)
		if (hid->ledmask & (1 << u))
			hid_set_data(out, &hid->led[u], (leds & wsled[u]) != 0);
	memcpy(buf, out, hid->ledlen);
	*id = hid->ledid;
	return (hid->ledlen);
}
