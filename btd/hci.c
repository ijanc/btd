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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "btd.h"

#define	HCI_CMD_TIMEOUT		5
#define	HCI_RESET_TRIES		3
#define	HCI_EVBUF		4096
#define	HCI_ACLBUF		(4 + 4096)

struct hci_cmd {
	TAILQ_ENTRY(hci_cmd)	 entry;
	uint16_t		 op;
	uint8_t			 len;
	uint8_t			 p[255];
	hci_cb			 cb;
	void			*arg;
	int			 noreply;
};

struct hci_acl {
	TAILQ_ENTRY(hci_acl)	 entry;
	struct hci_conn		*conn;
	size_t			 len;
	uint8_t			 data[];
};

static void	 hci_trace(const char *, uint8_t, const uint8_t *, size_t);
static void	 hci_cmd_queue(uint16_t, const void *, size_t, hci_cb, void *,
		    int);
static void	 hci_cmd_kick(void);
static void	 hci_cmd_timeout(int, short, void *);
static void	 hci_cmd_done(uint16_t, uint8_t, const uint8_t *, size_t);
static void	 hci_event(const uint8_t *, size_t);
static void	 hci_le_event(const uint8_t *, size_t);
static void	 hci_acl_packet(const uint8_t *, size_t);
static void	 hci_acl_kick(void);
static void	 hci_completed(const uint8_t *, size_t);
static void	 hci_init_next(int);
static void	 hci_init_step(void *, uint8_t, const uint8_t *, size_t);
static void	 hci_init_done(void);
static void	 hci_conn_complete(const uint8_t *, size_t);
static void	 hci_le_conn_complete(const uint8_t *, size_t, int);
static void	 hci_disconn_complete(const uint8_t *, size_t);
static void	 hci_adv_report(const uint8_t *, size_t);
static void	 hci_ext_adv_report(const uint8_t *, size_t);
static void	 hci_scan_done(void *, uint8_t, const uint8_t *, size_t);

struct hci_state	 hci;

static TAILQ_HEAD(, hci_cmd)	 cmdq = TAILQ_HEAD_INITIALIZER(cmdq);
static TAILQ_HEAD(, hci_acl)	 aclq = TAILQ_HEAD_INITIALIZER(aclq);
struct hci_conn_list		 hci_conns = TAILQ_HEAD_INITIALIZER(hci_conns);
static struct hci_cmd		*cmd_cur;
static struct event		 cmd_timer, cmd_delay;
static int			 cmd_timer_init;
static uint8_t			 evbuf[HCI_EVBUF];
static size_t			 evlen;
static int			 ev_flush, in_event;
static uint8_t			 aclbuf[HCI_ACLBUF];
static size_t			 acllen;
static int			 ext_page;
static int			 reset_tries;

static void
hci_trace(const char *dir, uint8_t type, const uint8_t *p, size_t len)
{
	char	 buf[3 * 32 + 8];
	size_t	 i, off = 0;

	if (log_getverbose() < 3)
		return;
	for (i = 0; i < len && i < 32; i++)
		off += snprintf(buf + off, sizeof(buf) - off, " %02x", p[i]);
	log_debug("%s %02x:%s%s", dir, type, buf, len > 32 ? " ..." : "");
}

static void
hci_cmd_queue(uint16_t op, const void *p, size_t len, hci_cb cb, void *arg,
    int noreply)
{
	struct hci_cmd	*c;

	if (len > sizeof(c->p))
		fatalx("%s: command 0x%04x too long", __func__, op);
	if ((c = calloc(1, sizeof(*c))) == NULL)
		fatal(NULL);
	c->op = op;
	c->len = len;
	if (len > 0)
		memcpy(c->p, p, len);
	c->cb = cb;
	c->arg = arg;
	c->noreply = noreply;
	TAILQ_INSERT_TAIL(&cmdq, c, entry);
	hci_cmd_kick();
}

void
hci_cmd(uint16_t op, const void *p, size_t len, hci_cb cb, void *arg)
{
	hci_cmd_queue(op, p, len, cb, arg, 0);
}

/* Vendor commands that the controller never answers. */
void
hci_cmd_noreply(uint16_t op, const void *p, size_t len, int msec)
{
	hci_cmd_queue(op, p, len, NULL, NULL, msec);
}

static void
hci_cmd_kick(void)
{
	struct timeval	 tv = { HCI_CMD_TIMEOUT, 0 };
	struct hci_cmd	*c;
	uint8_t		 buf[3 + 255];

	if (!cmd_timer_init) {
		evtimer_set(&cmd_timer, hci_cmd_timeout, NULL);
		evtimer_set(&cmd_delay, hci_cmd_timeout, &cmd_delay);
		cmd_timer_init = 1;
	}
	if (cmd_cur != NULL || evtimer_pending(&cmd_delay, NULL) ||
	    (c = TAILQ_FIRST(&cmdq)) == NULL)
		return;
	TAILQ_REMOVE(&cmdq, c, entry);

	buf[0] = c->op & 0xff;
	buf[1] = c->op >> 8;
	buf[2] = c->len;
	memcpy(buf + 3, c->p, c->len);
	hci_trace(">", HCI_PKT_CMD, buf, 3 + c->len);
	if (c->op == HCI_CMD_RESET) {
		if (in_event)
			ev_flush = 1;
		else
			evlen = 0;
	}
	engine_imsg_compose_bus(IMSG_HCI_CMD, buf, 3 + c->len);

	if (c->noreply) {
		tv.tv_sec = c->noreply / 1000;
		tv.tv_usec = (c->noreply % 1000) * 1000;
		free(c);
		evtimer_add(&cmd_delay, &tv);
		return;
	}
	cmd_cur = c;
	evtimer_add(&cmd_timer, &tv);
}

static void
hci_cmd_timeout(int fd, short event, void *arg)
{
	struct hci_cmd	*c = cmd_cur;

	if (arg == NULL) {
		if (c == NULL)
			return;
		log_warnx("command 0x%04x timed out", c->op);
		cmd_cur = NULL;
		if (c->cb != NULL)
			c->cb(c->arg, HCI_ERR_TIMEOUT, NULL, 0);
		free(c);
	}
	hci_cmd_kick();
}

static void
hci_cmd_done(uint16_t op, uint8_t status, const uint8_t *rp, size_t rplen)
{
	struct hci_cmd	*c = cmd_cur;

	if (c == NULL || c->op != op) {
		if (op != 0)
			log_debug("unexpected completion of command 0x%04x",
			    op);
		return;
	}
	cmd_cur = NULL;
	evtimer_del(&cmd_timer);
	if (c->cb != NULL)
		c->cb(c->arg, status, rp, rplen);
	else if (status != 0)
		log_warnx("command 0x%04x failed: 0x%02x", op, status);
	free(c);
	hci_cmd_kick();
}

struct hci_evlen {
	uint8_t		 code;
	uint8_t		 len;
	uint8_t		 exact;
};

static const struct hci_evlen hci_evlens[] = {
	{ 0x03, 11, 1 }, { 0x04, 10, 1 }, { 0x05, 4, 1 }, { 0x06, 3, 1 },
	{ 0x07, 255, 1 }, { 0x08, 4, 1 }, { 0x0b, 11, 1 }, { 0x0c, 8, 1 },
	{ 0x0e, 3, 0 }, { 0x0f, 4, 1 }, { 0x10, 1, 1 }, { 0x12, 8, 1 },
	{ 0x13, 1, 0 }, { 0x14, 6, 1 }, { 0x16, 6, 1 }, { 0x17, 6, 1 },
	{ 0x18, 23, 1 }, { 0x1b, 3, 1 }, { 0x1d, 5, 1 }, { 0x20, 7, 1 },
	{ 0x23, 13, 1 }, { 0x2c, 17, 1 }, { 0x30, 3, 1 }, { 0x31, 6, 1 },
	{ 0x32, 9, 1 }, { 0x33, 10, 1 }, { 0x36, 7, 1 }, { 0x3d, 14, 1 },
	{ 0x3e, 1, 0 }, { 0x57, 2, 1 }, { 0xff, 0, 0 },
};

/*
 * The interrupt endpoint is a byte stream, and ugen(4) drops what does
 * not fit in its queue, so events are checked for a consistent layout
 * before they are trusted.
 */
static int
hci_event_valid(const uint8_t *ev, size_t len, int strict)
{
	const uint8_t	*p = ev + 2;
	size_t		 plen = ev[1], off, n, i;

	for (i = 0; i < nitems(hci_evlens); i++)
		if (hci_evlens[i].code == ev[0])
			break;
	if (i == nitems(hci_evlens))
		return (!strict && ev[0] != 0 && ev[0] < 0x60);
	if (plen < hci_evlens[i].len ||
	    (hci_evlens[i].exact && plen != hci_evlens[i].len))
		return (0);
	if (len < 2 + plen)
		return (1);

	switch (ev[0]) {
	case HCI_EVT_NUM_COMPLETED:
		return (plen == 1 + (size_t)p[0] * 4);
	case HCI_EVT_LE_META:
		switch (p[0]) {
		case HCI_LE_ADV_REPORT:
			if (plen < 2 || p[1] == 0)
				return (0);
			for (off = 2, n = 0; n < p[1]; n++) {
				if (off + 10 > plen)
					return (0);
				off += 10 + p[off + 8];
			}
			return (off == plen);
		case HCI_LE_EXT_ADV_REPORT:
			if (plen < 2 || p[1] == 0)
				return (0);
			for (off = 2, n = 0; n < p[1]; n++) {
				if (off + 24 > plen)
					return (0);
				off += 24 + p[off + 23];
			}
			return (off == plen);
		case HCI_LE_CONN_COMPLETE:
			return (plen == 19);
		case HCI_LE_CONN_UPDATE_COMPLETE:
			return (plen == 10);
		case HCI_LE_LTK_REQUEST:
			return (plen == 13);
		case HCI_LE_ENH_CONN_COMPLETE:
			return (plen == 31);
		default:
			return (p[0] != 0 && p[0] < 0x40);
		}
	}
	return (1);
}

static int
hci_event_chain(const uint8_t *p, size_t len)
{
	size_t	 off = 0, need;
	int	 n = 0;

	while (off + 2 <= len) {
		if (!hci_event_valid(p + off, len - off, 1))
			return (0);
		need = 2 + p[off + 1];
		if (off + need > len)
			break;
		off += need;
		n++;
	}
	return (n > 0);
}

static void
hci_event_resync(void)
{
	size_t	 k;

	for (k = 1; k + 2 <= evlen; k++)
		if (hci_event_chain(evbuf + k, evlen - k))
			break;
	if (k + 2 > evlen)
		k = evlen;
	log_warnx("lost event bytes, skipping %zu of %zu", k, evlen);
	memmove(evbuf, evbuf + k, evlen - k);
	evlen -= k;
}

void
hci_input_event(const uint8_t *p, size_t len)
{
	size_t	 need;

	if (evlen + len > sizeof(evbuf)) {
		log_warnx("event buffer overflow");
		evlen = 0;
		return;
	}
	memcpy(evbuf + evlen, p, len);
	evlen += len;

	while (evlen >= 2) {
		if (!hci_event_valid(evbuf, evlen, 0)) {
			hci_event_resync();
			continue;
		}
		if (evlen < (need = 2 + evbuf[1]))
			break;
		hci_trace("<", HCI_PKT_EVT, evbuf, need);
		ev_flush = 0;
		in_event = 1;
		hci_event(evbuf, need);
		in_event = 0;
		if (ev_flush) {
			ev_flush = 0;
			evlen = 0;
			break;
		}
		memmove(evbuf, evbuf + need, evlen - need);
		evlen -= need;
	}
}

void
hci_input_acl(const uint8_t *p, size_t len)
{
	size_t	 need;

	if (acllen + len > sizeof(aclbuf)) {
		log_warnx("acl buffer overflow, resynchronizing");
		acllen = 0;
		return;
	}
	memcpy(aclbuf + acllen, p, len);
	acllen += len;

	while (acllen >= 4 && acllen >= (need = 4 + get16(aclbuf + 2))) {
		hci_trace("<", HCI_PKT_ACL, aclbuf, need);
		hci_acl_packet(aclbuf, need);
		memmove(aclbuf, aclbuf + need, acllen - need);
		acllen -= need;
	}
}

static void
hci_event(const uint8_t *ev, size_t len)
{
	const uint8_t	*p = ev + 2;
	size_t		 plen = len - 2;

	switch (ev[0]) {
	case HCI_EVT_CMD_COMPLETE:
		if (plen < 3)
			break;
		hci.ncmd = p[0];
		if (plen < 4)
			hci_cmd_done(get16(p + 1), 0, NULL, 0);
		else
			hci_cmd_done(get16(p + 1), p[3], p + 4, plen - 4);
		break;
	case HCI_EVT_CMD_STATUS:
		if (plen < 4)
			break;
		hci.ncmd = p[1];
		hci_cmd_done(get16(p + 2), p[0], NULL, 0);
		break;
	case HCI_EVT_NUM_COMPLETED:
		hci_completed(p, plen);
		break;
	case HCI_EVT_CONN_COMPLETE:
		hci_conn_complete(p, plen);
		break;
	case HCI_EVT_DISCONN_COMPLETE:
		hci_disconn_complete(p, plen);
		break;
	case HCI_EVT_LE_META:
		hci_le_event(p, plen);
		break;
	case HCI_EVT_HW_ERROR:
		fatalx("controller hardware error 0x%02x",
		    plen > 0 ? p[0] : 0);
	default:
		engine_hci_event(ev[0], p, plen);
		break;
	}
}

static void
hci_le_event(const uint8_t *p, size_t len)
{
	if (len < 1)
		return;
	switch (p[0]) {
	case HCI_LE_CONN_COMPLETE:
		hci_le_conn_complete(p + 1, len - 1, 0);
		break;
	case HCI_LE_ENH_CONN_COMPLETE:
		hci_le_conn_complete(p + 1, len - 1, 1);
		break;
	case HCI_LE_ADV_REPORT:
		hci_adv_report(p + 1, len - 1);
		break;
	case HCI_LE_EXT_ADV_REPORT:
		hci_ext_adv_report(p + 1, len - 1);
		break;
	default:
		engine_le_event(p[0], p + 1, len - 1);
		break;
	}
}

struct hci_conn *
hci_conn_find(uint16_t handle)
{
	struct hci_conn	*c;

	TAILQ_FOREACH(c, &hci_conns, entry)
		if (c->handle == handle)
			return (c);
	return (NULL);
}

struct hci_conn *
hci_conn_find_addr(int link, const struct bdaddr *addr)
{
	struct hci_conn	*c;

	TAILQ_FOREACH(c, &hci_conns, entry)
		if (c->link == link && bdaddr_cmp(&c->peer, addr) == 0)
			return (c);
	return (NULL);
}

static struct hci_conn *
hci_conn_new(uint16_t handle, int link)
{
	struct hci_conn	*c;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		fatal(NULL);
	c->handle = handle;
	c->link = link;
	TAILQ_INIT(&c->chans);
	c->sig_ident = 1;
	c->next_cid = L2CAP_CID_DYN;
	TAILQ_INSERT_TAIL(&hci_conns, c, entry);
	return (c);
}

static void
hci_conn_complete(const uint8_t *p, size_t len)
{
	struct hci_conn	*c;
	struct bdaddr	 addr;
	uint8_t		 status;

	if (len < 11)
		return;
	status = p[0];
	memcpy(addr.b, p + 3, 6);
	if (status != 0) {
		engine_conn_failed(LINK_BR, &addr, status);
		return;
	}
	if (p[9] != 0x01)
		return;
	c = hci_conn_new(get16(p + 1) & 0x0fff, LINK_BR);
	c->peer = addr;
	c->peer_type = BDADDR_PUBLIC;
	c->encrypted = p[10];
	log_debug("%s: connection 0x%04x up", bdaddr_ntoa(&addr), c->handle);
	engine_conn_up(c);
}

static void
hci_le_conn_complete(const uint8_t *p, size_t len, int enhanced)
{
	struct hci_conn	*c;
	struct bdaddr	 addr;
	uint8_t		 status;

	if (len < (enhanced ? 30 : 18))
		return;
	status = p[0];
	memcpy(addr.b, p + 5, 6);
	if (status != 0) {
		engine_conn_failed(LINK_LE, &addr, status);
		return;
	}
	c = hci_conn_new(get16(p + 1) & 0x0fff, LINK_LE);
	c->role = p[3];
	c->peer_type = p[4] & 1;
	c->peer = addr;
	p += enhanced ? 23 : 11;
	c->le_interval = get16(p);
	c->le_latency = get16(p + 2);
	c->le_timeout = get16(p + 4);
	log_debug("%s: LE connection 0x%04x up, interval %u",
	    bdaddr_ntoa(&addr), c->handle, c->le_interval);
	engine_conn_up(c);
}

static void
hci_disconn_complete(const uint8_t *p, size_t len)
{
	struct hci_conn	*c;
	struct hci_acl	*a, *na;
	int		*freep;

	if (len < 4 || p[0] != 0)
		return;
	if ((c = hci_conn_find(get16(p + 1) & 0x0fff)) == NULL)
		return;
	log_debug("%s: connection 0x%04x down, reason 0x%02x",
	    bdaddr_ntoa(&c->peer), c->handle, p[3]);

	freep = (c->link == LINK_LE && hci.le_acl_num != 0) ?
	    &hci.le_acl_free : &hci.acl_free;
	*freep += c->inflight;
	TAILQ_FOREACH_SAFE(a, &aclq, entry, na) {
		if (a->conn != c)
			continue;
		TAILQ_REMOVE(&aclq, a, entry);
		free(a);
	}
	TAILQ_REMOVE(&hci_conns, c, entry);
	engine_conn_down(c, p[3]);
	l2cap_conn_free(c);
	free(c->rx);
	free(c);
	hci_acl_kick();
}

void
hci_disconnect(struct hci_conn *c, uint8_t reason)
{
	uint8_t	 p[3];

	if (c->disconnecting)
		return;
	c->disconnecting = 1;
	put16(p, c->handle);
	p[2] = reason;
	hci_cmd(HCI_CMD_DISCONNECT, p, sizeof(p), NULL, NULL);
}

static void
hci_completed(const uint8_t *p, size_t len)
{
	struct hci_conn	*c;
	size_t		 i, n;
	uint16_t	 cnt;

	if (len < 1 || len < 1 + (size_t)p[0] * 4)
		return;
	n = p[0];
	for (i = 0; i < n; i++) {
		cnt = get16(p + 1 + i * 4 + 2);
		if ((c = hci_conn_find(get16(p + 1 + i * 4) & 0x0fff)) == NULL)
			continue;
		if (cnt > c->inflight)
			cnt = c->inflight;
		c->inflight -= cnt;
		if (c->link == LINK_LE && hci.le_acl_num != 0)
			hci.le_acl_free += cnt;
		else
			hci.acl_free += cnt;
	}
	hci_acl_kick();
}

static void
hci_acl_packet(const uint8_t *p, size_t len)
{
	struct hci_conn	*c;
	uint16_t	 h, dlen, l2len;
	int		 pb;

	h = get16(p);
	dlen = get16(p + 2);
	pb = (h >> 12) & 3;
	if ((c = hci_conn_find(h & 0x0fff)) == NULL)
		return;
	p += 4;

	if (pb == HCI_PB_CONT) {
		if (c->rx == NULL || c->rxlen + dlen > c->rxwant) {
			log_debug("%s: unexpected continuation",
			    bdaddr_ntoa(&c->peer));
			free(c->rx);
			c->rx = NULL;
			return;
		}
		memcpy(c->rx + c->rxlen, p, dlen);
		c->rxlen += dlen;
	} else {
		free(c->rx);
		c->rx = NULL;
		if (dlen < 4)
			return;
		l2len = get16(p);
		if (dlen == 4 + l2len) {
			l2cap_input(c, get16(p + 2), p + 4, l2len);
			return;
		}
		if (dlen > 4 + l2len)
			return;
		if ((c->rx = malloc(4 + l2len)) == NULL)
			fatal(NULL);
		memcpy(c->rx, p, dlen);
		c->rxlen = dlen;
		c->rxwant = 4 + l2len;
	}
	if (c->rxlen == c->rxwant) {
		l2cap_input(c, get16(c->rx + 2), c->rx + 4, c->rxwant - 4);
		free(c->rx);
		c->rx = NULL;
	}
}

void
hci_acl_send(struct hci_conn *c, const uint8_t *p, size_t len)
{
	struct hci_acl	*a;
	size_t		 mtu, off, n;

	mtu = (c->link == LINK_LE && hci.le_acl_num != 0) ?
	    hci.le_acl_len : hci.acl_len;
	if (mtu == 0)
		return;
	for (off = 0; off < len; off += n) {
		n = len - off;
		if (n > mtu)
			n = mtu;
		if ((a = malloc(sizeof(*a) + 4 + n)) == NULL)
			fatal(NULL);
		a->conn = c;
		a->len = 4 + n;
		put16(a->data, c->handle |
		    ((off == 0 ? HCI_PB_START_HOST : HCI_PB_CONT) << 12));
		put16(a->data + 2, n);
		memcpy(a->data + 4, p + off, n);
		TAILQ_INSERT_TAIL(&aclq, a, entry);
		c->queued++;
	}
	hci_acl_kick();
}

static void
hci_acl_kick(void)
{
	struct hci_acl	*a, *na;
	int		*freep;

	TAILQ_FOREACH_SAFE(a, &aclq, entry, na) {
		freep = (a->conn->link == LINK_LE && hci.le_acl_num != 0) ?
		    &hci.le_acl_free : &hci.acl_free;
		if (*freep <= 0)
			continue;
		(*freep)--;
		TAILQ_REMOVE(&aclq, a, entry);
		a->conn->queued--;
		a->conn->inflight++;
		hci_trace(">", HCI_PKT_ACL, a->data, a->len);
		engine_imsg_compose_bus(IMSG_HCI_ACL, a->data, a->len);
		free(a);
	}
}

int
hci_acl_pending(int link)
{
	struct hci_conn	*c;
	int		 n = 0;

	TAILQ_FOREACH(c, &hci_conns, entry)
		if (c->link == link)
			n += c->queued + c->inflight;
	return (n);
}

enum {
	I_RESET,
	I_COMMANDS,
	I_VERSION,
	I_LE_FEATURES,
	I_EXT_FEATURES,
	I_EVENT_MASK,
	I_LE_EVENT_MASK,
	I_BUFFER_SIZE,
	I_LE_BUFFER_SIZE,
	I_DATA_LEN_READ,
	I_DATA_LEN_WRITE,
	I_ADV_SETS,
	I_ADV_DATA_LEN,
	I_BDADDR,
	I_LE_HOST,
	I_RANDOM_ADDR,
	I_LOCAL_NAME,
	I_CLASS,
	I_SSP_MODE,
	I_SC_HOST,
	I_SCAN_ENABLE,
	I_PAGE_SCAN_TYPE,
	I_INQUIRY_SCAN_TYPE,
	I_DONE
};

void
hci_start(void)
{
	hci.state = HCI_S_INIT;
	hci.scan_want = hci.scanning = 0;
	hci_init_next(I_RESET);
}

/*
 * Bring the controller up one command at a time, each step started
 * from the completion of the previous one.
 */
static void
hci_init_next(int step)
{
	uint8_t	 p[248];
	void	*arg = (void *)(intptr_t)step;

	switch (step) {
	case I_RESET:
		hci_cmd(HCI_CMD_RESET, NULL, 0, hci_init_step, arg);
		break;
	case I_COMMANDS:
		hci_cmd(HCI_CMD_READ_LOCAL_COMMANDS, NULL, 0, hci_init_step,
		    arg);
		break;
	case I_VERSION:
		hci_cmd(HCI_CMD_READ_LOCAL_VERSION, NULL, 0, hci_init_step,
		    arg);
		break;
	case I_LE_FEATURES:
		hci_cmd(HCI_CMD_LE_READ_LOCAL_FEATURES, NULL, 0,
		    hci_init_step, arg);
		break;
	case I_EXT_FEATURES:
		p[0] = ext_page;
		hci_cmd(HCI_CMD_READ_LOCAL_EXT_FEATURES, p, 1, hci_init_step,
		    arg);
		break;
	case I_EVENT_MASK:
		put64(p, 0x3dbff807bfff9fffULL);
		hci_cmd(HCI_CMD_SET_EVENT_MASK, p, 8, hci_init_step, arg);
		break;
	case I_LE_EVENT_MASK:
		put64(p, 0x007bed0ffff7ffffULL);
		hci_cmd(HCI_CMD_LE_SET_EVENT_MASK, p, 8, hci_init_step, arg);
		break;
	case I_BUFFER_SIZE:
		hci_cmd(HCI_CMD_READ_BUFFER_SIZE, NULL, 0, hci_init_step, arg);
		break;
	case I_LE_BUFFER_SIZE:
		hci_cmd(HCI_CMD_LE_READ_BUFFER_SIZE, NULL, 0, hci_init_step,
		    arg);
		break;
	case I_DATA_LEN_READ:
		hci_cmd(HCI_CMD_LE_READ_DEFAULT_DATA_LEN, NULL, 0,
		    hci_init_step, arg);
		break;
	case I_DATA_LEN_WRITE:
		put16(p, 251);
		put16(p + 2, 2120);
		hci_cmd(HCI_CMD_LE_WRITE_DEFAULT_DATA_LEN, p, 4,
		    hci_init_step, arg);
		break;
	case I_ADV_SETS:
		hci_cmd(HCI_CMD_LE_READ_NUM_ADV_SETS, NULL, 0, hci_init_step,
		    arg);
		break;
	case I_ADV_DATA_LEN:
		hci_cmd(HCI_CMD_LE_READ_MAX_ADV_DATA_LEN, NULL, 0,
		    hci_init_step, arg);
		break;
	case I_BDADDR:
		hci_cmd(HCI_CMD_READ_BDADDR, NULL, 0, hci_init_step, arg);
		break;
	case I_LE_HOST:
		p[0] = 1;
		p[1] = 0;
		hci_cmd(HCI_CMD_WRITE_LE_HOST_SUPPORT, p, 2, hci_init_step,
		    arg);
		break;
	case I_RANDOM_ADDR:
		engine_local_identity(&hci.random);
		memcpy(p, hci.random.b, 6);
		hci_cmd(HCI_CMD_LE_SET_RANDOM_ADDR, p, 6, hci_init_step, arg);
		break;
	case I_LOCAL_NAME:
		memset(p, 0, sizeof(p));
		strlcpy((char *)p, engine_state.conf->name, sizeof(p));
		hci_cmd(HCI_CMD_WRITE_LOCAL_NAME, p, 248, hci_init_step, arg);
		break;
	case I_CLASS:
		memset(p, 0, 3);
		hci_cmd(HCI_CMD_WRITE_CLASS_OF_DEVICE, p, 3, hci_init_step,
		    arg);
		break;
	case I_SSP_MODE:
		p[0] = 1;
		hci_cmd(HCI_CMD_WRITE_SSP_MODE, p, 1, hci_init_step, arg);
		break;
	case I_SC_HOST:
		p[0] = 1;
		hci_cmd(HCI_CMD_WRITE_SC_HOST_SUPPORT, p, 1, hci_init_step,
		    arg);
		break;
	case I_SCAN_ENABLE:
		p[0] = HCI_SCAN_PAGE;
		hci_cmd(HCI_CMD_WRITE_SCAN_ENABLE, p, 1, hci_init_step, arg);
		break;
	case I_PAGE_SCAN_TYPE:
		p[0] = 1;
		hci_cmd(HCI_CMD_WRITE_PAGE_SCAN_TYPE, p, 1, hci_init_step,
		    arg);
		break;
	case I_INQUIRY_SCAN_TYPE:
		p[0] = 1;
		hci_cmd(HCI_CMD_WRITE_INQUIRY_SCAN_TYPE, p, 1, hci_init_step,
		    arg);
		break;
	case I_DONE:
		hci_init_done();
		break;
	}
}

static void
hci_init_step(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	int	 step = (intptr_t)arg;

	if (step == I_RESET && status == HCI_ERR_TIMEOUT &&
	    ++reset_tries < HCI_RESET_TRIES) {
		log_warnx("controller reset timed out, retrying");
		hci_init_next(I_RESET);
		return;
	}
	if (step == I_RESET)
		reset_tries = 0;
	if (status != 0 && step != I_ADV_SETS && step != I_ADV_DATA_LEN &&
	    step != I_DATA_LEN_READ && step != I_DATA_LEN_WRITE)
		fatalx("controller init step %d failed: 0x%02x", step, status);

	switch (step) {
	case I_COMMANDS:
		if (len >= sizeof(hci.commands))
			memcpy(hci.commands, rp, sizeof(hci.commands));
		break;
	case I_VERSION:
		if (len < 8)
			fatalx("short local version");
		hci.hci_ver = rp[0];
		hci.hci_rev = get16(rp + 1);
		hci.lmp_ver = rp[3];
		hci.manufacturer = get16(rp + 4);
		hci.lmp_subver = get16(rp + 6);
		log_info("controller: HCI 0x%02x revision 0x%04x, LMP 0x%02x "
		    "subversion 0x%04x, manufacturer 0x%04x", hci.hci_ver,
		    hci.hci_rev, hci.lmp_ver, hci.lmp_subver,
		    hci.manufacturer);
		if (rtk_needed()) {
			hci.state = HCI_S_FIRMWARE;
			rtk_load();
			return;
		}
		ext_page = 0;
		break;
	case I_LE_FEATURES:
		if (len >= sizeof(hci.le_features))
			memcpy(hci.le_features, rp, sizeof(hci.le_features));
		break;
	case I_EXT_FEATURES:
		if (len >= 10 && rp[0] < nitems(hci.features))
			memcpy(hci.features[rp[0]], rp + 2, 8);
		if (len >= 2 && ext_page < rp[1] &&
		    ext_page + 1 < (int)nitems(hci.features)) {
			ext_page++;
			hci_init_next(I_EXT_FEATURES);
			return;
		}
		break;
	case I_BUFFER_SIZE:
		if (len < 7)
			fatalx("short buffer size");
		hci.acl_len = get16(rp);
		hci.acl_num = get16(rp + 3);
		hci.acl_free = hci.acl_num;
		break;
	case I_LE_BUFFER_SIZE:
		if (len < 3)
			fatalx("short LE buffer size");
		hci.le_acl_len = get16(rp);
		hci.le_acl_num = rp[2];
		hci.le_acl_free = hci.le_acl_num;
		break;
	case I_BDADDR:
		if (len < 6)
			fatalx("short BD_ADDR");
		memcpy(hci.bdaddr.b, rp, 6);
		break;
	}
	hci_init_next(step + 1);
}

static void
hci_init_done(void)
{
	hci.ext_scan = (hci.le_features[1] & 0x10) != 0;
	hci.coded_phy = (hci.le_features[1] & 0x08) != 0;
	hci.state = HCI_S_RUNNING;
	log_info("controller %s ready: ACL %u x %u, LE ACL %u x %u",
	    bdaddr_ntoa(&hci.bdaddr), hci.acl_num, hci.acl_len,
	    hci.le_acl_num, hci.le_acl_len);
	engine_ready();
}

void
hci_scan(int on)
{
	uint8_t	 p[13];

	if (hci.state != HCI_S_RUNNING || on == hci.scan_want)
		return;
	hci.scan_want = on;
	if (on) {
		if (hci.ext_scan) {
			p[0] = BDADDR_RANDOM;
			p[1] = 0x00;
			p[2] = hci.coded_phy ? 0x05 : 0x01;
			p[3] = 0x01;
			put16(p + 4, 0x60);
			put16(p + 6, 0x60);
			p[8] = 0x01;
			put16(p + 9, 0x60);
			put16(p + 11, 0x60);
			hci_cmd(HCI_CMD_LE_SET_EXT_SCAN_PARAMS, p,
			    hci.coded_phy ? 13 : 8, NULL, NULL);
			p[0] = 1;
			p[1] = 1;
			put16(p + 2, 0);
			put16(p + 4, 0);
			hci_cmd(HCI_CMD_LE_SET_EXT_SCAN_ENABLE, p, 6,
			    hci_scan_done, NULL);
		} else {
			p[0] = 0x01;
			put16(p + 1, 0x60);
			put16(p + 3, 0x60);
			p[5] = BDADDR_RANDOM;
			p[6] = 0x00;
			hci_cmd(HCI_CMD_LE_SET_SCAN_PARAMS, p, 7, NULL, NULL);
			p[0] = 1;
			p[1] = 1;
			hci_cmd(HCI_CMD_LE_SET_SCAN_ENABLE, p, 2,
			    hci_scan_done, NULL);
		}
	} else {
		memset(p, 0, sizeof(p));
		if (hci.ext_scan)
			hci_cmd(HCI_CMD_LE_SET_EXT_SCAN_ENABLE, p, 6,
			    hci_scan_done, NULL);
		else
			hci_cmd(HCI_CMD_LE_SET_SCAN_ENABLE, p, 2,
			    hci_scan_done, NULL);
	}
}

static void
hci_scan_done(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	if (status != 0)
		log_warnx("scan %s failed: 0x%02x", hci.scan_want ? "enable" :
		    "disable", status);
	else
		hci.scanning = hci.scan_want;
	engine_scan_changed();
}

static void
hci_adv_report(const uint8_t *p, size_t len)
{
	struct bdaddr	 addr;
	size_t		 off = 1, dlen;
	int		 i, n;

	if (len < 1)
		return;
	n = p[0];
	for (i = 0; i < n; i++) {
		if (off + 9 > len)
			return;
		memcpy(addr.b, p + off + 2, 6);
		dlen = p[off + 8];
		if (off + 9 + dlen + 1 > len)
			return;
		engine_adv_report(&addr, p[off + 1] & 1, p[off] < 2,
		    (int8_t)p[off + 9 + dlen], p + off + 9, dlen);
		off += 9 + dlen + 1;
	}
}

static void
hci_ext_adv_report(const uint8_t *p, size_t len)
{
	struct bdaddr	 addr;
	size_t		 off = 1, dlen;
	uint16_t	 type;
	int		 i, n;

	if (len < 1)
		return;
	n = p[0];
	for (i = 0; i < n; i++) {
		if (off + 24 > len)
			return;
		type = get16(p + off);
		memcpy(addr.b, p + off + 3, 6);
		dlen = p[off + 23];
		if (off + 24 + dlen > len)
			return;
		engine_adv_report(&addr, p[off + 2] & 1, type & 0x01,
		    (int8_t)p[off + 13], p + off + 24, dlen);
		off += 24 + dlen;
	}
}

void
hci_le_connect(const struct bdaddr *addr, uint8_t type)
{
	uint8_t	 p[42];

	if (hci.ext_scan) {
		memset(p, 0, sizeof(p));
		p[0] = 0x00;
		p[1] = BDADDR_RANDOM;
		p[2] = type;
		memcpy(p + 3, addr->b, 6);
		p[9] = 0x01;
		put16(p + 10, 0x60);
		put16(p + 12, 0x60);
		put16(p + 14, 0x0c);
		put16(p + 16, 0x18);
		put16(p + 18, 0);
		put16(p + 20, 0x48);
		put16(p + 22, 0);
		put16(p + 24, 0);
		hci_cmd(HCI_CMD_LE_EXT_CREATE_CONN, p, 26, engine_create_status,
		    NULL);
	} else {
		put16(p, 0x60);
		put16(p + 2, 0x60);
		p[4] = 0x00;
		p[5] = type;
		memcpy(p + 6, addr->b, 6);
		p[12] = BDADDR_RANDOM;
		put16(p + 13, 0x0c);
		put16(p + 15, 0x18);
		put16(p + 17, 0);
		put16(p + 19, 0x48);
		put16(p + 21, 0);
		put16(p + 23, 0);
		hci_cmd(HCI_CMD_LE_CREATE_CONN, p, 25, engine_create_status,
		    NULL);
	}
}

void
hci_le_connect_cancel(void)
{
	hci_cmd(HCI_CMD_LE_CREATE_CONN_CANCEL, NULL, 0, NULL, NULL);
}

void
hci_br_connect(const struct bdaddr *addr)
{
	uint8_t	 p[13];

	memcpy(p, addr->b, 6);
	put16(p + 6, 0xcc18);
	p[8] = 0x02;
	p[9] = 0x00;
	put16(p + 10, 0);
	p[12] = 0x01;
	hci_cmd(HCI_CMD_CREATE_CONN, p, sizeof(p), engine_create_status, NULL);
}

uint16_t
get16(const uint8_t *p)
{
	return (p[0] | p[1] << 8);
}

uint32_t
get32(const uint8_t *p)
{
	return (p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24);
}

uint64_t
get64(const uint8_t *p)
{
	return (get32(p) | (uint64_t)get32(p + 4) << 32);
}

void
put16(uint8_t *p, uint16_t v)
{
	p[0] = v;
	p[1] = v >> 8;
}

void
put32(uint8_t *p, uint32_t v)
{
	put16(p, v);
	put16(p + 2, v >> 16);
}

void
put64(uint8_t *p, uint64_t v)
{
	put32(p, v);
	put32(p + 4, v >> 32);
}
