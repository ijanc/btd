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

#define	SMP_PAIRING_REQ		0x01
#define	SMP_PAIRING_RSP		0x02
#define	SMP_PAIRING_CONFIRM	0x03
#define	SMP_PAIRING_RANDOM	0x04
#define	SMP_PAIRING_FAILED	0x05
#define	SMP_ENCRYPTION_INFO	0x06
#define	SMP_CENTRAL_IDENT	0x07
#define	SMP_IDENTITY_INFO	0x08
#define	SMP_IDENTITY_ADDR	0x09
#define	SMP_SIGNING_INFO	0x0a
#define	SMP_SECURITY_REQ	0x0b
#define	SMP_PUBLIC_KEY		0x0c
#define	SMP_DHKEY_CHECK		0x0d

#define	SMP_IO_DISPLAY_ONLY	0x00
#define	SMP_IO_DISPLAY_YESNO	0x01
#define	SMP_IO_KEYBOARD_ONLY	0x02
#define	SMP_IO_NONE		0x03
#define	SMP_IO_KEYBOARD_DISPLAY	0x04

#define	SMP_AUTH_BONDING	0x01
#define	SMP_AUTH_MITM		0x04
#define	SMP_AUTH_SC		0x08

#define	SMP_DIST_ENC		0x01
#define	SMP_DIST_ID		0x02
#define	SMP_DIST_SIGN		0x04

#define	SMP_ERR_PASSKEY		0x01
#define	SMP_ERR_NOT_SUPPORTED	0x05
#define	SMP_ERR_AUTH_REQ	0x03
#define	SMP_ERR_CONFIRM		0x04
#define	SMP_ERR_UNSPECIFIED	0x08
#define	SMP_ERR_INVALID		0x0a
#define	SMP_ERR_DHKEY_CHECK	0x0b

#define	SMP_TIMEOUT		30

#define	SMP_JUST_WORKS		0
#define	SMP_PASSKEY		1

#define	SSP_IO_NONE		0x03
#define	SSP_AUTH_GENERAL	0x04

enum smp_state {
	SMP_S_IDLE,
	SMP_S_ENCRYPTING,
	SMP_S_WAIT_RSP,
	SMP_S_WAIT_PUBKEY,
	SMP_S_WAIT_CONFIRM,
	SMP_S_WAIT_RANDOM,
	SMP_S_WAIT_CHECK,
	SMP_S_WAIT_ENCRYPTION,
	SMP_S_WAIT_KEYS,
	SMP_S_DONE
};

struct smp {
	struct hci_conn		*conn;
	enum smp_state		 state;
	struct event		 timer;
	uint8_t			 preq[7];
	uint8_t			 pres[7];
	int			 method;
	void			*ecdh;
	uint8_t			 pka[64];
	uint8_t			 pkb[64];
	uint8_t			 dhkey[32];
	uint8_t			 na[16];
	uint8_t			 nb[16];
	uint8_t			 cb[16];
	uint32_t		 passkey;
	int			 round;
	uint8_t			 mackey[16];
	uint8_t			 ltk[16];
	uint8_t			 keysize;
	uint8_t			 dist_resp;
	uint8_t			 dist_init;
	uint8_t			 irk[16];
	int			 have_irk;
	struct bdaddr		 ident;
	uint8_t			 ident_type;
	int			 have_ident;
	int			 bonded;
};

static struct smp	*smp_get(struct hci_conn *);
static void		 smp_send(struct smp *, uint8_t, const void *, size_t);
static void		 smp_fail(struct smp *, uint8_t);
static void		 smp_timer(struct smp *);
static void		 smp_timeout(int, short, void *);
static void		 smp_pair(struct smp *);
static void		 smp_pairing_rsp(struct smp *, const uint8_t *, size_t);
static void		 smp_public_key(struct smp *, const uint8_t *, size_t);
static void		 smp_send_confirm(struct smp *);
static void		 smp_confirm(struct smp *, const uint8_t *, size_t);
static void		 smp_random(struct smp *, const uint8_t *, size_t);
static void		 smp_send_check(struct smp *);
static void		 smp_check(struct smp *, const uint8_t *, size_t);
static void		 smp_start_encryption(struct smp *, const uint8_t *,
			    uint16_t, uint64_t);
static void		 smp_keys(struct smp *, uint8_t, const uint8_t *,
			    size_t);
static void		 smp_finish(struct smp *);
static void		 smp_addr7(const struct bdaddr *, uint8_t, uint8_t *);
static void		 smp_r(struct smp *, uint8_t *);
static void		 smp_enc_status(void *, uint8_t, const uint8_t *,
			    size_t);
static void		 ssp_auth_status(void *, uint8_t, const uint8_t *,
			    size_t);

int
smp_rpa_match(const uint8_t irk[16], const struct bdaddr *addr)
{
	uint8_t	 hash[3];

	if (crypto_ah(irk, addr->b + 3, hash) == -1)
		return (0);
	return (memcmp(hash, addr->b, 3) == 0);
}

static struct smp *
smp_get(struct hci_conn *c)
{
	struct smp	*smp;

	if (c->smp != NULL)
		return (c->smp);
	if ((smp = calloc(1, sizeof(*smp))) == NULL)
		fatal(NULL);
	smp->conn = c;
	evtimer_set(&smp->timer, smp_timeout, smp);
	c->smp = smp;
	return (smp);
}

void
smp_free(struct hci_conn *c)
{
	struct smp	*smp = c->smp;

	if (smp == NULL)
		return;
	evtimer_del(&smp->timer);
	if (smp->ecdh != NULL)
		crypto_ecdh_free(smp->ecdh);
	explicit_bzero(smp, sizeof(*smp));
	free(smp);
	c->smp = NULL;
}

static void
smp_send(struct smp *smp, uint8_t code, const void *p, size_t len)
{
	uint8_t	 buf[1 + 64];

	buf[0] = code;
	memcpy(buf + 1, p, len);
	log_debug("%s: smp send 0x%02x", bdaddr_ntoa(&smp->conn->peer), code);
	l2cap_send_fixed(smp->conn, L2CAP_CID_SMP, buf, 1 + len);
}

static void
smp_timer(struct smp *smp)
{
	struct timeval	 tv = { SMP_TIMEOUT, 0 };

	evtimer_add(&smp->timer, &tv);
}

static void
smp_timeout(int fd, short event, void *arg)
{
	struct smp	*smp = arg;

	log_warnx("%s: pairing timed out", bdaddr_ntoa(&smp->conn->peer));
	smp->state = SMP_S_IDLE;
	engine_secured(smp->conn, 0);
}

static void
smp_fail(struct smp *smp, uint8_t reason)
{
	struct device	*dev = smp->conn->dev;

	log_warnx("%s: pairing failed: 0x%02x", bdaddr_ntoa(&smp->conn->peer),
	    reason);
	smp_send(smp, SMP_PAIRING_FAILED, &reason, 1);
	evtimer_del(&smp->timer);
	smp->state = SMP_S_IDLE;
	if (dev != NULL)
		dev->passkey = -1;
	engine_secured(smp->conn, 0);
}

void
smp_le_secure(struct hci_conn *c)
{
	struct smp	*smp = smp_get(c);
	struct bond	*b;

	b = c->dev != NULL ? bond_find(BOND_LE, &c->dev->addr) : NULL;
	if (b != NULL && (b->flags & BOND_F_LTK)) {
		smp->bonded = 1;
		smp->state = SMP_S_ENCRYPTING;
		smp_start_encryption(smp, b->ltk, b->ediv, b->rand);
		return;
	}
	smp_pair(smp);
}

static void
smp_start_encryption(struct smp *smp, const uint8_t *ltk, uint16_t ediv,
    uint64_t rand)
{
	uint8_t	 p[28];

	put16(p, smp->conn->handle);
	put64(p + 2, rand);
	put16(p + 10, ediv);
	memcpy(p + 12, ltk, 16);
	hci_cmd(HCI_CMD_LE_START_ENCRYPTION, p, sizeof(p), smp_enc_status,
	    (void *)(uintptr_t)smp->conn->handle);
	explicit_bzero(p, sizeof(p));
	smp_timer(smp);
}

static void
smp_enc_status(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	struct hci_conn	*c;

	if (status == 0 ||
	    (c = hci_conn_find((uintptr_t)arg)) == NULL || c->smp == NULL)
		return;
	log_warnx("%s: start encryption failed: 0x%02x",
	    bdaddr_ntoa(&c->peer), status);
	evtimer_del(&c->smp->timer);
	c->smp->state = SMP_S_IDLE;
	engine_secured(c, 0);
}

void
smp_encryption_changed(struct hci_conn *c, uint8_t status, int on)
{
	struct smp	*smp = c->smp;
	struct bond	*b;

	if (smp == NULL)
		return;
	switch (smp->state) {
	case SMP_S_ENCRYPTING:
		evtimer_del(&smp->timer);
		if (status != 0 || !on) {
			log_warnx("%s: encryption with stored key failed: "
			    "0x%02x", bdaddr_ntoa(&c->peer), status);
			if (status == HCI_ERR_KEY_MISSING && c->dev != NULL &&
			    (b = bond_find(BOND_LE, &c->dev->addr)) != NULL) {
				log_warnx("%s: peer lost the bond, removing it",
				    bdaddr_ntoa(&c->dev->addr));
				bond_delete(b);
			}
			smp->state = SMP_S_IDLE;
			engine_secured(c, 0);
			return;
		}
		smp->state = SMP_S_DONE;
		engine_secured(c, 1);
		break;
	case SMP_S_WAIT_ENCRYPTION:
		if (status != 0 || !on) {
			smp_fail(smp, SMP_ERR_UNSPECIFIED);
			return;
		}
		smp->state = SMP_S_WAIT_KEYS;
		smp_timer(smp);
		if (smp->dist_resp == 0)
			smp_finish(smp);
		break;
	default:
		break;
	}
}

static void
smp_pair(struct smp *smp)
{
	uint8_t	*p = smp->preq;

	p[0] = SMP_PAIRING_REQ;
	p[1] = SMP_IO_DISPLAY_ONLY;
	p[2] = 0x00;
	p[3] = SMP_AUTH_BONDING | SMP_AUTH_MITM | SMP_AUTH_SC;
	p[4] = 16;
	p[5] = SMP_DIST_ENC | SMP_DIST_ID;
	p[6] = SMP_DIST_ENC | SMP_DIST_ID;
	log_info("%s: pairing", bdaddr_ntoa(&smp->conn->peer));
	smp->state = SMP_S_WAIT_RSP;
	smp->bonded = 0;
	l2cap_send_fixed(smp->conn, L2CAP_CID_SMP, p, sizeof(smp->preq));
	smp_timer(smp);
}

void
smp_input(struct hci_conn *c, const uint8_t *p, size_t len)
{
	struct smp	*smp = smp_get(c);
	uint8_t		 reason;

	if (len < 1)
		return;
	log_debug("%s: smp code 0x%02x in state %d, %zu bytes",
	    bdaddr_ntoa(&c->peer), p[0], smp->state, len);
	switch (p[0]) {
	case SMP_PAIRING_RSP:
		if (smp->state == SMP_S_WAIT_RSP)
			smp_pairing_rsp(smp, p, len);
		break;
	case SMP_PUBLIC_KEY:
		if (smp->state == SMP_S_WAIT_PUBKEY)
			smp_public_key(smp, p + 1, len - 1);
		break;
	case SMP_PAIRING_CONFIRM:
		if (smp->state == SMP_S_WAIT_CONFIRM)
			smp_confirm(smp, p + 1, len - 1);
		break;
	case SMP_PAIRING_RANDOM:
		if (smp->state == SMP_S_WAIT_RANDOM)
			smp_random(smp, p + 1, len - 1);
		break;
	case SMP_DHKEY_CHECK:
		if (smp->state == SMP_S_WAIT_CHECK)
			smp_check(smp, p + 1, len - 1);
		break;
	case SMP_ENCRYPTION_INFO:
	case SMP_CENTRAL_IDENT:
	case SMP_IDENTITY_INFO:
	case SMP_IDENTITY_ADDR:
	case SMP_SIGNING_INFO:
		if (smp->state == SMP_S_WAIT_KEYS)
			smp_keys(smp, p[0], p + 1, len - 1);
		break;
	case SMP_PAIRING_FAILED:
		if (smp->state == SMP_S_IDLE || smp->state == SMP_S_DONE)
			break;
		log_warnx("%s: pairing failed by peer: 0x%02x",
		    bdaddr_ntoa(&c->peer), len > 1 ? p[1] : 0);
		evtimer_del(&smp->timer);
		smp->state = SMP_S_IDLE;
		if (c->dev != NULL)
			c->dev->passkey = -1;
		engine_secured(c, 0);
		break;
	case SMP_SECURITY_REQ:
		log_debug("%s: security request", bdaddr_ntoa(&c->peer));
		break;
	case SMP_PAIRING_REQ:
		reason = SMP_ERR_NOT_SUPPORTED;
		smp_send(smp, SMP_PAIRING_FAILED, &reason, 1);
		break;
	default:
		break;
	}
}

static void
smp_pairing_rsp(struct smp *smp, const uint8_t *p, size_t len)
{
	struct device	*dev = smp->conn->dev;
	uint8_t		 io;

	if (len != sizeof(smp->pres)) {
		smp_fail(smp, SMP_ERR_INVALID);
		return;
	}
	memcpy(smp->pres, p, sizeof(smp->pres));
	if (!(p[3] & SMP_AUTH_SC)) {
		log_warnx("%s: peer lacks secure connections",
		    bdaddr_ntoa(&smp->conn->peer));
		smp_fail(smp, SMP_ERR_AUTH_REQ);
		return;
	}
	io = p[1];
	smp->method = SMP_JUST_WORKS;
	if (((smp->preq[3] | p[3]) & SMP_AUTH_MITM) &&
	    (io == SMP_IO_KEYBOARD_ONLY || io == SMP_IO_KEYBOARD_DISPLAY))
		smp->method = SMP_PASSKEY;
	smp->keysize = p[4] < smp->preq[4] ? p[4] : smp->preq[4];
	if (smp->keysize < 7) {
		smp_fail(smp, 0x06);
		return;
	}
	smp->dist_resp = p[6] & smp->preq[6] & SMP_DIST_ID;
	smp->dist_init = p[5] & smp->preq[5] & SMP_DIST_ID;
	log_debug("%s: pairing response io 0x%02x auth 0x%02x, %s",
	    bdaddr_ntoa(&smp->conn->peer), io, p[3],
	    smp->method == SMP_PASSKEY ? "passkey entry" : "just works");

	if (smp->method == SMP_PASSKEY) {
		smp->passkey = arc4random_uniform(1000000);
		log_info("%s: passkey %06u, type it on the device and press "
		    "Enter", bdaddr_ntoa(&smp->conn->peer), smp->passkey);
		if (dev != NULL)
			dev->passkey = smp->passkey;
	}

	if ((smp->ecdh = crypto_ecdh_new(smp->pka)) == NULL) {
		smp_fail(smp, SMP_ERR_UNSPECIFIED);
		return;
	}
	smp->state = SMP_S_WAIT_PUBKEY;
	smp_send(smp, SMP_PUBLIC_KEY, smp->pka, sizeof(smp->pka));
	smp_timer(smp);
}

static void
smp_public_key(struct smp *smp, const uint8_t *p, size_t len)
{
	if (len != sizeof(smp->pkb) || memcmp(p, smp->pka, 64) == 0) {
		smp_fail(smp, SMP_ERR_INVALID);
		return;
	}
	memcpy(smp->pkb, p, sizeof(smp->pkb));
	if (crypto_ecdh_shared(smp->ecdh, smp->pkb, smp->dhkey) == -1) {
		smp_fail(smp, SMP_ERR_DHKEY_CHECK);
		return;
	}
	crypto_ecdh_free(smp->ecdh);
	smp->ecdh = NULL;
	smp->round = 0;
	smp->state = SMP_S_WAIT_CONFIRM;
	if (smp->method == SMP_PASSKEY)
		smp_send_confirm(smp);
	smp_timer(smp);
}

static void
smp_send_confirm(struct smp *smp)
{
	uint8_t	 ca[16], ri;

	arc4random_buf(smp->na, sizeof(smp->na));
	ri = 0x80 | ((smp->passkey >> smp->round) & 1);
	if (crypto_f4(smp->pka, smp->pkb, smp->na, ri, ca) == -1) {
		smp_fail(smp, SMP_ERR_UNSPECIFIED);
		return;
	}
	smp_send(smp, SMP_PAIRING_CONFIRM, ca, sizeof(ca));
}

static void
smp_confirm(struct smp *smp, const uint8_t *p, size_t len)
{
	if (len != sizeof(smp->cb)) {
		smp_fail(smp, SMP_ERR_INVALID);
		return;
	}
	memcpy(smp->cb, p, sizeof(smp->cb));
	if (smp->method == SMP_JUST_WORKS)
		arc4random_buf(smp->na, sizeof(smp->na));
	smp->state = SMP_S_WAIT_RANDOM;
	smp_send(smp, SMP_PAIRING_RANDOM, smp->na, sizeof(smp->na));
	smp_timer(smp);
}

static void
smp_random(struct smp *smp, const uint8_t *p, size_t len)
{
	uint8_t	 cb[16], ri;

	if (len != sizeof(smp->nb)) {
		smp_fail(smp, SMP_ERR_INVALID);
		return;
	}
	memcpy(smp->nb, p, sizeof(smp->nb));
	ri = smp->method == SMP_PASSKEY ?
	    0x80 | ((smp->passkey >> smp->round) & 1) : 0;
	if (crypto_f4(smp->pkb, smp->pka, smp->nb, ri, cb) == -1 ||
	    timingsafe_bcmp(cb, smp->cb, sizeof(cb)) != 0) {
		smp_fail(smp, smp->method == SMP_PASSKEY ? SMP_ERR_PASSKEY :
		    SMP_ERR_CONFIRM);
		return;
	}
	if (smp->method == SMP_PASSKEY && ++smp->round < 20) {
		smp->state = SMP_S_WAIT_CONFIRM;
		smp_send_confirm(smp);
		smp_timer(smp);
		return;
	}
	smp_send_check(smp);
}

static void
smp_addr7(const struct bdaddr *addr, uint8_t type, uint8_t *a)
{
	memcpy(a, addr->b, 6);
	a[6] = type;
}

static void
smp_r(struct smp *smp, uint8_t *r)
{
	memset(r, 0, 16);
	if (smp->method == SMP_PASSKEY)
		put32(r, smp->passkey);
}

static void
smp_send_check(struct smp *smp)
{
	uint8_t	 a[7], b[7], r[16], iocap[3], ea[16];

	smp_addr7(&hci.random, BDADDR_RANDOM, a);
	smp_addr7(&smp->conn->peer, smp->conn->peer_type, b);
	if (crypto_f5(smp->dhkey, smp->na, smp->nb, a, b, smp->mackey,
	    smp->ltk) == -1) {
		smp_fail(smp, SMP_ERR_UNSPECIFIED);
		return;
	}
	smp_r(smp, r);
	iocap[0] = smp->preq[1];
	iocap[1] = smp->preq[2];
	iocap[2] = smp->preq[3];
	if (crypto_f6(smp->mackey, smp->na, smp->nb, r, iocap, a, b, ea) ==
	    -1) {
		smp_fail(smp, SMP_ERR_UNSPECIFIED);
		return;
	}
	smp->state = SMP_S_WAIT_CHECK;
	smp_send(smp, SMP_DHKEY_CHECK, ea, sizeof(ea));
	smp_timer(smp);
}

static void
smp_check(struct smp *smp, const uint8_t *p, size_t len)
{
	struct device	*dev = smp->conn->dev;
	uint8_t		 a[7], b[7], r[16], iocap[3], eb[16];

	if (len != sizeof(eb)) {
		smp_fail(smp, SMP_ERR_INVALID);
		return;
	}
	smp_addr7(&hci.random, BDADDR_RANDOM, a);
	smp_addr7(&smp->conn->peer, smp->conn->peer_type, b);
	smp_r(smp, r);
	iocap[0] = smp->pres[1];
	iocap[1] = smp->pres[2];
	iocap[2] = smp->pres[3];
	if (crypto_f6(smp->mackey, smp->nb, smp->na, r, iocap, b, a, eb) ==
	    -1 || timingsafe_bcmp(eb, p, sizeof(eb)) != 0) {
		smp_fail(smp, SMP_ERR_DHKEY_CHECK);
		return;
	}
	if (dev != NULL)
		dev->passkey = -1;
	if (smp->keysize < 16)
		memset(smp->ltk + smp->keysize, 0, 16 - smp->keysize);
	smp->state = SMP_S_WAIT_ENCRYPTION;
	smp_start_encryption(smp, smp->ltk, 0, 0);
}

static void
smp_keys(struct smp *smp, uint8_t code, const uint8_t *p, size_t len)
{
	switch (code) {
	case SMP_IDENTITY_INFO:
		if (len != 16)
			break;
		memcpy(smp->irk, p, 16);
		smp->have_irk = 1;
		break;
	case SMP_IDENTITY_ADDR:
		if (len != 7)
			break;
		smp->ident_type = p[0];
		memcpy(smp->ident.b, p + 1, 6);
		smp->have_ident = 1;
		break;
	default:
		break;
	}
	if (smp->have_irk && smp->have_ident)
		smp_finish(smp);
}

static void
smp_finish(struct smp *smp)
{
	struct hci_conn	*c = smp->conn;
	struct bond	 b;
	uint8_t		 p[7];

	if (smp->dist_init & SMP_DIST_ID) {
		smp_send(smp, SMP_IDENTITY_INFO, engine_state.local.irk, 16);
		p[0] = BDADDR_RANDOM;
		memcpy(p + 1, engine_state.local.addr.b, 6);
		smp_send(smp, SMP_IDENTITY_ADDR, p, sizeof(p));
	}
	evtimer_del(&smp->timer);
	smp->state = SMP_S_DONE;

	memset(&b, 0, sizeof(b));
	b.type = BOND_LE;
	if (c->dev != NULL)
		b.addr = c->dev->addr;
	else
		b.addr = c->peer;
	b.addr_type = c->peer_type;
	if (smp->have_ident) {
		b.addr_type = smp->ident_type;
		if (bdaddr_cmp(&smp->ident, &b.addr) != 0) {
			log_info("%s: identity address %s",
			    bdaddr_ntoa(&b.addr), bdaddr_ntoa(&smp->ident));
			b.ident = smp->ident;
			b.flags |= BOND_F_IDENT;
		}
	}
	memcpy(b.ltk, smp->ltk, 16);
	b.keysize = smp->keysize;
	b.flags = BOND_F_LTK | BOND_F_SC;
	if (smp->method == SMP_PASSKEY)
		b.flags |= BOND_F_AUTH;
	if (smp->have_irk) {
		memcpy(b.irk, smp->irk, 16);
		b.flags |= BOND_F_IRK;
	}
	bond_store(&b);
	explicit_bzero(&b, sizeof(b));
	log_info("%s: paired (%s), bond stored", bdaddr_ntoa(&c->peer),
	    smp->method == SMP_PASSKEY ? "passkey, authenticated" :
	    "just works");
	engine_secured(c, 1);
}

int
smp_authenticated(struct hci_conn *c)
{
	struct bond	*b;

	if (c->dev == NULL ||
	    (b = bond_find(c->link == LINK_LE ? BOND_LE : BOND_BR,
	    &c->dev->addr)) == NULL)
		return (0);
	if (c->link == LINK_LE)
		return ((b->flags & BOND_F_AUTH) != 0);
	return (b->linkkey_type == 5 || b->linkkey_type == 8);
}

int
smp_sc(struct hci_conn *c)
{
	struct bond	*b;

	if (c->dev == NULL ||
	    (b = bond_find(c->link == LINK_LE ? BOND_LE : BOND_BR,
	    &c->dev->addr)) == NULL)
		return (0);
	if (c->link == LINK_LE)
		return ((b->flags & BOND_F_SC) != 0);
	return (b->linkkey_type == 7 || b->linkkey_type == 8);
}

void
ssp_secure(struct hci_conn *c)
{
	uint8_t	 p[2];

	put16(p, c->handle);
	hci_cmd(HCI_CMD_AUTH_REQUESTED, p, sizeof(p), ssp_auth_status,
	    (void *)(uintptr_t)c->handle);
}

static void
ssp_auth_status(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	struct hci_conn	*c;

	if (status == 0 || (c = hci_conn_find((uintptr_t)arg)) == NULL)
		return;
	log_warnx("%s: authentication request failed: 0x%02x",
	    bdaddr_ntoa(&c->peer), status);
	engine_secured(c, 0);
}

void
ssp_event(uint8_t code, const uint8_t *p, size_t len)
{
	struct hci_conn	*c;
	struct bond	*b, nb;
	struct bdaddr	 addr;
	uint8_t		 rsp[22];

	switch (code) {
	case HCI_EVT_LINK_KEY_REQUEST:
		if (len < 6)
			return;
		memcpy(addr.b, p, 6);
		memcpy(rsp, p, 6);
		if ((b = bond_find(BOND_BR, &addr)) != NULL) {
			memcpy(rsp + 6, b->linkkey, 16);
			hci_cmd(HCI_CMD_LINK_KEY_REPLY, rsp, 22, NULL, NULL);
			explicit_bzero(rsp, sizeof(rsp));
		} else
			hci_cmd(HCI_CMD_LINK_KEY_NEG_REPLY, rsp, 6, NULL,
			    NULL);
		break;
	case HCI_EVT_PIN_CODE_REQUEST:
		if (len < 6)
			return;
		log_warnx("%s: legacy pairing not supported",
		    bdaddr_ntoa((const struct bdaddr *)p));
		hci_cmd(HCI_CMD_PIN_CODE_NEG_REPLY, p, 6, NULL, NULL);
		break;
	case HCI_EVT_IO_CAP_REQUEST:
		if (len < 6)
			return;
		memcpy(addr.b, p, 6);
		memcpy(rsp, p, 6);
		if (device_find(DEV_HEADSET, &addr) == NULL) {
			rsp[6] = HCI_ERR_PAIRING_NOT_ALLOWED;
			hci_cmd(HCI_CMD_IO_CAP_NEG_REPLY, rsp, 7, NULL, NULL);
			break;
		}
		log_info("%s: pairing", bdaddr_ntoa(&addr));
		rsp[6] = SSP_IO_NONE;
		rsp[7] = 0x00;
		rsp[8] = SSP_AUTH_GENERAL;
		hci_cmd(HCI_CMD_IO_CAP_REPLY, rsp, 9, NULL, NULL);
		break;
	case HCI_EVT_IO_CAP_RESPONSE:
		if (len < 9)
			return;
		log_debug("%s: peer io capability 0x%02x, authentication "
		    "0x%02x", bdaddr_ntoa((const struct bdaddr *)p), p[6],
		    p[8]);
		break;
	case HCI_EVT_USER_CONFIRM_REQUEST:
		if (len < 6)
			return;
		hci_cmd(HCI_CMD_USER_CONFIRM_REPLY, p, 6, NULL, NULL);
		break;
	case HCI_EVT_SSP_COMPLETE:
		if (len < 7)
			return;
		if (p[0] != 0)
			log_warnx("%s: pairing failed: 0x%02x",
			    bdaddr_ntoa((const struct bdaddr *)(p + 1)), p[0]);
		break;
	case HCI_EVT_LINK_KEY_NOTIFICATION:
		if (len < 23)
			return;
		memset(&nb, 0, sizeof(nb));
		nb.type = BOND_BR;
		memcpy(nb.addr.b, p, 6);
		memcpy(nb.linkkey, p + 6, 16);
		nb.linkkey_type = p[22];
		bond_store(&nb);
		explicit_bzero(&nb, sizeof(nb));
		log_info("%s: paired, link key type %u stored",
		    bdaddr_ntoa((const struct bdaddr *)p), p[22]);
		break;
	case HCI_EVT_AUTH_COMPLETE:
		if (len < 3 || (c = hci_conn_find(get16(p + 1))) == NULL)
			return;
		if (p[0] != 0) {
			log_warnx("%s: authentication failed: 0x%02x",
			    bdaddr_ntoa(&c->peer), p[0]);
			if (p[0] == HCI_ERR_KEY_MISSING &&
			    (b = bond_find(BOND_BR, &c->peer)) != NULL) {
				log_warnx("%s: peer lost the bond, removing it",
				    bdaddr_ntoa(&c->peer));
				bond_delete(b);
			}
			engine_secured(c, 0);
			return;
		}
		put16(rsp, c->handle);
		rsp[2] = 1;
		hci_cmd(HCI_CMD_SET_CONN_ENCRYPTION, rsp, 3, NULL, NULL);
		break;
	}
}

void
ssp_encryption_changed(struct hci_conn *c, uint8_t status, int on)
{
	if (c->dev == NULL || c->dev->state != DEV_SECURING)
		return;
	engine_secured(c, status == 0 && on);
}
