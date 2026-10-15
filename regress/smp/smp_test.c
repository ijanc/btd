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

/*
 * Link security checks in smp.c, driven through the HCI and L2CAP calls
 * it makes.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <string.h>

#include "btd.h"

#define	HANDLE		0x0042

struct engine_state	 engine_state;
struct hci_state	 hci;

static struct hci_conn	 conn;
static struct device	 dev;
static struct bond	 bond;
static int		 have_bond, conn_gone;

static uint16_t		 cmd_op;
static uint8_t		 cmd_p[255];
static size_t		 cmd_len;
static hci_cb		 cmd_cb;
static void		*cmd_arg;
static int		 ncmd;
static int		 disconnected;
static uint8_t		 disconnect_reason;
static int		 secured;
static uint8_t		 sent[65];
static size_t		 sentlen;
static int		 failed;

void
hci_cmd(uint16_t op, const void *p, size_t len, hci_cb cb, void *arg)
{
	cmd_op = op;
	memcpy(cmd_p, p, len);
	cmd_len = len;
	cmd_cb = cb;
	cmd_arg = arg;
	ncmd++;
}

struct hci_conn *
hci_conn_find(uint16_t handle)
{
	return (!conn_gone && handle == conn.handle ? &conn : NULL);
}

void
hci_disconnect(struct hci_conn *c, uint8_t reason)
{
	disconnected++;
	disconnect_reason = reason;
}

void
engine_secured(struct hci_conn *c, int ok)
{
	secured = ok ? 1 : -1;
}

void
l2cap_send_fixed(struct hci_conn *c, uint16_t cid, const uint8_t *p,
    size_t len)
{
	if (len > sizeof(sent))
		len = sizeof(sent);
	memcpy(sent, p, len);
	sentlen = len;
}

struct bond *
bond_find(int type, const struct bdaddr *addr)
{
	return (have_bond && type == bond.type ? &bond : NULL);
}

void
bond_store(struct bond *b)
{
}

struct device *
device_find(int kind, const struct bdaddr *addr)
{
	return (&dev);
}

const char *
bdaddr_ntoa(const struct bdaddr *a)
{
	return ("00:00:00:00:00:00");
}

int
bdaddr_cmp(const struct bdaddr *a, const struct bdaddr *b)
{
	return (memcmp(a->b, b->b, sizeof(a->b)));
}

uint16_t
get16(const uint8_t *p)
{
	return (p[0] | p[1] << 8);
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
	int	 i;

	for (i = 0; i < 4; i++)
		p[i] = v >> (8 * i);
}

void
put64(uint8_t *p, uint64_t v)
{
	int	 i;

	for (i = 0; i < 8; i++)
		p[i] = v >> (8 * i);
}

static void
setup(int link, int state)
{
	if (conn.smp != NULL)
		smp_free(&conn);
	memset(&conn, 0, sizeof(conn));
	memset(&dev, 0, sizeof(dev));
	conn.handle = HANDLE;
	conn.link = link;
	conn.dev = &dev;
	dev.kind = link == LINK_LE ? DEV_HID : DEV_HEADSET;
	dev.state = state;
	dev.conn = &conn;
	memset(&bond, 0, sizeof(bond));
	have_bond = conn_gone = 0;
	cmd_op = 0;
	cmd_len = 0;
	cmd_cb = NULL;
	ncmd = disconnected = secured = 0;
	disconnect_reason = 0;
	sentlen = 0;
}

static void
check(const char *name, int cond)
{
	if (cond) {
		printf("%s: ok\n", name);
		return;
	}
	printf("%s: FAILED (op 0x%04x, %d commands, secured %d, "
	    "disconnected %d reason 0x%02x)\n", name, cmd_op, ncmd, secured,
	    disconnected, disconnect_reason);
	failed = 1;
}

/* Encryption Change as engine.c reports it. */
static void
encrypt(uint8_t status, int mode)
{
	if (status == 0)
		conn.encrypted = mode;
	ssp_encryption_changed(&conn, status, mode);
}

static void
br_bond(uint8_t linkkey_type)
{
	have_bond = 1;
	bond.type = BOND_BR;
	bond.linkkey_type = linkkey_type;
}

/* Answer the pending Read Encryption Key Size, if it was sent. */
static int
key_size_reply(uint8_t status, uint8_t size, size_t len)
{
	uint8_t	 rp[3];

	if (cmd_op != HCI_CMD_READ_ENC_KEY_SIZE || cmd_len != 2 ||
	    get16(cmd_p) != HANDLE || cmd_cb == NULL)
		return (0);
	put16(rp, HANDLE);
	rp[2] = size;
	cmd_cb(cmd_arg, status, rp, len);
	return (1);
}

static void
test_br_key_size(void)
{
	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	check("br securing waits for the key size", secured == 0 &&
	    cmd_op == HCI_CMD_READ_ENC_KEY_SIZE);
	check("br securing key size 16", key_size_reply(0, 16, 3) &&
	    secured == 1 && disconnected == 0);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	check("br securing key size 15", key_size_reply(0, 15, 3) &&
	    secured != 1 && disconnected == 1 &&
	    disconnect_reason == HCI_ERR_AUTH_FAILURE);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	check("br securing key size 1", key_size_reply(0, 1, 3) &&
	    secured != 1 && disconnected == 1);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	check("br key size command failed", key_size_reply(0x01, 16, 3) &&
	    secured != 1 && disconnected == 1);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	check("br key size reply short", key_size_reply(0, 16, 2) &&
	    secured != 1 && disconnected == 1);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	conn_gone = 1;
	check("br connection gone before the reply",
	    key_size_reply(0, 16, 3) && secured == 0 && disconnected == 0);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	conn.encrypted = 0;
	check("br reply for a new link on the same handle",
	    key_size_reply(0, 16, 3) && secured == 0 && disconnected == 0);

	setup(LINK_BR, DEV_SECURING);
	encrypt(0, 1);
	conn.encrypted = 0;
	check("br failure for a new link on the same handle",
	    key_size_reply(0x02, 0, 3) && secured == 0 && disconnected == 0);

	setup(LINK_BR, DEV_SECURING);
	encrypt(HCI_ERR_AUTH_FAILURE, 0);
	check("br encryption failed", ncmd == 0 && secured == -1);

	setup(LINK_BR, DEV_READY);
	encrypt(0, 1);
	check("br ready re-encrypted key size 16",
	    key_size_reply(0, 16, 3) && secured == 0 && disconnected == 0);

	setup(LINK_BR, DEV_READY);
	encrypt(0, 1);
	check("br ready re-encrypted key size 7",
	    key_size_reply(0, 7, 3) && secured == 0 && disconnected == 1 &&
	    disconnect_reason == HCI_ERR_AUTH_FAILURE);
}

static void
test_br_cipher(void)
{
	setup(LINK_BR, DEV_SECURING);
	br_bond(7);
	encrypt(0, 1);
	check("br sc key with e0 refused", ncmd == 0 && secured != 1 &&
	    disconnected == 1 && disconnect_reason == HCI_ERR_AUTH_FAILURE);

	setup(LINK_BR, DEV_SECURING);
	br_bond(8);
	encrypt(0, 1);
	check("br authenticated sc key with e0 refused", ncmd == 0 &&
	    secured != 1 && disconnected == 1);

	setup(LINK_BR, DEV_SECURING);
	br_bond(7);
	encrypt(0, 2);
	check("br sc key with aes-ccm", key_size_reply(0, 16, 3) &&
	    secured == 1 && disconnected == 0);

	setup(LINK_BR, DEV_SECURING);
	br_bond(4);
	encrypt(0, 1);
	check("br p-192 key with e0", key_size_reply(0, 16, 3) &&
	    secured == 1 && disconnected == 0);

	setup(LINK_BR, DEV_SECURING);
	br_bond(5);
	encrypt(0, 1);
	check("br authenticated p-192 key with e0",
	    key_size_reply(0, 16, 3) && secured == 1 && disconnected == 0);

	setup(LINK_BR, DEV_READY);
	br_bond(7);
	encrypt(0, 1);
	check("br ready sc key re-encrypted with e0", ncmd == 0 &&
	    secured == 0 && disconnected == 1 &&
	    disconnect_reason == HCI_ERR_AUTH_FAILURE);
}

/*
 * SMP codes: 0x01 Pairing Request, 0x02 Pairing Response, 0x05 Pairing
 * Failed (0x06 Encryption Key Size), 0x0c Pairing Public Key.
 */
static void
le_pairing_rsp(uint8_t keysize)
{
	/* No input no output, bonding and Secure Connections, keys ID. */
	uint8_t	 rsp[7] = { 0x02, 0x03, 0x00, 0x09, 0, 0x02, 0x02 };

	rsp[4] = keysize;
	smp_input(&conn, rsp, sizeof(rsp));
}

static void
test_le_key_size(void)
{
	setup(LINK_LE, DEV_SECURING);
	smp_le_secure(&conn);
	check("le pairing request asks for 16", sentlen == 7 &&
	    sent[0] == 0x01 && sent[4] == 16);
	le_pairing_rsp(15);
	check("le pairing response key size 15", sentlen == 2 &&
	    sent[0] == 0x05 && sent[1] == 0x06 && secured == -1);

	setup(LINK_LE, DEV_SECURING);
	smp_le_secure(&conn);
	le_pairing_rsp(7);
	check("le pairing response key size 7", sentlen == 2 &&
	    sent[0] == 0x05 && sent[1] == 0x06 && secured == -1);

	setup(LINK_LE, DEV_SECURING);
	smp_le_secure(&conn);
	le_pairing_rsp(16);
	check("le pairing response key size 16", secured == 0 &&
	    sent[0] == 0x0c);

	setup(LINK_LE, DEV_SECURING);
	have_bond = 1;
	bond.type = BOND_LE;
	bond.flags = BOND_F_LTK | BOND_F_SC;
	bond.keysize = 16;
	smp_le_secure(&conn);
	check("le bond key size 16 encrypts",
	    cmd_op == HCI_CMD_LE_START_ENCRYPTION && secured == 0);

	setup(LINK_LE, DEV_SECURING);
	have_bond = 1;
	bond.type = BOND_LE;
	bond.flags = BOND_F_LTK | BOND_F_SC;
	bond.keysize = 7;
	smp_le_secure(&conn);
	check("le bond key size 7 refused", ncmd == 0 && secured == -1);
}

int
main(void)
{
	event_init();
	test_br_key_size();
	test_br_cipher();
	test_le_key_size();
	if (conn.smp != NULL)
		smp_free(&conn);
	return (failed);
}
