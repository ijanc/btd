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

#define	RTK_MANUFACTURER	0x005d
#define	RTK_ROM_LMP_8761A	0x8761
#define	RTK_FRAGMENT		252
#define	RTK_EPATCH_HDR		14
#define	RTK_DROP_DELAY		200

static const uint8_t	 rtk_signature[8] = "Realtech";
static const uint8_t	 rtk_ext_signature[4] = { 0x51, 0x04, 0xfd, 0x77 };

static int		 rtk_parse(uint32_t *, int *);
static int		 rtk_patch(int);
static void		 rtk_dropped(void *, uint8_t, const uint8_t *, size_t);
static void		 rtk_rom_version(void *, uint8_t, const uint8_t *,
			    size_t);
static void		 rtk_fragment(void *, uint8_t, const uint8_t *, size_t);
static void		 rtk_done(void *, uint8_t, const uint8_t *, size_t);
static void		 rtk_reset(void *, uint8_t, const uint8_t *, size_t);

static int		 rtk_tried;
static uint32_t		 rtk_version;
static uint8_t		*rtk_payload;
static size_t		 rtk_len;

static int
rtk_parse(uint32_t *version, int *project)
{
	struct engine_fw	*fw = &engine_state.fw;
	size_t			 off;
	uint8_t			 len, op;

	*project = -1;
	if (fw->len < RTK_EPATCH_HDR + sizeof(rtk_ext_signature) ||
	    memcmp(fw->buf, rtk_signature, sizeof(rtk_signature)) != 0 ||
	    memcmp(fw->buf + fw->len - sizeof(rtk_ext_signature),
	    rtk_ext_signature, sizeof(rtk_ext_signature)) != 0)
		return (-1);

	off = fw->len - sizeof(rtk_ext_signature);
	while (off >= RTK_EPATCH_HDR + 2) {
		len = fw->buf[off - 2];
		op = fw->buf[off - 1];
		off -= 2;
		if (op == 0xff)
			break;
		if (len == 0)
			return (-1);
		if (op == 0 && len == 1) {
			*project = fw->buf[off - 1];
			break;
		}
		if (off < len)
			return (-1);
		off -= len;
	}
	if (*project == -1)
		return (-1);
	*version = get32(fw->buf + 8);
	return (0);
}

int
rtk_needed(void)
{
	uint32_t	 version;
	int		 project;

	if (hci.manufacturer != RTK_MANUFACTURER || rtk_tried)
		return (0);
	if (engine_state.fw.len == 0) {
		if (hci.lmp_subver == RTK_ROM_LMP_8761A)
			log_warnx("controller needs firmware, none loaded");
		return (0);
	}
	if (rtk_parse(&version, &project) == -1) {
		log_warnx("firmware: bad epatch file");
		rtk_tried = 1;
		return (0);
	}
	rtk_version = version;
	if (hci.lmp_subver == RTK_ROM_LMP_8761A)
		return (1);
	if (((uint32_t)hci.hci_rev << 16 | hci.lmp_subver) == version) {
		log_info("firmware 0x%08x already loaded", version);
		hci.fw_version = version;
		return (0);
	}
	return (1);
}

void
rtk_load(void)
{
	rtk_tried = 1;
	if (hci.lmp_subver != RTK_ROM_LMP_8761A) {
		log_info("firmware 0x%04x%04x loaded, replacing with 0x%08x",
		    hci.hci_rev, hci.lmp_subver, rtk_version);
		hci_cmd_noreply(HCI_CMD_RTK_DROP_FW, NULL, 0, RTK_DROP_DELAY);
		hci_cmd(HCI_CMD_RESET, NULL, 0, NULL, NULL);
		hci_cmd(HCI_CMD_READ_LOCAL_VERSION, NULL, 0, rtk_dropped,
		    NULL);
		return;
	}
	hci_cmd(HCI_CMD_RTK_READ_ROM_VERSION, NULL, 0, rtk_rom_version, NULL);
}

static void
rtk_dropped(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	if (status != 0 || len < 8 || get16(rp + 6) != RTK_ROM_LMP_8761A) {
		log_warnx("firmware: controller did not drop its firmware");
		hci_start();
		return;
	}
	hci_cmd(HCI_CMD_RTK_READ_ROM_VERSION, NULL, 0, rtk_rom_version, NULL);
}

static int
rtk_patch(int rom)
{
	struct engine_fw	*fw = &engine_state.fw;
	struct engine_fw	*cfg = &engine_state.fwconfig;
	size_t			 i, n, tab, plen, poff;

	n = get16(fw->buf + 12);
	tab = RTK_EPATCH_HDR;
	if (tab + 8 * n > fw->len)
		return (-1);
	for (i = 0; i < n; i++) {
		if (get16(fw->buf + tab + 2 * i) != rom + 1)
			continue;
		plen = get16(fw->buf + tab + 2 * n + 2 * i);
		poff = get32(fw->buf + tab + 4 * n + 4 * i);
		if (plen < 4 || poff + plen > fw->len)
			return (-1);
		rtk_len = plen + cfg->len;
		if ((rtk_payload = malloc(rtk_len)) == NULL)
			fatal(NULL);
		memcpy(rtk_payload, fw->buf + poff, plen - 4);
		put32(rtk_payload + plen - 4, rtk_version);
		if (cfg->len > 0)
			memcpy(rtk_payload + plen, cfg->buf, cfg->len);
		return (0);
	}
	return (-1);
}

static void
rtk_rom_version(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	uint8_t		 p[1 + RTK_FRAGMENT];
	size_t		 i, nfrag, off, n;

	if (status != 0 || len < 1) {
		log_warnx("firmware: cannot read ROM version");
		hci_start();
		return;
	}
	if (rtk_patch(rp[0]) == -1) {
		log_warnx("firmware: no patch for ROM version %u", rp[0]);
		hci_start();
		return;
	}
	nfrag = (rtk_len + RTK_FRAGMENT - 1) / RTK_FRAGMENT;
	log_info("firmware 0x%08x: ROM version %u, %zu bytes in %zu "
	    "fragments", rtk_version, rp[0], rtk_len, nfrag);
	for (i = 0; i < nfrag; i++) {
		off = i * RTK_FRAGMENT;
		n = rtk_len - off;
		if (n > RTK_FRAGMENT)
			n = RTK_FRAGMENT;
		p[0] = i > 0x7f ? (i & 0x7f) + 1 : i;
		if (i == nfrag - 1)
			p[0] |= 0x80;
		memcpy(p + 1, rtk_payload + off, n);
		hci_cmd(HCI_CMD_RTK_DOWNLOAD, p, 1 + n, rtk_fragment,
		    i == nfrag - 1 ? &rtk_len : NULL);
	}
	free(rtk_payload);
	rtk_payload = NULL;
}

static void
rtk_fragment(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	if (status != 0)
		fatalx("firmware download failed: 0x%02x", status);
	if (arg == NULL)
		return;
	hci_cmd(HCI_CMD_RTK_READ_ROM_VERSION, NULL, 0, rtk_done, NULL);
}

static void
rtk_done(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	if (status == 0 && len >= 1)
		log_debug("firmware: ROM version %u after download", rp[0]);
	hci.fw_version = rtk_version;
	hci_cmd(HCI_CMD_RESET, NULL, 0, rtk_reset, NULL);
}

static void
rtk_reset(void *arg, uint8_t status, const uint8_t *rp, size_t len)
{
	log_info("firmware 0x%08x loaded", rtk_version);
	hci_start();
}
