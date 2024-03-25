/*
 * Copyright (c) 2024 Murilo Ijanc <murilo@ijanc.org>
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

#ifndef nitems
#define	nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define	_PATH_CONF_FILE		"/etc/btd.conf"
#define	_PATH_LOCKFILE		"/dev/btd.lock"
#define	_PATH_BTD_SOCKET	"/dev/btd.sock"
#define	_PATH_BTD_DB		"/var/db/btd"
#define	_PATH_BONDS		"/var/db/btd/bonds"
#define	_PATH_FIRMWARE		"/etc/firmware"
#define	_PATH_WSMOUSE		"/dev/wsmouse"
#define	_PATH_WSKBD		"/dev/wskbd0"
#define	_PATH_WSCFG		"/dev/ttyCcfg"
#define	_PATH_SNDIO_SOCKDIR	"/tmp/sndio"
#define	_PATH_SNDIO_COOKIEDIR	"/var/db/btd/.sndio"
#define	BTD_USER		"_btd"

#define	BTD_MAXHID		8
#define	BTD_FWCHUNK		8192
#define	BTD_MAXEVENTS		64
#define	BTD_NAMELEN		64

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_LOG_VERBOSE,
	IMSG_CTL_RELOAD,
	IMSG_CTL_SHOW_CONTROLLER,
	IMSG_CTL_SHOW_DEVICES,
	IMSG_CTL_SHOW_BONDS,
	IMSG_CTL_CONTROLLER,
	IMSG_CTL_DEVICE,
	IMSG_CTL_BOND,
	IMSG_CTL_END,
	IMSG_SOCKET_IPC,
	IMSG_SOCKET_BUS,
	IMSG_CONTROLFD,
	IMSG_DEVFD_CTL,
	IMSG_DEVFD_INTR,
	IMSG_DEVFD_BULK,
	IMSG_DEVFD_WSCFG,
	IMSG_KBDTYPE,
	IMSG_FIRMWARE,
	IMSG_FIRMWARE_CONFIG,
	IMSG_FIRMWARE_END,
	IMSG_BOND,
	IMSG_BOND_LOCAL,
	IMSG_BOND_SAVE,
	IMSG_BOND_DELETE,
	IMSG_BOND_LOCAL_SAVE,
	IMSG_BONDS_END,
	IMSG_RECONF_CONF,
	IMSG_RECONF_HID,
	IMSG_RECONF_HEADSET,
	IMSG_RECONF_END,
	IMSG_STARTUP,
	IMSG_HCI_CMD,
	IMSG_HCI_ACL,
	IMSG_HCI_EVT,
	IMSG_HCI_ACLDATA,
	IMSG_WSKBD,
	IMSG_WSMOUSE,
	IMSG_AUDIO_START,
	IMSG_AUDIO_STOP,
	IMSG_AUDIO_FRAME,
	IMSG_VOLUME_LOCAL,
	IMSG_VOLUME_REMOTE,
};

struct bdaddr {
	uint8_t		 b[6];
};

#define	BDADDR_PUBLIC	0
#define	BDADDR_RANDOM	1

/* bus.c */
void		 bus(int, int);

/* frontend.c */
void		 frontend(int, int);
int		 frontend_imsg_compose_main(int, pid_t, void *, uint16_t);
int		 frontend_imsg_compose_engine(int, pid_t, void *, uint16_t);

/* engine.c */
void		 engine(int, int);
int		 engine_imsg_compose_main(int, void *, uint16_t);
int		 engine_imsg_compose_bus(int, void *, uint16_t);
int		 engine_imsg_compose_frontend(int, pid_t, void *, uint16_t);
void		 engine_show_controller(pid_t);
void		 engine_show_devices(pid_t);
void		 engine_show_bonds(pid_t);
void		 engine_local_identity(struct bdaddr *);
void		 engine_ready(void);
void		 engine_scan_changed(void);
void		 engine_adv_report(const struct bdaddr *, uint8_t, int, int,
		     const uint8_t *, size_t);
void		 engine_create_status(void *, uint8_t, const uint8_t *,
		     size_t);
void		 engine_conn_up(struct hci_conn *);
void		 engine_conn_down(struct hci_conn *, uint8_t);
void		 engine_conn_failed(int, const struct bdaddr *, uint8_t);
void		 engine_hci_event(uint8_t, const uint8_t *, size_t);
void		 engine_le_event(uint8_t, const uint8_t *, size_t);
void		 engine_schedule(void);
void		 engine_release(struct device *);
void		 engine_secured(struct hci_conn *, int);
void		 device_reconf(void);
void		 device_state(struct device *, int);
struct device	*device_find(int, const struct bdaddr *);

/* btd.c */
void		 imsg_event_add(struct imsgev *);
int		 imsg_compose_event(struct imsgev *, uint16_t, uint32_t,
		     pid_t, int, void *, uint16_t);
int		 imsg_forward_event(struct imsgev *, struct imsg *);
const char	*i2s(uint32_t);
const char	*bdaddr_ntoa(const struct bdaddr *);
int		 bdaddr_aton(const char *, struct bdaddr *);
int		 bdaddr_cmp(const struct bdaddr *, const struct bdaddr *);
struct btd_conf	*config_new_empty(void);
void		 config_clear(struct btd_conf *);

