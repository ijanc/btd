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

struct hid_conf {
	TAILQ_ENTRY(hid_conf)	 entry;
	struct bdaddr		 addr;
};

struct headset_conf {
	struct bdaddr		 addr;
	int			 rate;
	int			 bitpool;
};

struct btd_conf {
	char			 name[BTD_NAMELEN];
	char			 device[16];
	char			 firmware[BTD_NAMELEN];
	TAILQ_HEAD(, hid_conf)	 hid_list;
	struct headset_conf	*headset;
};

#define	BOND_LE		1
#define	BOND_BR		2

#define	BOND_F_AUTH	0x01
#define	BOND_F_SC	0x02
#define	BOND_F_IRK	0x04
#define	BOND_F_LTK	0x08

/* bus.c */
void		 bus(int, int);

/* frontend.c */
void		 frontend(int, int);
int		 frontend_imsg_compose_main(int, pid_t, void *, uint16_t);
int		 frontend_imsg_compose_engine(int, pid_t, void *, uint16_t);

/* engine */

#define	HCI_PKT_CMD			0x01
#define	HCI_PKT_ACL			0x02
#define	HCI_PKT_EVT			0x04

#define	HCI_CMD_INQUIRY_CANCEL		0x0402
#define	HCI_CMD_CREATE_CONN		0x0405
#define	HCI_CMD_DISCONNECT		0x0406
#define	HCI_CMD_ACCEPT_CONN		0x0409
#define	HCI_CMD_REJECT_CONN		0x040a
#define	HCI_CMD_LINK_KEY_REPLY		0x040b
#define	HCI_CMD_LINK_KEY_NEG_REPLY	0x040c
#define	HCI_CMD_PIN_CODE_NEG_REPLY	0x040e
#define	HCI_CMD_AUTH_REQUESTED		0x0411
#define	HCI_CMD_SET_CONN_ENCRYPTION	0x0413
#define	HCI_CMD_REMOTE_NAME_REQUEST	0x0419
#define	HCI_CMD_READ_REMOTE_FEATURES	0x041b
#define	HCI_CMD_IO_CAP_REPLY		0x042b
#define	HCI_CMD_USER_CONFIRM_REPLY	0x042c
#define	HCI_CMD_USER_CONFIRM_NEG_REPLY	0x042d
#define	HCI_CMD_IO_CAP_NEG_REPLY	0x0434
#define	HCI_CMD_SWITCH_ROLE		0x080b
#define	HCI_CMD_WRITE_LINK_POLICY	0x080d
#define	HCI_CMD_SET_EVENT_MASK		0x0c01
#define	HCI_CMD_RESET			0x0c03
#define	HCI_CMD_WRITE_LOCAL_NAME	0x0c13
#define	HCI_CMD_WRITE_SCAN_ENABLE	0x0c1a
#define	HCI_CMD_WRITE_CLASS_OF_DEVICE	0x0c24
#define	HCI_CMD_WRITE_INQUIRY_SCAN_TYPE	0x0c43
#define	HCI_CMD_WRITE_PAGE_SCAN_TYPE	0x0c47
#define	HCI_CMD_WRITE_SSP_MODE		0x0c56
#define	HCI_CMD_WRITE_LE_HOST_SUPPORT	0x0c6d
#define	HCI_CMD_WRITE_SC_HOST_SUPPORT	0x0c7a
#define	HCI_CMD_READ_LOCAL_VERSION	0x1001
#define	HCI_CMD_READ_LOCAL_COMMANDS	0x1002
#define	HCI_CMD_READ_LOCAL_EXT_FEATURES	0x1004
#define	HCI_CMD_READ_BUFFER_SIZE	0x1005
#define	HCI_CMD_READ_BDADDR		0x1009
#define	HCI_CMD_LE_SET_EVENT_MASK	0x2001
#define	HCI_CMD_LE_READ_BUFFER_SIZE	0x2002
#define	HCI_CMD_LE_READ_LOCAL_FEATURES	0x2003
#define	HCI_CMD_LE_SET_RANDOM_ADDR	0x2005
#define	HCI_CMD_LE_SET_SCAN_PARAMS	0x200b
#define	HCI_CMD_LE_SET_SCAN_ENABLE	0x200c
#define	HCI_CMD_LE_CREATE_CONN		0x200d
#define	HCI_CMD_LE_CREATE_CONN_CANCEL	0x200e
#define	HCI_CMD_LE_CONN_UPDATE		0x2013
#define	HCI_CMD_LE_START_ENCRYPTION	0x2019
#define	HCI_CMD_LE_LTK_REPLY		0x201a
#define	HCI_CMD_LE_LTK_NEG_REPLY	0x201b
#define	HCI_CMD_LE_READ_DEFAULT_DATA_LEN 0x2023
#define	HCI_CMD_LE_WRITE_DEFAULT_DATA_LEN 0x2024
#define	HCI_CMD_LE_READ_MAX_ADV_DATA_LEN 0x203a
#define	HCI_CMD_LE_READ_NUM_ADV_SETS	0x203b
#define	HCI_CMD_LE_SET_EXT_SCAN_PARAMS	0x2041
#define	HCI_CMD_LE_SET_EXT_SCAN_ENABLE	0x2042
#define	HCI_CMD_LE_EXT_CREATE_CONN	0x2043
#define	HCI_CMD_RTK_DOWNLOAD		0xfc20
#define	HCI_CMD_RTK_DROP_FW		0xfc66
#define	HCI_CMD_RTK_READ_ROM_VERSION	0xfc6d

#define	HCI_EVT_CONN_COMPLETE		0x03
#define	HCI_EVT_CONN_REQUEST		0x04
#define	HCI_EVT_DISCONN_COMPLETE	0x05
#define	HCI_EVT_AUTH_COMPLETE		0x06
#define	HCI_EVT_REMOTE_NAME		0x07
#define	HCI_EVT_ENCRYPTION_CHANGE	0x08
#define	HCI_EVT_CMD_COMPLETE		0x0e
#define	HCI_EVT_CMD_STATUS		0x0f
#define	HCI_EVT_HW_ERROR		0x10
#define	HCI_EVT_ROLE_CHANGE		0x12
#define	HCI_EVT_NUM_COMPLETED		0x13
#define	HCI_EVT_MODE_CHANGE		0x14
#define	HCI_EVT_PIN_CODE_REQUEST	0x16
#define	HCI_EVT_LINK_KEY_REQUEST	0x17
#define	HCI_EVT_LINK_KEY_NOTIFICATION	0x18
#define	HCI_EVT_ENCRYPTION_KEY_REFRESH	0x30
#define	HCI_EVT_IO_CAP_REQUEST		0x31
#define	HCI_EVT_IO_CAP_RESPONSE		0x32
#define	HCI_EVT_USER_CONFIRM_REQUEST	0x33
#define	HCI_EVT_SSP_COMPLETE		0x36
#define	HCI_EVT_LE_META			0x3e

#define	HCI_LE_CONN_COMPLETE		0x01
#define	HCI_LE_ADV_REPORT		0x02
#define	HCI_LE_CONN_UPDATE_COMPLETE	0x03
#define	HCI_LE_LTK_REQUEST		0x05
#define	HCI_LE_ENH_CONN_COMPLETE	0x0a
#define	HCI_LE_EXT_ADV_REPORT		0x0d

#define	HCI_ERR_PAGE_TIMEOUT		0x04
#define	HCI_ERR_AUTH_FAILURE		0x05
#define	HCI_ERR_KEY_MISSING		0x06
#define	HCI_ERR_CONN_TIMEOUT		0x08
#define	HCI_ERR_TIMEOUT			0xff
#define	HCI_ERR_REMOTE_USER		0x13
#define	HCI_ERR_LOCAL_HOST		0x16
#define	HCI_ERR_UNKNOWN_CONN		0x02
#define	HCI_ERR_LIMITED_RESOURCES	0x0d
#define	HCI_ERR_PAIRING_NOT_ALLOWED	0x18

#define	HCI_SCAN_INQUIRY		0x01
#define	HCI_SCAN_PAGE			0x02

#define	HCI_PB_START_HOST		0x00
#define	HCI_PB_CONT			0x01
#define	HCI_PB_START			0x02

#define	LINK_BR				1
#define	LINK_LE				2

#define	HCI_S_DOWN			0
#define	HCI_S_INIT			1
#define	HCI_S_FIRMWARE			2
#define	HCI_S_RUNNING			3

#define	L2CAP_CID_SIGNAL		0x0001
#define	L2CAP_CID_ATT			0x0004
#define	L2CAP_CID_LE_SIGNAL		0x0005
#define	L2CAP_CID_SMP			0x0006
#define	L2CAP_CID_DYN			0x0040

#define	L2CAP_PSM_SDP			0x0001
#define	L2CAP_PSM_AVCTP			0x0017
#define	L2CAP_PSM_AVDTP			0x0019

typedef void	(*hci_cb)(void *, uint8_t, const uint8_t *, size_t);

struct engine_fw {
	uint8_t			*buf;
	size_t			 len;
	size_t			 size;
};

struct engine_state {
	struct btd_conf		*conf;
	struct bond_list	 bonds;
	struct bond_local	 local;
	int			 have_local;
	int			 kbdtype;
	struct engine_fw	 fw;
	struct engine_fw	 fwconfig;
};

struct hci_state {
	int			 state;
	int			 ncmd;
	uint8_t			 hci_ver;
	uint16_t		 hci_rev;
	uint8_t			 lmp_ver;
	uint16_t		 lmp_subver;
	uint16_t		 manufacturer;
	uint32_t		 fw_version;
	uint8_t			 commands[64];
	uint8_t			 features[3][8];
	uint8_t			 le_features[8];
	struct bdaddr		 bdaddr;
	struct bdaddr		 random;
	uint16_t		 acl_len;
	uint16_t		 acl_num;
	uint16_t		 le_acl_len;
	uint16_t		 le_acl_num;
	int			 acl_free;
	int			 le_acl_free;
	int			 ext_scan;
	int			 coded_phy;
	int			 scan_want;
	int			 scanning;
};

#define	ATT_OP_ERROR_RSP		0x01
#define	ATT_OP_MTU_REQ			0x02
#define	ATT_OP_MTU_RSP			0x03
#define	ATT_OP_FIND_INFO_REQ		0x04
#define	ATT_OP_FIND_BY_TYPE_REQ		0x06
#define	ATT_OP_READ_BY_TYPE_REQ		0x08
#define	ATT_OP_READ_REQ			0x0a
#define	ATT_OP_READ_BLOB_REQ		0x0c
#define	ATT_OP_READ_BY_GROUP_REQ	0x10
#define	ATT_OP_WRITE_REQ		0x12
#define	ATT_OP_NOTIFY			0x1b
#define	ATT_OP_INDICATE			0x1d
#define	ATT_OP_CONFIRM			0x1e
#define	ATT_OP_COMMAND			0x40

#define	ATT_ERR_INVALID_HANDLE		0x01
#define	ATT_ERR_NOT_SUPPORTED		0x06
#define	ATT_ERR_INVALID_OFFSET		0x07
#define	ATT_ERR_NOT_FOUND		0x0a
#define	ATT_ERR_UNLIKELY		0x0e

#define	L2CAP_S_WAIT_CONNECT		1
#define	L2CAP_S_CONFIG			2
#define	L2CAP_S_OPEN			3
#define	L2CAP_S_WAIT_DISCONNECT		4

#define	DEV_HID				1
#define	DEV_HEADSET			2

#define	DEV_IDLE			0
#define	DEV_WAIT			1
#define	DEV_CONNECTING			2
#define	DEV_SECURING			3
#define	DEV_SETUP			4
#define	DEV_READY			5

#define	DEV_HID_RETRY			1
#define	DEV_HEADSET_RETRY		3
#define	DEV_LE_CONNECT_TIMEOUT		3

struct l2cap_chan;
struct hci_conn;
struct smp;
struct att;
struct hid;

struct l2cap_proto {
	uint16_t		 psm;
	void			*(*accept)(struct hci_conn *);
	void			 (*open)(struct l2cap_chan *);
	void			 (*input)(struct l2cap_chan *,
				    const uint8_t *, size_t);
	void			 (*close)(struct l2cap_chan *);
};

struct l2cap_chan {
	TAILQ_ENTRY(l2cap_chan)	 entry;
	struct hci_conn		*conn;
	uint16_t		 psm;
	uint16_t		 lcid;
	uint16_t		 rcid;
	uint16_t		 imtu;
	uint16_t		 omtu;
	int			 state;
	int			 cfg;
	uint8_t			 ident;
	struct event		 timer;
	const struct l2cap_proto *proto;
	void			*arg;
};

struct device {
	TAILQ_ENTRY(device)	 entry;
	int			 kind;
	struct bdaddr		 addr;
	int			 state;
	int			 removed;
	struct hci_conn		*conn;
	struct event		 retry;
	int			 passkey;
	char			 info[128];
	struct headset_conf	 hs;
	void			*proto;
};

typedef void	(*att_cb)(void *, uint8_t, const uint8_t *, size_t);
typedef void	(*att_notify_cb)(void *, uint16_t, const uint8_t *, size_t);

TAILQ_HEAD(l2cap_chan_list, l2cap_chan);

struct hci_conn {
	TAILQ_ENTRY(hci_conn)	 entry;
	uint16_t		 handle;
	int			 link;
	int			 role;
	struct bdaddr		 peer;
	uint8_t			 peer_type;
	struct device		*dev;
	int			 encrypted;
	int			 disconnecting;
	int			 inflight;
	int			 queued;
	uint16_t		 le_interval;
	uint16_t		 le_latency;
	uint16_t		 le_timeout;
	uint8_t			*rx;
	size_t			 rxlen;
	size_t			 rxwant;
	struct l2cap_chan_list	 chans;
	uint8_t			 sig_ident;
	uint16_t		 next_cid;
	struct smp		*smp;
	struct att		*att;
};

TAILQ_HEAD(hci_conn_list, hci_conn);

extern struct engine_state	 engine_state;
extern struct hci_state		 hci;
extern struct hci_conn_list	 hci_conns;

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

/* hci.c */
void		 hci_start(void);
void		 hci_cmd(uint16_t, const void *, size_t, hci_cb, void *);
void		 hci_cmd_noreply(uint16_t, const void *, size_t, int);
void		 hci_input_event(const uint8_t *, size_t);
void		 hci_input_acl(const uint8_t *, size_t);
struct hci_conn	*hci_conn_find(uint16_t);
struct hci_conn	*hci_conn_find_addr(int, const struct bdaddr *);
void		 hci_disconnect(struct hci_conn *, uint8_t);
void		 hci_acl_send(struct hci_conn *, const uint8_t *, size_t);
int		 hci_acl_pending(int);
void		 hci_scan(int);
void		 hci_le_connect(const struct bdaddr *, uint8_t);
void		 hci_le_connect_cancel(void);
void		 hci_br_connect(const struct bdaddr *);
uint16_t	 get16(const uint8_t *);
uint32_t	 get32(const uint8_t *);
uint64_t	 get64(const uint8_t *);
void		 put16(uint8_t *, uint16_t);
void		 put32(uint8_t *, uint32_t);
void		 put64(uint8_t *, uint64_t);

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

/* parse.y */
struct btd_conf	*parse_config(const char *);

/* printconf.c */
void		 print_config(struct btd_conf *);
