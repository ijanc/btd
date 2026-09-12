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
#include <poll.h>
#include <sndio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "btd.h"

#define	AUDIO_MON		"snd/mon"
#define	AUDIO_CTL		"snd/default"
#define	AUDIO_RETRY		2
#define	AUDIO_MAXFRAME		512
#define	AUDIO_MAXCHAN		8

struct audio {
	struct sio_hdl		*hdl;
	struct event		 ev;
	struct event		 retry;
	struct audio_params	 params;
	int			 wanted;
	struct sbc		 sbc;
	int16_t			*pcm;
	size_t			 need;
	size_t			 have;
};

struct volume_ctl {
	unsigned int		 addr;
	unsigned int		 val;
};

struct volume {
	struct sioctl_hdl	*hdl;
	struct event		 ev;
	struct event		 retry;
	struct volume_ctl	 level[AUDIO_MAXCHAN];
	struct volume_ctl	 mute[AUDIO_MAXCHAN];
	int			 nlevel;
	int			 nmute;
	unsigned int		 maxval;
};

static void	 audio_open(void);
static void	 audio_close(void);
static void	 audio_arm(void);
static void	 audio_cb(int, short, void *);
static void	 audio_retry(int, short, void *);
static void	 volume_open(void);
static void	 volume_close(void);
static void	 volume_arm(void);
static void	 volume_cb(int, short, void *);
static void	 volume_retry(int, short, void *);
static void	 volume_ondesc(void *, struct sioctl_desc *, int);
static void	 volume_onval(void *, unsigned int, unsigned int);
static void	 volume_report(void);

static struct audio	 audio;
static struct volume	 volume;

void
audio_init(void)
{
	evtimer_set(&audio.retry, audio_retry, NULL);
	evtimer_set(&volume.retry, volume_retry, NULL);
	volume_open();
}

void
audio_start(struct audio_params *par)
{
	audio_stop();
	if (sbc_init(&audio.sbc, par) == -1) {
		log_warnx("unsupported audio parameters");
		return;
	}
	audio.params = *par;
	audio.need = sbc_frame_samples() * par->channels;
	if ((audio.pcm = reallocarray(NULL, audio.need,
	    sizeof(*audio.pcm))) == NULL)
		fatal(NULL);
	audio.have = 0;
	audio.wanted = 1;
	audio_open();
}

void
audio_stop(void)
{
	audio.wanted = 0;
	evtimer_del(&audio.retry);
	audio_close();
	free(audio.pcm);
	audio.pcm = NULL;
}

static void
audio_open(void)
{
	struct timeval	 tv = { AUDIO_RETRY, 0 };
	struct sio_par	 par;

	if ((audio.hdl = sio_open(AUDIO_MON, SIO_REC, 1)) == NULL) {
		log_debug("%s: cannot open, retrying", AUDIO_MON);
		evtimer_add(&audio.retry, &tv);
		return;
	}
	sio_initpar(&par);
	par.bits = 16;
	par.sig = 1;
	par.le = SIO_LE_NATIVE;
	par.rchan = audio.params.channels;
	par.rate = audio.params.rate;
	par.appbufsz = par.rate / 10;
	if (!sio_setpar(audio.hdl, &par) || !sio_getpar(audio.hdl, &par) ||
	    par.bits != 16 || par.rchan != (unsigned)audio.params.channels ||
	    par.rate != (unsigned)audio.params.rate) {
		log_warnx("%s: cannot record %d Hz stereo", AUDIO_MON,
		    audio.params.rate);
		audio_close();
		evtimer_add(&audio.retry, &tv);
		return;
	}
	if (!sio_start(audio.hdl)) {
		audio_close();
		evtimer_add(&audio.retry, &tv);
		return;
	}
	log_info("%s: recording %u Hz", AUDIO_MON, par.rate);
	audio_arm();
}

static void
audio_close(void)
{
	if (audio.hdl == NULL)
		return;
	if (event_initialized(&audio.ev))
		event_del(&audio.ev);
	sio_close(audio.hdl);
	audio.hdl = NULL;
}

static void
audio_retry(int fd, short event, void *arg)
{
	if (audio.wanted && audio.hdl == NULL)
		audio_open();
}

static void
audio_arm(void)
{
	struct pollfd	 pfd;
	short		 ev = 0;

	if (sio_pollfd(audio.hdl, &pfd, POLLIN) < 1)
		return;
	if (pfd.events & POLLIN)
		ev |= EV_READ;
	if (pfd.events & POLLOUT)
		ev |= EV_WRITE;
	event_set(&audio.ev, pfd.fd, ev, audio_cb, NULL);
	event_add(&audio.ev, NULL);
}

static void
audio_cb(int fd, short event, void *arg)
{
	struct timeval	 tv = { AUDIO_RETRY, 0 };
	struct pollfd	 pfd;
	uint8_t		 frame[AUDIO_MAXFRAME];
	size_t		 n, len;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (event & EV_READ)
		pfd.revents |= POLLIN;
	if (event & EV_WRITE)
		pfd.revents |= POLLOUT;
	if (sio_revents(audio.hdl, &pfd) & POLLIN) {
		for (;;) {
			n = sio_read(audio.hdl, (uint8_t *)audio.pcm +
			    audio.have, (audio.need * sizeof(*audio.pcm)) -
			    audio.have);
			if (n == 0)
				break;
			audio.have += n;
			if (audio.have < audio.need * sizeof(*audio.pcm))
				continue;
			len = sbc_encode(&audio.sbc, audio.pcm, frame);
			frontend_imsg_compose_engine(IMSG_AUDIO_FRAME, 0,
			    frame, len);
			audio.have = 0;
		}
	}
	if (sio_eof(audio.hdl)) {
		log_warnx("%s: lost", AUDIO_MON);
		audio_close();
		evtimer_add(&audio.retry, &tv);
		return;
	}
	audio_arm();
}

void
audio_set_volume(int v)
{
	unsigned int	 val;
	int		 i;

	if (volume.hdl == NULL || volume.nlevel == 0 || v < 0 || v > 127)
		return;
	val = (v * volume.maxval + 63) / 127;
	for (i = 0; i < volume.nlevel; i++)
		sioctl_setval(volume.hdl, volume.level[i].addr, val);
}

static void
volume_open(void)
{
	struct timeval	 tv = { AUDIO_RETRY, 0 };

	volume.nlevel = volume.nmute = 0;
	if ((volume.hdl = sioctl_open(AUDIO_CTL, SIOCTL_READ | SIOCTL_WRITE,
	    1)) == NULL) {
		evtimer_add(&volume.retry, &tv);
		return;
	}
	if (!sioctl_ondesc(volume.hdl, volume_ondesc, NULL) ||
	    !sioctl_onval(volume.hdl, volume_onval, NULL)) {
		volume_close();
		evtimer_add(&volume.retry, &tv);
		return;
	}
	volume_arm();
}

static void
volume_close(void)
{
	if (volume.hdl == NULL)
		return;
	if (event_initialized(&volume.ev))
		event_del(&volume.ev);
	sioctl_close(volume.hdl);
	volume.hdl = NULL;
}

static void
volume_retry(int fd, short event, void *arg)
{
	if (volume.hdl == NULL)
		volume_open();
}

static void
volume_arm(void)
{
	struct pollfd	 pfd;
	short		 ev = 0;

	if (sioctl_pollfd(volume.hdl, &pfd, POLLIN) < 1)
		return;
	if (pfd.events & POLLIN)
		ev |= EV_READ;
	if (pfd.events & POLLOUT)
		ev |= EV_WRITE;
	event_set(&volume.ev, pfd.fd, ev, volume_cb, NULL);
	event_add(&volume.ev, NULL);
}

static void
volume_cb(int fd, short event, void *arg)
{
	struct timeval	 tv = { AUDIO_RETRY, 0 };
	struct pollfd	 pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (event & EV_READ)
		pfd.revents |= POLLIN;
	if (event & EV_WRITE)
		pfd.revents |= POLLOUT;
	sioctl_revents(volume.hdl, &pfd);
	if (sioctl_eof(volume.hdl)) {
		volume_close();
		evtimer_add(&volume.retry, &tv);
		return;
	}
	volume_arm();
}

static void
volume_ondesc(void *arg, struct sioctl_desc *d, int val)
{
	if (d == NULL) {
		volume_report();
		return;
	}
	if (d->group[0] != '\0' || strcmp(d->node0.name, "output") != 0)
		return;
	if (d->type == SIOCTL_NUM && strcmp(d->func, "level") == 0 &&
	    volume.nlevel < AUDIO_MAXCHAN) {
		volume.level[volume.nlevel].addr = d->addr;
		volume.level[volume.nlevel++].val = val;
		volume.maxval = d->maxval;
	} else if (d->type == SIOCTL_SW && strcmp(d->func, "mute") == 0 &&
	    volume.nmute < AUDIO_MAXCHAN) {
		volume.mute[volume.nmute].addr = d->addr;
		volume.mute[volume.nmute++].val = val;
	}
}

static void
volume_onval(void *arg, unsigned int addr, unsigned int val)
{
	int	 i;

	for (i = 0; i < volume.nlevel; i++)
		if (volume.level[i].addr == addr) {
			volume.level[i].val = val;
			volume_report();
			return;
		}
	for (i = 0; i < volume.nmute; i++)
		if (volume.mute[i].addr == addr) {
			volume.mute[i].val = val;
			volume_report();
			return;
		}
}

static void
volume_report(void)
{
	unsigned int	 level = 0;
	int		 i, v, mute = volume.nmute > 0;

	if (volume.nlevel == 0 || volume.maxval == 0)
		return;
	for (i = 0; i < volume.nlevel; i++)
		if (volume.level[i].val > level)
			level = volume.level[i].val;
	for (i = 0; i < volume.nmute; i++)
		if (!volume.mute[i].val)
			mute = 0;
	v = mute ? 0 : (level * 127 + volume.maxval / 2) / volume.maxval;
	frontend_imsg_compose_engine(IMSG_VOLUME_LOCAL, 0, &v, sizeof(v));
}
