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

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "btd.h"

#define	SECONDS		5
#define	MAXDELAY	400

__dead void	 usage(void);
void		 encode(int, int, int, const char *, const char *);
void		 compare(const char *, const char *, double);
int16_t		*load(const char *, size_t *);

__dead void
usage(void)
{
	fprintf(stderr, "usage: sbc_test encode rate bitpool snr|loudness "
	    "pcm sbc\n       sbc_test compare pcm decoded min_snr\n");
	exit(2);
}

void
encode(int rate, int bitpool, int alloc, const char *pcmfile,
    const char *sbcfile)
{
	struct audio_params	 par;
	struct sbc		 sbc;
	FILE			*pf, *sf;
	int16_t			*pcm;
	uint8_t			 frame[512];
	size_t			 n, i, step, len;
	double			 t;
	uint32_t		 seed;

	memset(&par, 0, sizeof(par));
	par.rate = rate;
	par.channels = 2;
	par.mode = SBC_MODE_STEREO;
	par.blocks = 16;
	par.subbands = 8;
	par.alloc = alloc;
	par.bitpool = bitpool;
	if (sbc_init(&sbc, &par) == -1)
		errx(1, "sbc_init");

	step = sbc_frame_samples();
	n = (rate * SECONDS) / step * step;
	if ((pcm = calloc(n * 2, sizeof(*pcm))) == NULL)
		err(1, NULL);
	seed = 1;
	for (i = 0; i < n; i++) {
		t = (double)i / rate;
		pcm[2 * i] = 9000 * sin(2 * M_PI * 440 * t) +
		    4000 * sin(2 * M_PI * (200 + 3000 * t) * t);
		pcm[2 * i + 1] = 8000 * sin(2 * M_PI * 1000 * t) +
		    3000 * sin(2 * M_PI * 5000 * t) +
		    (int)((seed = seed * 1103515245 + 12345) >> 16 & 0x3ff) % 600 -
		    300;
	}

	if ((pf = fopen(pcmfile, "w")) == NULL)
		err(1, "%s", pcmfile);
	if (fwrite(pcm, sizeof(*pcm), n * 2, pf) != n * 2)
		err(1, "%s", pcmfile);
	fclose(pf);

	if ((sf = fopen(sbcfile, "w")) == NULL)
		err(1, "%s", sbcfile);
	for (i = 0; i < n; i += step) {
		len = sbc_encode(&sbc, pcm + 2 * i, frame);
		if (len != sbc_frame_len(&sbc))
			errx(1, "frame length %zu", len);
		if (fwrite(frame, 1, len, sf) != len)
			err(1, "%s", sbcfile);
	}
	fclose(sf);
	free(pcm);
}

int16_t *
load(const char *file, size_t *n)
{
	FILE	*f;
	int16_t	*p;
	long	 len;

	if ((f = fopen(file, "r")) == NULL)
		err(1, "%s", file);
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	rewind(f);
	if ((p = malloc(len)) == NULL)
		err(1, NULL);
	if (fread(p, 1, len, f) != (size_t)len)
		err(1, "%s", file);
	fclose(f);
	*n = len / sizeof(*p);
	return (p);
}

void
compare(const char *orig, const char *dec, double min)
{
	int16_t	*a, *b;
	size_t	 na, nb, i, n, d, best = 0;
	double	 sig, noise, snr, bestsnr = -1000;
	int	 ch;

	a = load(orig, &na);
	b = load(dec, &nb);
	for (ch = 0; ch < 2; ch++) {
		bestsnr = -1000;
		for (d = 0; d < MAXDELAY; d++) {
			sig = noise = 0;
			n = na / 2 < nb / 2 - d ? na / 2 : nb / 2 - d;
			for (i = 4800; i + 4800 < n; i++) {
				sig += (double)a[2 * i + ch] * a[2 * i + ch];
				noise += ((double)b[2 * (i + d) + ch] -
				    a[2 * i + ch]) * ((double)b[2 * (i + d) +
				    ch] - a[2 * i + ch]);
			}
			snr = 10 * log10(sig / (noise + 1));
			if (snr > bestsnr) {
				bestsnr = snr;
				best = d;
			}
		}
		printf("channel %d: delay %zu, snr %.1f dB\n", ch, best,
		    bestsnr);
		if (bestsnr < min)
			errx(1, "snr below %.1f dB", min);
	}
}

int
main(int argc, char *argv[])
{
	const char	*errstr;
	int		 rate, bitpool;
	double		 min;

	if (argc == 7 && strcmp(argv[1], "encode") == 0) {
		rate = strtonum(argv[2], 16000, 48000, &errstr);
		if (errstr != NULL)
			errx(1, "rate %s", errstr);
		bitpool = strtonum(argv[3], 2, 250, &errstr);
		if (errstr != NULL)
			errx(1, "bitpool %s", errstr);
		encode(rate, bitpool, strcmp(argv[4], "snr") == 0 ?
		    SBC_ALLOC_SNR : SBC_ALLOC_LOUDNESS, argv[5], argv[6]);
	} else if (argc == 5 && strcmp(argv[1], "compare") == 0) {
		min = strtod(argv[4], NULL);
		compare(argv[2], argv[3], min);
	} else
		usage();
	return (0);
}
