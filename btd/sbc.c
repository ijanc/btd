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
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "btd.h"

#define	SBC_SYNCWORD	0x9c
#define	SBC_SUBBANDS	8
#define	SBC_BLOCKS	16
#define	SBC_TAPS	80
#define	SBC_FRAC	12
#define	SBC_COEF	24

/* Proto_8_80, A2DP specification, appendix B.8, read row-wise. */
static const double proto_8_80[SBC_TAPS] = {
	0.00000000E+00, 1.56575398E-04, 3.43256425E-04, 5.54620202E-04,
	8.23919506E-04, 1.13992507E-03, 1.47640169E-03, 1.78371725E-03,
	2.01182542E-03, 2.10371989E-03, 1.99454554E-03, 1.61656283E-03,
	9.02154502E-04, -1.78805361E-04, -1.64973098E-03, -3.49717454E-03,
	5.65949473E-03, 8.02941163E-03, 1.04584443E-02, 1.27472335E-02,
	1.46525263E-02, 1.59045603E-02, 1.62208471E-02, 1.53184106E-02,
	1.29371806E-02, 8.85757540E-03, 2.92408442E-03, -4.91578024E-03,
	-1.46404076E-02, -2.61098752E-02, -3.90751381E-02, -5.31873032E-02,
	6.79989431E-02, 8.29847578E-02, 9.75753918E-02, 1.11196689E-01,
	1.23264548E-01, 1.33264415E-01, 1.40753505E-01, 1.45389847E-01,
	1.46955068E-01, 1.45389847E-01, 1.40753505E-01, 1.33264415E-01,
	1.23264548E-01, 1.11196689E-01, 9.75753918E-02, 8.29847578E-02,
	-6.79989431E-02, -5.31873032E-02, -3.90751381E-02, -2.61098752E-02,
	-1.46404076E-02, -4.91578024E-03, 2.92408442E-03, 8.85757540E-03,
	1.29371806E-02, 1.53184106E-02, 1.62208471E-02, 1.59045603E-02,
	1.46525263E-02, 1.27472335E-02, 1.04584443E-02, 8.02941163E-03,
	-5.65949473E-03, -3.49717454E-03, -1.64973098E-03, -1.78805361E-04,
	9.02154502E-04, 1.61656283E-03, 1.99454554E-03, 2.10371989E-03,
	2.01182542E-03, 1.78371725E-03, 1.47640169E-03, 1.13992507E-03,
	8.23919506E-04, 5.54620202E-04, 3.43256425E-04, 1.56575398E-04,
};

static const int offset8[4][SBC_SUBBANDS] = {
	{ -2, 0, 0, 0, 0, 0, 0, 1 },
	{ -3, 0, 0, 0, 0, 0, 1, 2 },
	{ -4, 0, 0, 0, 0, 0, 1, 2 },
	{ -4, 0, 0, 0, 0, 0, 1, 2 },
};

static int32_t	 proto[SBC_TAPS];
static int32_t	 matrix[SBC_SUBBANDS][2 * SBC_SUBBANDS];
static int	 tables_done;

static void	 sbc_tables(void);
static void	 sbc_analyze(struct sbc *, int, const int16_t *, int,
		    int32_t *);
static void	 sbc_allocate(const struct sbc *, int[2][SBC_SUBBANDS],
		    int[2][SBC_SUBBANDS]);
static uint8_t	 sbc_crc(const uint8_t *, size_t);

static void
sbc_tables(void)
{
	int	 i, m;

	for (i = 0; i < SBC_TAPS; i++)
		proto[i] = lround(proto_8_80[i] * (1 << SBC_COEF));
	for (m = 0; m < SBC_SUBBANDS; m++)
		for (i = 0; i < 2 * SBC_SUBBANDS; i++)
			matrix[m][i] = lround(cos((m + 0.5) *
			    (i - SBC_SUBBANDS / 2) * M_PI / SBC_SUBBANDS) *
			    (1 << SBC_COEF));
	tables_done = 1;
}

int
sbc_init(struct sbc *sbc, const struct audio_params *par)
{
	if (par->subbands != SBC_SUBBANDS || par->blocks != SBC_BLOCKS ||
	    par->mode != SBC_MODE_STEREO || par->channels != 2 ||
	    par->bitpool < 2 || par->bitpool > 32 * SBC_SUBBANDS)
		return (-1);
	switch (par->rate) {
	case 16000:
		sbc->freq = 0;
		break;
	case 32000:
		sbc->freq = 1;
		break;
	case 44100:
		sbc->freq = 2;
		break;
	case 48000:
		sbc->freq = 3;
		break;
	default:
		return (-1);
	}
	if (!tables_done)
		sbc_tables();
	memset(sbc->x, 0, sizeof(sbc->x));
	sbc->alloc = par->alloc;
	sbc->bitpool = par->bitpool;
	return (0);
}

size_t
sbc_frame_len(const struct sbc *sbc)
{
	return (4 + (4 * SBC_SUBBANDS * 2) / 8 +
	    (SBC_BLOCKS * sbc->bitpool + 7) / 8);
}

size_t
sbc_frame_samples(void)
{
	return (SBC_BLOCKS * SBC_SUBBANDS);
}

/*
 * Polyphase analysis: the newest sample sits at x[0], the window
 * already carries the sign of every 2M long segment.
 */
static void
sbc_analyze(struct sbc *sbc, int ch, const int16_t *pcm, int stride,
    int32_t *out)
{
	int32_t	*x = sbc->x[ch];
	int64_t	 y[2 * SBC_SUBBANDS], s;
	int	 i, j, m;

	memmove(x + SBC_SUBBANDS, x, (SBC_TAPS - SBC_SUBBANDS) * sizeof(*x));
	for (i = 0; i < SBC_SUBBANDS; i++)
		x[SBC_SUBBANDS - 1 - i] = pcm[i * stride];
	for (i = 0; i < 2 * SBC_SUBBANDS; i++) {
		s = 0;
		for (j = i; j < SBC_TAPS; j += 2 * SBC_SUBBANDS)
			s += (int64_t)proto[j] * x[j];
		y[i] = s >> (SBC_COEF - SBC_FRAC);
	}
	for (m = 0; m < SBC_SUBBANDS; m++) {
		s = 0;
		for (i = 0; i < 2 * SBC_SUBBANDS; i++)
			s += y[i] * matrix[m][i];
		out[m] = s >> SBC_COEF;
	}
}

static void
sbc_allocate(const struct sbc *sbc, int sf[2][SBC_SUBBANDS],
    int bits[2][SBC_SUBBANDS])
{
	int	 bitneed[2][SBC_SUBBANDS];
	int	 ch, sb, loudness, max_bitneed = 0;
	int	 bitcount, slicecount, bitslice;

	for (ch = 0; ch < 2; ch++)
		for (sb = 0; sb < SBC_SUBBANDS; sb++) {
			if (sbc->alloc == SBC_ALLOC_SNR) {
				bitneed[ch][sb] = sf[ch][sb];
			} else if (sf[ch][sb] == 0) {
				bitneed[ch][sb] = -5;
			} else {
				loudness = sf[ch][sb] -
				    offset8[sbc->freq][sb];
				bitneed[ch][sb] = loudness > 0 ?
				    loudness / 2 : loudness;
			}
			if (bitneed[ch][sb] > max_bitneed)
				max_bitneed = bitneed[ch][sb];
		}

	bitcount = 0;
	slicecount = 0;
	bitslice = max_bitneed + 1;
	do {
		bitslice--;
		bitcount += slicecount;
		slicecount = 0;
		for (ch = 0; ch < 2; ch++)
			for (sb = 0; sb < SBC_SUBBANDS; sb++) {
				if (bitneed[ch][sb] > bitslice + 1 &&
				    bitneed[ch][sb] < bitslice + 16)
					slicecount++;
				else if (bitneed[ch][sb] == bitslice + 1)
					slicecount += 2;
			}
	} while (bitcount + slicecount < sbc->bitpool);
	if (bitcount + slicecount == sbc->bitpool) {
		bitcount += slicecount;
		bitslice--;
	}

	for (ch = 0; ch < 2; ch++)
		for (sb = 0; sb < SBC_SUBBANDS; sb++) {
			if (bitneed[ch][sb] < bitslice + 2)
				bits[ch][sb] = 0;
			else {
				bits[ch][sb] = bitneed[ch][sb] - bitslice;
				if (bits[ch][sb] > 16)
					bits[ch][sb] = 16;
			}
		}

	ch = 0;
	sb = 0;
	while (bitcount < sbc->bitpool && sb < SBC_SUBBANDS) {
		if (bits[ch][sb] >= 2 && bits[ch][sb] < 16) {
			bits[ch][sb]++;
			bitcount++;
		} else if (bitneed[ch][sb] == bitslice + 1 &&
		    sbc->bitpool > bitcount + 1) {
			bits[ch][sb] = 2;
			bitcount += 2;
		}
		if (ch == 1) {
			ch = 0;
			sb++;
		} else
			ch = 1;
	}
	ch = 0;
	sb = 0;
	while (bitcount < sbc->bitpool && sb < SBC_SUBBANDS) {
		if (bits[ch][sb] < 16) {
			bits[ch][sb]++;
			bitcount++;
		}
		if (ch == 1) {
			ch = 0;
			sb++;
		} else
			ch = 1;
	}
}

/* CRC-8, generator x^8 + x^4 + x^3 + x^2 + 1, initial state 0x0f. */
static uint8_t
sbc_crc(const uint8_t *p, size_t len)
{
	uint8_t	 crc = 0x0f;
	size_t	 i;
	int	 b;

	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (b = 0; b < 8; b++)
			crc = crc & 0x80 ? (crc << 1) ^ 0x1d : crc << 1;
	}
	return (crc);
}

size_t
sbc_encode(struct sbc *sbc, const int16_t *pcm, uint8_t *out)
{
	int32_t		 s[SBC_BLOCKS][2][SBC_SUBBANDS];
	int		 sf[2][SBC_SUBBANDS], bits[2][SBC_SUBBANDS];
	uint8_t		 crc[10];
	uint32_t	 acc = 0, max, levels;
	int64_t		 q;
	size_t		 len, off;
	int		 blk, ch, sb, nacc = 0;

	for (blk = 0; blk < SBC_BLOCKS; blk++)
		for (ch = 0; ch < 2; ch++)
			sbc_analyze(sbc, ch, pcm + blk * SBC_SUBBANDS * 2 + ch,
			    2, s[blk][ch]);

	for (ch = 0; ch < 2; ch++)
		for (sb = 0; sb < SBC_SUBBANDS; sb++) {
			max = 0;
			for (blk = 0; blk < SBC_BLOCKS; blk++)
				if ((uint32_t)abs(s[blk][ch][sb]) > max)
					max = abs(s[blk][ch][sb]);
			sf[ch][sb] = 0;
			while (sf[ch][sb] < 15 &&
			    max >= (1U << (sf[ch][sb] + 1 + SBC_FRAC)))
				sf[ch][sb]++;
		}

	sbc_allocate(sbc, sf, bits);

	len = sbc_frame_len(sbc);
	memset(out, 0, len);
	out[0] = SBC_SYNCWORD;
	out[1] = sbc->freq << 6 | 0x03 << 4 | SBC_MODE_STEREO << 2 |
	    (sbc->alloc == SBC_ALLOC_SNR) << 1 | 1;
	out[2] = sbc->bitpool;
	for (ch = 0; ch < 2; ch++)
		for (sb = 0; sb < SBC_SUBBANDS; sb += 2)
			out[4 + ch * 4 + sb / 2] = sf[ch][sb] << 4 |
			    sf[ch][sb + 1];
	crc[0] = out[1];
	crc[1] = out[2];
	memcpy(crc + 2, out + 4, 8);
	out[3] = sbc_crc(crc, sizeof(crc));

	off = 12;
	for (blk = 0; blk < SBC_BLOCKS; blk++)
		for (ch = 0; ch < 2; ch++)
			for (sb = 0; sb < SBC_SUBBANDS; sb++) {
				if (bits[ch][sb] == 0)
					continue;
				levels = (1U << bits[ch][sb]) - 1;
				q = ((int64_t)s[blk][ch][sb] +
				    ((int64_t)1 << (sf[ch][sb] + 1 + SBC_FRAC))) *
				    levels >> (sf[ch][sb] + 2 + SBC_FRAC);
				if (q < 0)
					q = 0;
				else if (q > levels)
					q = levels;
				acc = acc << bits[ch][sb] | (uint32_t)q;
				nacc += bits[ch][sb];
				while (nacc >= 8) {
					nacc -= 8;
					out[off++] = acc >> nacc;
				}
			}
	if (nacc > 0)
		out[off++] = acc << (8 - nacc);
	return (len);
}
