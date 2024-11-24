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

/*
 * The specification writes keys and messages most significant octet
 * first; here every value is kept in the little endian order in which
 * it goes over the air and is swapped around the AES primitives.
 */

#include <sys/types.h>
#include <sys/queue.h>

#include <event.h>
#include <imsg.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "btd.h"

#define	CMAC_MSG_MAX	80

static void	 swap(const uint8_t *, uint8_t *, size_t);
static int	 cmac(const uint8_t *, const uint8_t *, size_t, uint8_t *);

static const uint8_t f5_salt[16] = {
	0xbe, 0x83, 0x60, 0x5a, 0xdb, 0x0b, 0x37, 0x60,
	0x38, 0xa5, 0xf5, 0xaa, 0x91, 0x83, 0x88, 0x6c
};

static void
swap(const uint8_t *src, uint8_t *dst, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		dst[len - 1 - i] = src[i];
}

int
crypto_e(const uint8_t k[16], const uint8_t in[16], uint8_t out[16])
{
	AES_KEY	 key;
	uint8_t	 kb[16], ib[16], ob[16];

	swap(k, kb, 16);
	swap(in, ib, 16);
	if (AES_set_encrypt_key(kb, 128, &key) != 0)
		return (-1);
	AES_encrypt(ib, ob, &key);
	swap(ob, out, 16);
	explicit_bzero(&key, sizeof(key));
	explicit_bzero(kb, sizeof(kb));
	return (0);
}

static int
cmac(const uint8_t k[16], const uint8_t *m, size_t len, uint8_t mac[16])
{
	CMAC_CTX	*ctx;
	uint8_t		 kb[16], mb[CMAC_MSG_MAX], ob[16];
	size_t		 olen;
	int		 ret = -1;

	if (len > sizeof(mb))
		return (-1);
	swap(k, kb, 16);
	swap(m, mb, len);
	if ((ctx = CMAC_CTX_new()) == NULL)
		return (-1);
	if (CMAC_Init(ctx, kb, 16, EVP_aes_128_cbc(), NULL) == 1 &&
	    CMAC_Update(ctx, mb, len) == 1 &&
	    CMAC_Final(ctx, ob, &olen) == 1 && olen == 16) {
		swap(ob, mac, 16);
		ret = 0;
	}
	CMAC_CTX_free(ctx);
	explicit_bzero(kb, sizeof(kb));
	return (ret);
}

int
crypto_cmac(const uint8_t k[16], const uint8_t *m, size_t len,
    uint8_t mac[16])
{
	return (cmac(k, m, len, mac));
}

int
crypto_ah(const uint8_t irk[16], const uint8_t r[3], uint8_t res[3])
{
	uint8_t	 in[16], out[16];

	memset(in, 0, sizeof(in));
	memcpy(in, r, 3);
	if (crypto_e(irk, in, out) == -1)
		return (-1);
	memcpy(res, out, 3);
	return (0);
}

int
crypto_c1(const uint8_t k[16], const uint8_t r[16], const uint8_t preq[7],
    const uint8_t pres[7], uint8_t iat, const uint8_t ia[6], uint8_t rat,
    const uint8_t ra[6], uint8_t res[16])
{
	uint8_t	 p1[16], p2[16], t[16];
	int	 i;

	p1[0] = iat;
	p1[1] = rat;
	memcpy(p1 + 2, preq, 7);
	memcpy(p1 + 9, pres, 7);
	memcpy(p2, ra, 6);
	memcpy(p2 + 6, ia, 6);
	memset(p2 + 12, 0, 4);

	for (i = 0; i < 16; i++)
		t[i] = r[i] ^ p1[i];
	if (crypto_e(k, t, t) == -1)
		return (-1);
	for (i = 0; i < 16; i++)
		t[i] ^= p2[i];
	return (crypto_e(k, t, res));
}

int
crypto_s1(const uint8_t k[16], const uint8_t r1[16], const uint8_t r2[16],
    uint8_t res[16])
{
	uint8_t	 r[16];

	memcpy(r, r2, 8);
	memcpy(r + 8, r1, 8);
	return (crypto_e(k, r, res));
}

int
crypto_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
    uint8_t z, uint8_t res[16])
{
	uint8_t	 m[65];

	m[0] = z;
	memcpy(m + 1, v, 32);
	memcpy(m + 33, u, 32);
	return (cmac(x, m, sizeof(m), res));
}

int
crypto_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t a1[7], const uint8_t a2[7], uint8_t mackey[16],
    uint8_t ltk[16])
{
	uint8_t	 m[53], t[16];
	int	 ret;

	if (cmac(f5_salt, w, 32, t) == -1)
		return (-1);

	m[0] = 0x00;
	m[1] = 0x01;
	memcpy(m + 2, a2, 7);
	memcpy(m + 9, a1, 7);
	memcpy(m + 16, n2, 16);
	memcpy(m + 32, n1, 16);
	m[48] = 'e';
	m[49] = 'l';
	m[50] = 't';
	m[51] = 'b';
	m[52] = 0;
	if (cmac(t, m, sizeof(m), mackey) == -1) {
		explicit_bzero(t, sizeof(t));
		return (-1);
	}
	m[52] = 1;
	ret = cmac(t, m, sizeof(m), ltk);
	explicit_bzero(t, sizeof(t));
	return (ret);
}

int
crypto_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
    const uint8_t r[16], const uint8_t iocap[3], const uint8_t a1[7],
    const uint8_t a2[7], uint8_t res[16])
{
	uint8_t	 m[65];

	memcpy(m, a2, 7);
	memcpy(m + 7, a1, 7);
	memcpy(m + 14, iocap, 3);
	memcpy(m + 17, r, 16);
	memcpy(m + 33, n2, 16);
	memcpy(m + 49, n1, 16);
	return (cmac(w, m, sizeof(m), res));
}

int
crypto_g2(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
    const uint8_t y[16], uint32_t *val)
{
	uint8_t	 m[80], mac[16];

	memcpy(m, y, 16);
	memcpy(m + 16, v, 32);
	memcpy(m + 48, u, 32);
	if (cmac(x, m, sizeof(m), mac) == -1)
		return (-1);
	*val = (mac[0] | mac[1] << 8 | mac[2] << 16 |
	    (uint32_t)mac[3] << 24) % 1000000;
	return (0);
}

int
crypto_h6(const uint8_t w[16], const uint8_t keyid[4], uint8_t res[16])
{
	return (cmac(w, keyid, 4, res));
}

void *
crypto_ecdh_new(uint8_t pub[64])
{
	EC_KEY		*key;
	const EC_POINT	*point;
	BIGNUM		*x = NULL, *y = NULL;
	uint8_t		 buf[32];
	int		 ok = 0;

	if ((key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
		return (NULL);
	if (EC_KEY_generate_key(key) != 1)
		goto done;
	if ((point = EC_KEY_get0_public_key(key)) == NULL)
		goto done;
	if ((x = BN_new()) == NULL || (y = BN_new()) == NULL)
		goto done;
	if (EC_POINT_get_affine_coordinates(EC_KEY_get0_group(key), point, x,
	    y, NULL) != 1)
		goto done;
	if (BN_bn2binpad(x, buf, 32) != 32)
		goto done;
	swap(buf, pub, 32);
	if (BN_bn2binpad(y, buf, 32) != 32)
		goto done;
	swap(buf, pub + 32, 32);
	ok = 1;
 done:
	BN_free(x);
	BN_free(y);
	if (!ok) {
		EC_KEY_free(key);
		return (NULL);
	}
	return (key);
}

int
crypto_ecdh_shared(void *ctx, const uint8_t peer[64], uint8_t dhkey[32])
{
	EC_KEY		*key = ctx;
	const EC_GROUP	*group = EC_KEY_get0_group(key);
	EC_POINT	*point = NULL, *shared = NULL;
	BIGNUM		*x = NULL, *y = NULL;
	uint8_t		 buf[32];
	int		 ret = -1;

	if ((x = BN_new()) == NULL || (y = BN_new()) == NULL)
		goto done;
	swap(peer, buf, 32);
	if (BN_bin2bn(buf, 32, x) == NULL)
		goto done;
	swap(peer + 32, buf, 32);
	if (BN_bin2bn(buf, 32, y) == NULL)
		goto done;
	if ((point = EC_POINT_new(group)) == NULL ||
	    (shared = EC_POINT_new(group)) == NULL)
		goto done;
	if (EC_POINT_set_affine_coordinates(group, point, x, y, NULL) != 1)
		goto done;
	if (EC_POINT_is_on_curve(group, point, NULL) != 1)
		goto done;
	if (EC_POINT_mul(group, shared, NULL, point,
	    EC_KEY_get0_private_key(key), NULL) != 1)
		goto done;
	if (EC_POINT_get_affine_coordinates(group, shared, x, NULL, NULL) != 1)
		goto done;
	if (BN_bn2binpad(x, buf, 32) != 32)
		goto done;
	swap(buf, dhkey, 32);
	ret = 0;
 done:
	explicit_bzero(buf, sizeof(buf));
	EC_POINT_free(point);
	EC_POINT_free(shared);
	BN_free(x);
	BN_free(y);
	return (ret);
}

void
crypto_ecdh_free(void *ctx)
{
	EC_KEY_free(ctx);
}
