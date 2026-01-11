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
#include <sys/stat.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "btd.h"

static int	 hex_decode(const char *, uint8_t *, size_t);
static void	 hex_print(FILE *, const uint8_t *, size_t);
static int	 bond_parse(char *, struct bond *, struct bond_local *);

static int
hex_decode(const char *s, uint8_t *p, size_t len)
{
	unsigned int	 v;
	size_t		 i;

	if (strlen(s) != len * 2)
		return (-1);
	for (i = 0; i < len; i++) {
		if (sscanf(s + i * 2, "%2x", &v) != 1)
			return (-1);
		p[i] = v;
	}
	return (0);
}

static void
hex_print(FILE *f, const uint8_t *p, size_t len)
{
	size_t	 i;

	for (i = 0; i < len; i++)
		fprintf(f, "%02x", p[i]);
}

/*
 * One bond per line:
 *	local ADDR irk HEX
 *	le ADDR public|random [ltk HEX ediv N rand N keysize N] [irk HEX]
 *	    [auth] [sc]
 *	br ADDR linkkey HEX type N
 */
static int
bond_parse(char *line, struct bond *b, struct bond_local *local)
{
	char		*ap, *word[32];
	const char	*errstr;
	int		 n = 0, i;

	while ((ap = strsep(&line, " \t\n")) != NULL) {
		if (*ap == '\0')
			continue;
		if (n == nitems(word))
			return (-1);
		word[n++] = ap;
	}
	if (n == 0 || word[0][0] == '#')
		return (0);
	if (n < 2)
		return (-1);

	if (strcmp(word[0], "local") == 0) {
		if (n != 4 || bdaddr_aton(word[1], &local->addr) == -1 ||
		    strcmp(word[2], "irk") != 0 ||
		    hex_decode(word[3], local->irk, sizeof(local->irk)) == -1)
			return (-1);
		return (2);
	}

	memset(b, 0, sizeof(*b));
	if (bdaddr_aton(word[1], &b->addr) == -1)
		return (-1);
	if (strcmp(word[0], "br") == 0) {
		b->type = BOND_BR;
		if (n != 6 || strcmp(word[2], "linkkey") != 0 ||
		    hex_decode(word[3], b->linkkey, sizeof(b->linkkey)) == -1 ||
		    strcmp(word[4], "type") != 0)
			return (-1);
		b->linkkey_type = strtonum(word[5], 0, 8, &errstr);
		if (errstr != NULL)
			return (-1);
		return (1);
	}
	if (strcmp(word[0], "le") != 0 || n < 3)
		return (-1);
	b->type = BOND_LE;
	if (strcmp(word[2], "public") == 0)
		b->addr_type = BDADDR_PUBLIC;
	else if (strcmp(word[2], "random") == 0)
		b->addr_type = BDADDR_RANDOM;
	else
		return (-1);
	b->keysize = 16;
	for (i = 3; i < n; i++) {
		if (strcmp(word[i], "auth") == 0)
			b->flags |= BOND_F_AUTH;
		else if (strcmp(word[i], "sc") == 0)
			b->flags |= BOND_F_SC;
		else if (i + 1 == n)
			return (-1);
		else if (strcmp(word[i], "ltk") == 0) {
			if (hex_decode(word[++i], b->ltk, sizeof(b->ltk)) == -1)
				return (-1);
			b->flags |= BOND_F_LTK;
		} else if (strcmp(word[i], "irk") == 0) {
			if (hex_decode(word[++i], b->irk, sizeof(b->irk)) == -1)
				return (-1);
			b->flags |= BOND_F_IRK;
		} else if (strcmp(word[i], "ediv") == 0) {
			b->ediv = strtonum(word[++i], 0, UINT16_MAX, &errstr);
			if (errstr != NULL)
				return (-1);
		} else if (strcmp(word[i], "rand") == 0) {
			errno = 0;
			b->rand = strtoull(word[++i], &ap, 0);
			if (errno != 0 || *ap != '\0')
				return (-1);
		} else if (strcmp(word[i], "keysize") == 0) {
			b->keysize = strtonum(word[++i], 7, 16, &errstr);
			if (errstr != NULL)
				return (-1);
		} else
			return (-1);
	}
	return (1);
}

int
bond_read(const char *path, struct bond_list *list, struct bond_local *local)
{
	FILE		*f;
	struct bond	 b, *nb;
	char		*line = NULL;
	size_t		 linesize = 0;
	int		 lineno = 0, have_local = 0;

	if ((f = fopen(path, "r")) == NULL) {
		if (errno != ENOENT)
			log_warn("%s", path);
		return (0);
	}
	while (getline(&line, &linesize, f) != -1) {
		lineno++;
		switch (bond_parse(line, &b, local)) {
		case -1:
			log_warnx("%s:%d: invalid bond", path, lineno);
			break;
		case 1:
			if ((nb = malloc(sizeof(*nb))) == NULL)
				fatal(NULL);
			*nb = b;
			TAILQ_INSERT_TAIL(list, nb, entry);
			break;
		case 2:
			have_local = 1;
			break;
		}
	}
	free(line);
	fclose(f);
	return (have_local);
}

int
bond_write(const char *path, struct bond_list *list, struct bond_local *local)
{
	FILE		*f;
	struct bond	*b;
	char		 tmp[PATH_MAX];
	int		 fd;

	if (snprintf(tmp, sizeof(tmp), "%s.XXXXXXXXXX", path) >=
	    (int)sizeof(tmp))
		return (-1);
	if ((fd = mkstemp(tmp)) == -1) {
		log_warn("%s", tmp);
		return (-1);
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		log_warn("%s", tmp);
		close(fd);
		unlink(tmp);
		return (-1);
	}
	if (local != NULL) {
		fprintf(f, "local %s irk ", bdaddr_ntoa(&local->addr));
		hex_print(f, local->irk, sizeof(local->irk));
		fprintf(f, "\n");
	}
	TAILQ_FOREACH(b, list, entry) {
		if (b->type == BOND_BR) {
			fprintf(f, "br %s linkkey ", bdaddr_ntoa(&b->addr));
			hex_print(f, b->linkkey, sizeof(b->linkkey));
			fprintf(f, " type %u\n", b->linkkey_type);
			continue;
		}
		fprintf(f, "le %s %s", bdaddr_ntoa(&b->addr),
		    b->addr_type == BDADDR_RANDOM ? "random" : "public");
		if (b->flags & BOND_F_LTK) {
			fprintf(f, " ltk ");
			hex_print(f, b->ltk, sizeof(b->ltk));
			fprintf(f, " ediv %u rand %llu keysize %u", b->ediv,
			    (unsigned long long)b->rand, b->keysize);
		}
		if (b->flags & BOND_F_IRK) {
			fprintf(f, " irk ");
			hex_print(f, b->irk, sizeof(b->irk));
		}
		if (b->flags & BOND_F_AUTH)
			fprintf(f, " auth");
		if (b->flags & BOND_F_SC)
			fprintf(f, " sc");
		fprintf(f, "\n");
	}
	if (fflush(f) == EOF || fsync(fd) == -1 || ferror(f)) {
		log_warn("%s", tmp);
		fclose(f);
		unlink(tmp);
		return (-1);
	}
	fclose(f);
	if (rename(tmp, path) == -1) {
		log_warn("rename %s", path);
		unlink(tmp);
		return (-1);
	}
	return (0);
}

struct bond *
bond_find(int type, const struct bdaddr *addr)
{
	struct bond	*b;

	TAILQ_FOREACH(b, &engine_state.bonds, entry)
		if (b->type == type && bdaddr_cmp(&b->addr, addr) == 0)
			return (b);
	return (NULL);
}

void
bond_store(struct bond *nb)
{
	struct bond	*b;

	if ((b = bond_find(nb->type, &nb->addr)) == NULL) {
		if ((b = calloc(1, sizeof(*b))) == NULL)
			fatal(NULL);
		TAILQ_INSERT_TAIL(&engine_state.bonds, b, entry);
	}
	nb->entry = b->entry;
	*b = *nb;
	engine_imsg_compose_main(IMSG_BOND_SAVE, b, sizeof(*b));
}

void
bond_delete(struct bond *b)
{
	TAILQ_REMOVE(&engine_state.bonds, b, entry);
	engine_imsg_compose_main(IMSG_BOND_DELETE, b, sizeof(*b));
	explicit_bzero(b, sizeof(*b));
	free(b);
}
