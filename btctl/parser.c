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
#include <string.h>

#include "btd.h"
#include "parser.h"

enum token_type {
	NOTOKEN,
	ENDTOKEN,
	KEYWORD,
	ADDRESS
};

struct token {
	enum token_type		 type;
	const char		*keyword;
	int			 value;
	const struct token	*next;
};

static const struct token	 t_main[];
static const struct token	 t_show[];
static const struct token	 t_log[];
static const struct token	 t_unpair[];

static const struct token t_main[] = {
	{KEYWORD,	"log",		NONE,		t_log},
	{KEYWORD,	"reload",	RELOAD,		NULL},
	{KEYWORD,	"show",		SHOW_DEVICES,	t_show},
	{KEYWORD,	"unpair",	UNPAIR,		t_unpair},
	{ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_show[] = {
	{NOTOKEN,	"",		NONE,		NULL},
	{KEYWORD,	"bonds",	SHOW_BONDS,	NULL},
	{KEYWORD,	"controller",	SHOW_CONTROLLER, NULL},
	{KEYWORD,	"devices",	SHOW_DEVICES,	NULL},
	{ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_log[] = {
	{KEYWORD,	"brief",	LOG_BRIEF,	NULL},
	{KEYWORD,	"verbose",	LOG_VERBOSE,	NULL},
	{ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_unpair[] = {
	{ADDRESS,	"",		NONE,		NULL},
	{ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token	*match_token(const char *,
				    const struct token *,
				    struct parse_result *);
static void			 show_valid_args(const struct token *);
static int			 parse_addr(const char *, struct bdaddr *);

struct parse_result *
parse(int argc, char *argv[])
{
	static struct parse_result	 res;
	const struct token		*table = t_main;
	const struct token		*match;

	memset(&res, 0, sizeof(res));

	while (argc >= 0) {
		if ((match = match_token(argv[0], table, &res)) == NULL) {
			fprintf(stderr, "valid commands/args:\n");
			show_valid_args(table);
			return (NULL);
		}

		argc--;
		argv++;

		if (match->type == NOTOKEN || match->next == NULL)
			break;

		table = match->next;
	}

	if (argc > 0) {
		fprintf(stderr, "superfluous argument: %s\n", argv[0]);
		return (NULL);
	}

	return (&res);
}

static const struct token *
match_token(const char *word, const struct token *table,
    struct parse_result *res)
{
	const struct token	*t = NULL;
	u_int			 i, match = 0;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			if (word == NULL || strlen(word) == 0) {
				match++;
				t = &table[i];
			}
			break;
		case KEYWORD:
			if (word != NULL && strncmp(word, table[i].keyword,
			    strlen(word)) == 0) {
				match++;
				t = &table[i];
				if (t->value)
					res->action = t->value;
			}
			break;
		case ADDRESS:
			if (word != NULL && parse_addr(word, &res->addr)) {
				match++;
				t = &table[i];
			}
			break;
		case ENDTOKEN:
			break;
		}
	}

	if (match != 1) {
		if (word == NULL)
			fprintf(stderr, "missing argument:\n");
		else if (match > 1)
			fprintf(stderr, "ambiguous argument: %s\n", word);
		else if (match < 1)
			fprintf(stderr, "unknown argument: %s\n", word);
		return (NULL);
	}

	return (t);
}

static void
show_valid_args(const struct token *table)
{
	int	 i;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			fprintf(stderr, "  <cr>\n");
			break;
		case KEYWORD:
			fprintf(stderr, "  %s\n", table[i].keyword);
			break;
		case ADDRESS:
			fprintf(stderr, "  <address>\n");
			break;
		case ENDTOKEN:
			break;
		}
	}
}

static int
parse_addr(const char *word, struct bdaddr *addr)
{
	unsigned int	 v[6];
	char		 c;
	int		 i;

	if (strlen(word) != 17 || sscanf(word, "%2x:%2x:%2x:%2x:%2x:%2x%c",
	    &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &c) != 6)
		return (0);
	for (i = 0; i < 6; i++)
		addr->b[5 - i] = v[i];
	return (1);
}
