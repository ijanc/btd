PROG=	btctl
SRCS=	btctl.c parser.c

MAN=

BINDIR=	/usr/local/sbin
MANDIR=	/usr/local/man/man

CFLAGS+= -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../btd
LDADD=	-lutil
DPADD=	${LIBUTIL}

.include <bsd.prog.mk>
