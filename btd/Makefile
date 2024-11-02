PROG=	btd
SRCS=	btd.c bus.c engine.c frontend.c control.c parse.y printconf.c log.c
SRCS+=	hci.c rtk.c l2cap.c crypto.c

MAN=

BINDIR=	/usr/local/sbin
MANDIR=	/usr/local/man/man

#DEBUG=	-g -DDEBUG=3 -O0

CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+=	-levent -lutil -lcrypto -lsndio -lusbhid -lm
DPADD+= ${LIBEVENT} ${LIBUTIL} ${LIBCRYPTO} ${LIBSNDIO} ${LIBUSBHID} ${LIBM}

.include <bsd.prog.mk>
