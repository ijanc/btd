PROG=		hid_test
SRCS=		hid_test.c hid.c log.c
.PATH:		${.CURDIR}/../../btd
CFLAGS+=	-Wall -I${.CURDIR}/../../btd
LDADD=		-lusbhid -lutil
DPADD=		${LIBUSBHID} ${LIBUTIL}
NOMAN=		yes

.include <bsd.regress.mk>
