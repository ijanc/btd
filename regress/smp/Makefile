PROG=		smp_test
SRCS=		smp_test.c smp.c crypto.c log.c
.PATH:		${.CURDIR}/../../btd
CFLAGS+=	-Wall -I${.CURDIR}/../../btd
LDADD=		-levent -lcrypto
DPADD=		${LIBEVENT} ${LIBCRYPTO}
NOMAN=		yes

.include <bsd.regress.mk>
