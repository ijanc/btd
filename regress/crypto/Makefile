PROG=		crypto_test
SRCS=		crypto_test.c crypto.c
.PATH:		${.CURDIR}/../../btd
CFLAGS+=	-Wall -I${.CURDIR}/../../btd
LDADD=		-lcrypto
DPADD=		${LIBCRYPTO}
NOMAN=		yes

.include <bsd.regress.mk>
