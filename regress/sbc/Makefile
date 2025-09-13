PROG=		sbc_test
SRCS=		sbc_test.c sbc.c
.PATH:		${.CURDIR}/../../btd
CFLAGS+=	-Wall -I${.CURDIR}/../../btd
LDADD=		-lm
DPADD=		${LIBM}
NOMAN=		yes
CLEANFILES+=	*.pcm *.sbc

FFMPEG?=	/usr/local/bin/ffmpeg
SNR?=		25

REGRESS_TARGETS=
.for rate bitpool alloc in 48000 53 loudness 48000 38 loudness 44100 53 snr
REGRESS_TARGETS+=	run-${rate}-${bitpool}-${alloc}
run-${rate}-${bitpool}-${alloc}: ${PROG}
	./${PROG} encode ${rate} ${bitpool} ${alloc} in.pcm out.sbc
	${FFMPEG} -loglevel error -y -f sbc -i out.sbc -f s16le -ac 2 \
	    out.pcm
	./${PROG} compare in.pcm out.pcm ${SNR}
.endfor

.if !exists(${FFMPEG})
REGRESS_SKIP_TARGETS=	${REGRESS_TARGETS}
.endif

.include <bsd.regress.mk>
