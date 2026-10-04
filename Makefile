SUBDIR=		btd btctl

.if make(regress) || make(clean) || make(cleandir) || make(obj)
SUBDIR+=	regress
.endif

VERSION=	0.1
CLEANFILES=	btd-${VERSION}.tar.gz*

.PHONY: dist btd-${VERSION}.tar.gz
dist: btd-${VERSION}.tar.gz
	gpg --armor --detach-sign btd-${VERSION}.tar.gz
	@echo ${.OBJDIR}/btd-${VERSION}.tar.gz

btd-${VERSION}.tar.gz:
	cd ${.CURDIR} && pax -w -x ustar -s ',^,btd-${VERSION}/,' \
	    README LICENSE Changes Makefile \
	    btd/Makefile btd/*.[chy] btd/*.[58] \
	    btctl/Makefile btctl/*.[ch] btctl/*.8 etc/rc.d/btd \
	    regress/Makefile regress/*/Makefile regress/*/*.[ch] | \
	    gzip -9 > ${.OBJDIR}/$@

.include <bsd.subdir.mk>
