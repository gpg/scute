# Makefile.am - Makefile src/ for scute.
# Copyright (C) 2006, 2008 g10 Code GmbH
#
# This file is part of Scute.
#
# Scute is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Scute is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <https://gnu.org/licenses/>.
# SPDX-License-Identifier: LGPL-2.1-or-later

## Process this file with automake to produce Makefile.in

EXTRA_DIST = libscute.vers scute.def versioninfo.rc.in

sources = cryptoki.h pkcs11.h debug.c debug.h settings.h support.h	\
	locking.h locking.c error-mapping.h error-mapping.c		\
	get-path.c agent.h agent.c					\
	slots.h slots.c table.h table.c					\
	cert.h cert-gpgsm.c cert-object.c gpgsm.h gpgsm.c		\
	p11-cancelfunction.c p11-closeallsessions.c p11-closesession.c	\
	p11-copyobject.c p11-createobject.c p11-decrypt.c		\
	p11-decryptdigestupdate.c p11-decryptfinal.c p11-decryptinit.c	\
	p11-decryptupdate.c p11-decryptverifyupdate.c p11-derivekey.c	\
	p11-destroyobject.c p11-digest.c p11-digestencryptupdate.c	\
	p11-digestfinal.c p11-digestinit.c p11-digestkey.c		\
	p11-digestupdate.c p11-encrypt.c p11-encryptfinal.c		\
	p11-encryptinit.c p11-encryptupdate.c p11-finalize.c		\
	p11-findobjects.c p11-findobjectsfinal.c p11-findobjectsinit.c	\
	p11-generatekey.c p11-generatekeypair.c p11-generaterandom.c	\
	p11-getattributevalue.c p11-getfunctionlist.c			\
	p11-getfunctionstatus.c p11-getinfo.c p11-getmechanisminfo.c	\
	p11-getmechanismlist.c p11-getobjectsize.c			\
	p11-getoperationstate.c p11-getsessioninfo.c p11-getslotinfo.c	\
	p11-getslotlist.c p11-gettokeninfo.c p11-initialize.c		\
	p11-initpin.c p11-inittoken.c p11-login.c p11-logout.c		\
	p11-opensession.c p11-seedrandom.c p11-setattributevalue.c	\
	p11-setoperationstate.c p11-setpin.c p11-sign.c			\
	p11-signencryptupdate.c p11-signfinal.c	p11-signinit.c		\
	p11-signrecover.c p11-signrecoverinit.c	p11-signupdate.c	\
	p11-unwrapkey.c p11-verify.c p11-verifyfinal.c p11-verifyinit.c	\
	p11-verifyrecover.c p11-verifyrecoverinit.c p11-verifyupdate.c	\
	p11-waitforslotevent.c p11-wrapkey.c sexp-parse.h


if HAVE_LD_VERSION_SCRIPT
scute_version_script_cmd = -Wl,--version-script=$(srcdir)/libscute.vers
else
scute_version_script_cmd =
endif


if HAVE_DARWIN_SYSTEM
lib_LTLIBRARIES = libscute.la
else
lib_LTLIBRARIES = scute.la
endif

if HAVE_W32_SYSTEM

RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES: .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

scute_res = versioninfo.lo
scute_res_ldflag = -Wl,.libs/versioninfo.o

no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/scute.def

install-def-file:
	$(INSTALL) $(srcdir)/scute.def $(DESTDIR)$(libdir)/scute.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/scute.def

# On Windows targets, link statically to libgpg-error and libassuan.
scute_deps = $(scute_res) scute.def libgpg-error.a libassuan.a

scute_libadd = -L.

libgpg-error.a:
	ln -sf $$($(GPG_ERROR_CONFIG) --prefix)/lib/libgpg-error.a .

libassuan.a:
	ln -sf $$($(LIBASSUAN_CONFIG) --prefix)/lib/libassuan.a .

clean-local:
	rm -f libgpg-error.a libassuan.a

else

scute_res =
scute_res_ldflag =
no_undefined =
export_symbols =
install-def-file:
uninstall-def-file:

scute_deps =
scute_libadd =

endif

if HAVE_DARWIN_SYSTEM
libscute_la_LDFLAGS = $(scute_res_ldflag) $(no_undefined) -avoid-version $(export_symbols) \
	$(scute_version_script_cmd) -version-info \
	@LIBSCUTE_LT_CURRENT@:@LIBSCUTE_LT_REVISION@:@LIBSCUTE_LT_AGE@
libscute_la_DEPENDENCIES = @LTLIBOBJS@ $(srcdir)/libscute.vers $(scute_deps)
libscute_la_LIBADD = $(scute_libadd) \
	@LTLIBOBJS@ @LIBASSUAN_LIBS@ @GPG_ERROR_LIBS@

libscute_la_CPPFLAGS = -I$(srcdir)/../include \
	@LIBASSUAN_CFLAGS@ @GPG_ERROR_CFLAGS@
libscute_la_SOURCES = $(sources)
else
scute_la_LDFLAGS = $(scute_res_ldflag) $(no_undefined) -module -avoid-version $(export_symbols) \
	$(scute_version_script_cmd) -version-info \
	@LIBSCUTE_LT_CURRENT@:@LIBSCUTE_LT_REVISION@:@LIBSCUTE_LT_AGE@
scute_la_DEPENDENCIES = @LTLIBOBJS@ $(srcdir)/libscute.vers $(scute_deps)
# scute_libadd must come BEFORE libassuan and gpg-error, because we
# override it on Windows targets.
scute_la_LIBADD = $(scute_libadd) \
	@LTLIBOBJS@ @LIBASSUAN_LIBS@ @GPG_ERROR_LIBS@

scute_la_CPPFLAGS = -I$(srcdir)/../include \
	@LIBASSUAN_CFLAGS@ @GPG_ERROR_CFLAGS@
scute_la_SOURCES = $(sources)
endif
