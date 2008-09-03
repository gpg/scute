# Makefile.am - Makefile src/ for scute.
# Copyright (C) 2006, 2008 g10 Code GmbH
# 
# This file is part of Scute.
#
# Scute is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Scute is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scute; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
# In addition, as a special exception, g10 Code GmbH gives permission
# to link this library: with the Mozilla Foundation's code for
# Mozilla (or with modified versions of it that use the same license
# as the "Mozilla" code), and distribute the linked executables.  You
# must obey the GNU General Public License in all respects for all of
# the code used other than "Mozilla".  If you modify this file, you
# may extend this exception to your version of the file, but you are
# not obligated to do so.  If you do not wish to do so, delete this
# exception statement from your version.

## Process this file with automake to produce Makefile.in

EXTRA_DIST = libscute.vers scute.def versioninfo.rc.in stpcpy.h

sources = cryptoki.h pkcs11.h debug.h settings.h support.h		\
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
	p11-waitforslotevent.c p11-wrapkey.c


if HAVE_LD_VERSION_SCRIPT
scute_version_script_cmd = -Wl,--version-script=$(srcdir)/libscute.vers
else
scute_version_script_cmd =
endif


lib_LTLIBRARIES = libscute.la

if HAVE_W32_SYSTEM

LTRCCOMPILE = $(LIBTOOL) --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) | \
     sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

SUFFIXES: .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i $< -o $@

scute_res = versioninfo.lo
scute_res_ldflag = -Wl,.libs/versioninfo.o

no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/scute.def

install-def-file:
	$(INSTALL) $(srcdir)/scute.def $(DESTDIR)$(libdir)/scute.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/scute.def

scute_deps = $(scute_res) scute.def

else

scute_res =
scute_res_ldflag =
no_undefined =
export_symbols =
install-def-file:
uninstall-def-file:

scute_deps =

endif

libscute_la_LDFLAGS = $(scute_res_ldflag) $(no_undefined) $(export_symbols) \
	$(scute_version_script_cmd) -version-info \
	@LIBSCUTE_LT_CURRENT@:@LIBSCUTE_LT_REVISION@:@LIBSCUTE_LT_AGE@
libscute_la_DEPENDENCIES = @LTLIBOBJS@ $(srcdir)/libscute.vers $(scute_deps)
libscute_la_LIBADD = @LTLIBOBJS@ @LIBASSUAN_LIBS@ @GPG_ERROR_LIBS@

libscute_la_CPPFLAGS = -I$(srcdir)/../include \
	@LIBASSUAN_CFLAGS@ @GPG_ERROR_CFLAGS@
libscute_la_SOURCES = $(sources)

# The above rules only build a static library on W32.  We build the
# DLL below, such that it is autonomous (does not link to any other
# non-standard DLL).

EXEEXT = .dll

if HAVE_W32_SYSTEM

bin_PROGRAMS = scute

AM_CFLAGS = @LIBASSUAN_CFLAGS@ @GPG_ERROR_CFLAGS@ -shared

scute_SOURCES = dllmain.c $(sources) versioninfo.rc

scute_DEPENDENCIES = @LTLIBOBJS@ versioninfo.o libgpg-error.a libassuan.a

libgpg-error.a:
	ln -s $$($(GPG_ERROR_CONFIG) --prefix)/lib/libgpg-error.a .

libassuan.a:
	ln -s $$($(LIBASSUAN_CONFIG) --prefix)/lib/libassuan.a .

clean-local:
	rm -f libgpg-error.a libassuan.a


scute_LDADD = @LTLIBOBJS@ $(srcdir)/scute.def -L. -lassuan -lgpg-error -lws2_32

.rc.o:
	$(RC) -I $(srcdir) -I . `test -f '$<' || echo '$(srcdir)/'`$< $@

endif
