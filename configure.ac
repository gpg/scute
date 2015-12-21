# configure.ac: Configure script for Scute.
# Copyright (C) 2006, 2007, 2008, 2009, 2010, 2015 g10 Code GmbH
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
# along with this program; if not, see <http://www.gnu.org/licenses/>.
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

# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
min_automake_version="1.9.3"

# To build a release you need to create a tag with the version number
# (git tag -s scute-1.n.m) and run "./autogen.sh --force".  Please
# bump the version number immediately *after* the release and do
# another commit and push so that the git magic is able to work.
m4_define([mym4_package],[scute])
m4_define([mym4_major], [1])
m4_define([mym4_minor], [5])
m4_define([mym4_micro], [0])

# To start a new development series, i.e a new major or minor number
# you need to mark an arbitrary commit before the first beta release
# with an annotated tag.  For example the 1.5 branch starts off with
# the tag "scute-1.5-base".  This is used as the base for counting
# beta numbers before the first release of a series.

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isbeta).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_verslist], m4_split(m4_esyscmd([./autogen.sh --find-version] \
                           mym4_package mym4_major mym4_minor mym4_micro),[:]))
m4_define([mym4_isbeta],       m4_argn(2, mym4_verslist))
m4_define([mym4_version],      m4_argn(4, mym4_verslist))
m4_define([mym4_revision],     m4_argn(7, mym4_verslist))
m4_define([mym4_revision_dec], m4_argn(8, mym4_verslist))
m4_esyscmd([echo ]mym4_version[>VERSION])
AC_INIT([mym4_package],[mym4_version], [http://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBSCUTE_LT_CURRENT=0
LIBSCUTE_LT_AGE=0
LIBSCUTE_LT_REVISION=2

# Version numbers reported by the PKCS #11 module to its users.
VERSION_MAJOR=1
VERSION_MINOR=0

NEED_GPG_ERROR_VERSION=1.4
NEED_LIBASSUAN_VERSION=2.0.0
NEED_GPGSM_VERSION=1.9.6
# Some status variables to give feedback at the end of a configure run.
have_gpg_error=no
have_libassuan=no

BUILD_REVISION=svn_revision
PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/cryptoki.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CANONICAL_HOST

# Autobuilder support.
AB_INIT

# Enable GNU extensions on systems that have them.
AC_GNU_SOURCE

AH_VERBATIM([_REENTRANT],
[/* To allow the use of scute in multithreaded programs we have to use
  special features from the library.  */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif])

# Checks for programs.
AC_PROG_CC

#
# Setup gcc specific options
#
AC_MSG_NOTICE([checking for cc features])
if test "$GCC" = yes; then
    mycflags=
    mycflags_save=$CFLAGS

    # Check whether gcc does not emit a diagnositc for unknow -Wno-*
    # options.  This is the case for gcc >= 4.6
    AC_MSG_CHECKING([if gcc ignores unknown -Wno-* options])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6 )
#kickerror
#endif]],[])],[_gcc_silent_wno=yes],[_gcc_silent_wno=no])
    AC_MSG_RESULT($_gcc_silent_wno)

    # Note that it is okay to use CFLAGS here because these are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        mycflags="$mycflags -O3 -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        mycflags="$mycflags -Wformat -Wno-format-y2k -Wformat-security"
        if test x"$_gcc_silent_wno" = xyes ; then
          _gcc_wopt=yes
        else
          AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
          CFLAGS="-Wno-missing-field-initializers"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                            [_gcc_wopt=yes],[_gcc_wopt=no])
          AC_MSG_RESULT($_gcc_wopt)
        fi
        if test x"$_gcc_wopt" = xyes ; then
          mycflags="$mycflags -W -Wno-sign-compare"
          mycflags="$mycflags -Wno-missing-field-initializers"
        fi

        AC_MSG_CHECKING([if gcc supports -Wdeclaration-after-statement])
        CFLAGS="-Wdeclaration-after-statement"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        if test x"$_gcc_wopt" = xyes ; then
          mycflags="$mycflags -Wdeclaration-after-statement"
        fi
    else
        mycflags="$mycflags -Wall"
    fi

    if test x"$_gcc_silent_wno" = xyes ; then
      _gcc_psign=yes
    else
      AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
      CFLAGS="-Wno-pointer-sign"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                        [_gcc_psign=yes],[_gcc_psign=no])
      AC_MSG_RESULT($_gcc_psign)
    fi
    if test x"$_gcc_psign" = xyes ; then
       mycflags="$mycflags -Wno-pointer-sign"
    fi

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    if test x"$_gcc_psign" = xyes ; then
       mycflags="$mycflags -Wpointer-arith"
    fi

    CFLAGS="$mycflags $mycflags_save"
fi

AC_ARG_ENABLE(optimization,
   AC_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
                   fi])


AC_SUBST(LIBSCUTE_LT_CURRENT)
AC_SUBST(LIBSCUTE_LT_AGE)
AC_SUBST(LIBSCUTE_LT_REVISION)
AC_DEFINE_UNQUOTED(NEED_GPGSM_VERSION, "$NEED_GPGSM_VERSION",
				       [Min. needed GPGSM version.])

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(VERSION_MAJOR, $VERSION_MAJOR, [Major version number])
AC_DEFINE_UNQUOTED(VERSION_MINOR, $VERSION_MINOR, [Minor version number])

# Don't default to build static libs.
# FIXME: Caution: Evil hack ahead.  Libtool does not support linking a
# static library to a shared library.  But for libassuan, we need this.
# Instead adding a lot of junk to Makefile.am to get this, we just override
# all safety checks here.  We are driving without seat belts now!
# http://lists.cairographics.org/archives/cairo/2009-April/016962.html
lt_cv_deplibs_check_method=pass_all
LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])

# For now we hardcode the use of version scripts.  It would be better
# to write a test for this or even implement this within libtool.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
esac
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

GPGSM_DEFAULT=no
GPG_AGENT_DEFAULT=no
have_w32_system=no
case "${host}" in
    *-mingw32*)
        # special stuff for Windoze NT
	GPGSM_DEFAULT='c:\\gnupg\\gpgsm.exe'
        GPG_AGENT_DEFAULT='c:\\gnupg\\gpg-agent.exe'
	have_w32_system=yes
        ;;
    *)
	;;
esac

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)

# Generate values for the DLL version info
if test "$have_w32_system" = yes; then
    BUILD_TIMESTAMP=`date --iso-8601=minutes`
    changequote(,)dnl 
    BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
    changequote([,])dnl
    BUILD_FILEVERSION="${BUILD_FILEVERSION}${BUILD_REVISION}"
fi
AC_SUBST(BUILD_REVISION)
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)

# Checks for libraries.

AC_CHECK_FUNCS([ttyname localtime_r timegm stpcpy])

# Run the checks needed for estream-printf.c
estream_PRINTF_INIT

# The error code library.  Error codes are sent over the IPC layer and
# have to be interpreted.
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes, have_gpg_error=no)

# The IPC library.
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_VERSION",
                  have_libassuan=yes, have_libassuan=no)

# GPGSM
NO_OVERRIDE=no
AC_ARG_WITH(gpgsm,
	    AC_HELP_STRING([--with-gpgsm=PATH], [use GpgSM binary at PATH]),
	    GPGSM=$withval, NO_OVERRIDE=yes)
if test "$NO_OVERRIDE" = "yes" || test "$GPGSM" = "yes"; then
  GPGSM=
  NO_OVERRIDE=yes
  if test "$cross_compiling" != "yes"; then
    AC_PATH_PROG(GPGSM, gpgsm)
  fi
  if test -z "$GPGSM"; then
    GPGSM="$GPGSM_DEFAULT"
  fi
fi
if test "$GPGSM" = no; then
  if test "$NO_OVERRIDE" = "yes"; then
    if test "$cross_compiling" != "yes"; then
      AC_MSG_WARN([
***
*** Could not find GpgSM, install GpgSM or use --with-gpgsm=PATH to enable it
***])
    else
      AC_MSG_ERROR([
***
*** Can not determine path to GpgSM when cross-compiling, use --with-gpgsm=PATH
***])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPGSM_PATH, "$GPGSM", [Path to the GPGSM binary.])
  AC_DEFINE(ENABLE_GPGSM,1,[Whether GPGSM support is enabled])
fi
AM_CONDITIONAL(HAVE_GPGSM, test "$GPGSM" != "no")


dnl Check for GPGSM version requirement.
GPGSM_VERSION=unknown
ok=maybe
if test -z "$GPGSM" -o "x$GPGSM" = "xno"; then
  ok=no
else
  if test "$cross_compiling" = "yes"; then
    AC_MSG_WARN([GPGSM version can not be checked when cross compiling])
    ok=no
  else
    if test ! -x "$GPGSM"; then
      AC_MSG_WARN([GPGSM not executable, version check disabled])
      ok=no
    fi
  fi
fi
if test "$ok" = "maybe"; then
  AC_MSG_CHECKING(for GPGSM >= $NEED_GPGSM_VERSION)
  req_major=`echo $NEED_GPGSM_VERSION | \
             sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
  req_minor=`echo $NEED_GPGSM_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
  req_micro=`echo $NEED_GPGSM_VERSION | \
	     sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
  gpgsm_version=`$GPGSM --version | grep ^gpgsm`
  major=`echo $gpgsm_version | \
	 sed 's/^gpgsm (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  minor=`echo $gpgsm_version | \
	 sed 's/^gpgsm (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  micro=`echo $gpgsm_version | \
	 sed 's/^gpgsm (GnuPG) \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
  GPGSM_VERSION=`echo $gpgsm_version | sed 's/^gpgsm (GnuPG) //'`

  if test "$major" -gt "$req_major"; then
    ok=yes
  else
    if test "$major" -eq "$req_major"; then
      if test "$minor" -gt "$req_minor"; then
        ok=yes
      else
        if test "$minor" -eq "$req_minor"; then
          if test "$micro" -ge "$req_micro"; then
            ok=yes
	  fi
        fi
      fi
    fi
  fi
  if test "$ok" = "yes"; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
    AC_MSG_WARN([GPGSM must be at least version $NEED_GPGSM_VERSION])
  fi
fi
gpgsm_ok="$ok"

# GPG_AGENT
NO_OVERRIDE=no
AC_ARG_WITH(gpg-agent,
	    AC_HELP_STRING([--with-gpg-agent=PATH], [use GPG Agent binary at PATH]),
	    GPG_AGENT=$withval, NO_OVERRIDE=yes)
if test "$NO_OVERRIDE" = "yes" || test "$GPG_AGENT" = "yes"; then
  GPG_AGENT=
  NO_OVERRIDE=yes
  if test "$cross_compiling" != "yes"; then
    AC_PATH_PROG(GPG_AGENT, gpg-agent)
  fi
  if test -z "$GPG_AGENT"; then
    GPG_AGENT="$GPG_AGENT_DEFAULT"
  fi
fi
if test "$GPG_AGENT" = no; then
  if test "$NO_OVERRIDE" = "yes"; then
    if test "$cross_compiling" != "yes"; then
      AC_MSG_WARN([
***
*** Could not find GPG Agent, install GPG Agent or use --with-gpg-agent=PATH to enable it
***])
    else
      AC_MSG_ERROR([
***
*** Can not determine path to GPG Agent when cross-compiling, use --with-gpg-agent=PATH
***])
    fi
  fi
else
  AC_DEFINE_UNQUOTED(GPG_AGENT_PATH, "$GPG_AGENT", [Path to the GPG_AGENT binary.])
  AC_DEFINE(ENABLE_GPG_AGENT,1, [Whether GPG Agent support is enabled])
fi
AM_CONDITIONAL(HAVE_GPG_AGENT, test "$GPG_AGENT" != "no")


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.

# Check for programs needed for the manual.
AC_CHECK_PROG(CONVERT, convert, convert)
AC_CHECK_PROG(EPSTOPDF, epstopdf, epstopdf)

# Test if tests can be run
ok=yes
AM_CONDITIONAL(RUN_TESTS, test "$ok" = "yes")


AH_BOTTOM([
/* Prefix all estream functions.  */
#define _ESTREAM_EXT_SYM_PREFIX _scute_
])


# Print errors here so that they are visible all
# together and the user can acquire them all together.

die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgpg-error to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/pub/gcrypt/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libassuan" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libassuan to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/pub/gcrypt/alpha/libassuan/
*** (at least version $NEED_LIBASSUAN_VERSION is required).
***]])
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi

AC_CONFIG_FILES([Makefile
                 m4/Makefile
                 src/Makefile
                 tests/Makefile
		 doc/manual/Makefile
		 doc/Makefile
                 src/versioninfo.rc])
AC_OUTPUT
