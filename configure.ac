# configure.ac: Configure script for Scute.
# Copyright (C) 2006, 2007, 2008, 2009, 2010, 2015 g10 Code GmbH
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

# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
min_automake_version="1.16.3"

# To build a release you need to create a tag with the version number
# (git tag -s scute-1.n.m) and run "./autogen.sh --force".  Please
# bump the version number immediately *after* the release and do
# another commit and push so that the git magic is able to work.
m4_define([mym4_package],[scute])
m4_define([mym4_major], [1])
m4_define([mym4_minor], [7])
m4_define([mym4_micro], [1])

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
AC_INIT([mym4_package],[mym4_version],[https://bugs.gnupg.org])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBSCUTE_LT_CURRENT=0
LIBSCUTE_LT_AGE=0
LIBSCUTE_LT_REVISION=5

# Version numbers reported by the PKCS #11 module to its users.
VERSION_MAJOR=1
VERSION_MINOR=0

NEED_GPG_ERROR_VERSION=1.38
NEED_LIBASSUAN_VERSION=2.5.0

# Some status variables to give feedback at the end of a configure run.
have_gpg_error=no
have_libassuan=no

#
# Provide information about the build.
#
BUILD_REVISION="mym4_revision"
BUILD_REVISION_DEC="mym4_revision_dec"

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/cryptoki.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_CANONICAL_HOST

# Autobuilder support.
AB_INIT

# Enable GNU extensions on systems that have them.
AC_USE_SYSTEM_EXTENSIONS

AH_VERBATIM([_REENTRANT],
[/* To allow the use of scute in multithreaded programs we have to use
  special features from the library.  */
#ifndef _REENTRANT
# define _REENTRANT 1
#endif])

# Checks for programs.
AC_PROG_CC

# Check for programs needed for the manual.
AC_CHECK_PROG(YAT2M, yat2m, yat2m)
have_doc_tools=no
if test -n "$ac_cv_prog_YAT2M" ; then
    have_doc_tools=yes
fi

# Note: A suitable gitlog-to-changelog script can be found in GnuPG master.
AC_CHECK_PROGS(GITLOG_TO_CHANGELOG, gitlog-to-changelog, [gitlog-to-changelog])

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
   AS_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
                   fi])

#
# Option to disable building of doc file
#
build_doc=yes
AC_ARG_ENABLE([doc], AS_HELP_STRING([--disable-doc],
                                    [do not build the documentation]),
                     build_doc=$enableval, build_doc=yes)
AM_CONDITIONAL([BUILD_DOC], [test "x$build_doc" != xno && test "x$have_doc_tools" = xyes])

#
# Option to build/run tests
#
build_tests=yes
AC_ARG_ENABLE([tests], AS_HELP_STRING([--disable-tests],
                                    [do not build the tests]),
                     build_tests=$enableval, build_tests=yes)
AM_CONDITIONAL([BUILD_TESTS], [test "x$build_tests" != xno])


AC_SUBST(LIBSCUTE_LT_CURRENT)
AC_SUBST(LIBSCUTE_LT_AGE)
AC_SUBST(LIBSCUTE_LT_REVISION)
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
    *-apple-darwin*)
        AC_DEFINE(_DARWIN_C_SOURCE, 900000L,
                  Expose all libc features (__DARWIN_C_FULL).)
        AC_DEFINE(_XOPEN_SOURCE, 500, Activate POSIX interface on MacOS X)
        ;;
esac
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")

#
# Specify how we support our local modification of libtool for Windows
# 64-bit.  Options are:
#
# (1) apply: when appying patch fails, it results failure of entire build
# (2) never: never apply the patch (no try)
# (3) try: use patched if it goes well, use original if fails
#
AC_ARG_WITH([libtool-modification],
  AS_HELP_STRING([--with-libtool-modification=apply|never|try],
                 [how to handle libtool modification (default=never)]),
                 build_libtool_modification=$withval,
                 build_libtool_modification=never)

#
# Apply a patch (locally maintained one of ours) to libtool
#
case $host in
  x86_64-*mingw32*)
AC_CONFIG_COMMANDS([libtool-patch],[[
  if test "$build_selection" = never; then
    echo "patch not applied"
  elif (mv -f libtool libtool.orig; \
        sed -f $srcdir/build-aux/libtool-patch.sed libtool.orig >libtool); then
    echo "applied successfully"
  elif test "$build_selection" = try; then
    mv -f libtool.orig libtool
    echo "patch failed, thus, using original"
  else
    echo "patch failed"
    as_fn_exit 1
  fi
]],[build_selection=$build_libtool_modification])
  ;;
  *)
  ;;
esac

have_w32_system=no
have_darwin_system=no
case "${host}" in
    *-mingw32*)
        # special stuff for Windows NT
	have_w32_system=yes
        ;;
    *-apple-darwin*)
        have_darwin_system=yes
        ;;
    *)
	;;
esac

if test "$have_w32_system" = yes; then
   AC_DEFINE(HAVE_W32_SYSTEM,1, [Defined if we run on a W32 API based system])
fi
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)
AM_CONDITIONAL(HAVE_DARWIN_SYSTEM, test "$have_darwin_system" = yes)

# Generate values for the DLL version info
if test "$have_w32_system" = yes; then
    BUILD_TIMESTAMP=`date --iso-8601=minutes`
    changequote(,)dnl
    BUILD_FILEVERSION=`echo "$VERSION" | sed 's/\([0-9.]*\).*/\1./;s/\./,/g'`
    changequote([,])dnl
    BUILD_FILEVERSION="${BUILD_FILEVERSION}${BUILD_REVISION_DEC}"
fi
AC_SUBST(BUILD_REVISION)
AC_SUBST(BUILD_REVISION_DEC)
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)

# The error code library.  Error codes are sent over the IPC layer and
# have to be interpreted.
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes, have_gpg_error=no)

# The IPC library.
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_VERSION",
                  have_libassuan=yes, have_libassuan=no)



# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_CHECK_FUNCS([ttyname localtime_r timegm stpcpy])

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
*** This library is for example available at
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
		 doc/Makefile
                 src/versioninfo.rc])
AC_OUTPUT

echo "
        Scute v${VERSION} has been configured as follows:

        Revision: mym4_revision  (mym4_revision_dec)
        Platform: $host
"
