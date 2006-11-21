#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
min_automake_version="1.9.3"

# Version number: Remember to change it immediately *after* a release.
#                 Make sure to run  "svn up" before a "make dist".
#                 See below for the LT versions.
#
# The CVS version is usually the next intended release version with
# the string "-cvs" appended.  The reason for this is that tests for a
# specific feature can already be done under the assumption that the
# CVS version is the most recent one in a branch.  To disable the CVS
# version for the real release, just comment out the my_iscvs macro.
# Note, that we are now using Subversion instead of CVS and append the
# SVN revision number to the "cvs" suffix.  To make this most useful
# for snapshot releases please do an "svn up" right before recreating
# the configure script, so that a proper revision number for all files
# is available when running a "make distcheck".
m4_define(my_version, [1.0.0])
m4_define(my_iscvs, yes)
AC_INIT([scute], my_version[]m4_ifdef([my_iscvs], [-cvs[]m4_translit(
               [$Revision: 1179 $],[Ra-z $:])]),
               [marcus@g10code.com])

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:			REVISION++)
#   (Interfaces added/removed/changed:	CURRENT++, REVISION=0)
#   (Interfaces added:			AGE++)
#   (Interfaces removed/changed:	AGE=0)
#
LIBSCUTE_LT_CURRENT=0
LIBSCUTE_LT_AGE=0
LIBSCUTE_LT_REVISION=0

# Version numbers reported by the PKCS #11 module to its users.
VERSION_MAJOR=1
VERSION_MINOR=0

NEED_GPG_ERROR_VERSION=0.7
NEED_LIBASSUAN_VERSION=0.6.10
NEED_GPGSM_VERSION=1.9.6
# Some status variables to give feedback at the end of a configure run.
have_gpg_error=no
have_libassuan=no

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR([src/cryptoki.h])
AC_CONFIG_HEADER([config.h])

dnl FIXME: Enable this with autoconf 2.59.
dnl AC_CONFIG_MACRO_DIR(m4)
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_MAINTAINER_MODE
AC_CANONICAL_HOST

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

# FIXME: We should support setting the CFLAGS by the user.  But
# -std=gnu99 is required.
CFLAGS="-std=gnu99 -Wall -Wno-pointer-sign -g -O3"

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
AC_DISABLE_STATIC
AC_LIBTOOL_WIN32_DLL
AC_LIBTOOL_RC
AC_PROG_LIBTOOL

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

# Checks for libraries.

# The error code library.  Error codes are sent over the IPC layer and
# have to be interpreted.
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes, have_gpg_error=no)

# The IPC library.
AM_PATH_LIBASSUAN("$NEED_LIBASSUAN_VERSION",
                  have_libassuan=yes, have_libassuan=no)

# GPGSM
GPGSM_DEFAULT=no
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

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_REALLOC

# Test if tests can be run
ok=yes
AM_CONDITIONAL(RUN_TESTS, test "$ok" = "yes")


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
                 include/Makefile
                 src/Makefile
                 tests/Makefile
		 doc/manual/Makefile
		 doc/Makefile])
AC_OUTPUT
