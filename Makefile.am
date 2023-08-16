# Makefile.am - Top level Makefile for scute.
# Copyright (C) 2006 g10 Code GmbH
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

AM_DISTCHECK_DVI_TARGET = pdf

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2 no-dist-gzip

EXTRA_DIST = autogen.sh README.GIT VERSION build-aux/libtool-patch.sed

if RUN_TESTS
tests = tests
else
tests =
endif

if BUILD_DOC
doc = doc
else
doc =
endif

SUBDIRS = m4 src ${tests} ${doc}

dist-hook: gen-ChangeLog

distcheck-hook:
	set -e; ( \
	pref="#+macro: scute_" ;\
	reldate="$$(date -u +%Y-%m-%d)" ;\
        echo "$${pref}ver  $(PACKAGE_VERSION)"  ;\
        echo "$${pref}date $${reldate}" ;\
        list='$(DIST_ARCHIVES)'; for i in $$list; do \
	  case "$$i" in *.tar.bz2) \
            echo "$${pref}size $$(wc -c <$$i|awk '{print int($$1/1024)}')k" ;\
	    echo "$${pref}sha1 $$(sha1sum <$$i|cut -d' ' -f1)" ;\
	    echo "$${pref}sha2 $$(sha256sum <$$i|cut -d' ' -f1)" ;;\
	  esac;\
	done ) | tee $(distdir).swdb

.PHONY: gen-ChangeLog release sign-release

gen_start_date = 2011-12-01T00:00:00
gen-ChangeLog:
	if test -d $(top_srcdir)/.git; then				\
	  (cd $(top_srcdir) &&                      			\
	    $(GITLOG_TO_CHANGELOG) --append-dot --tear-off		\
	    --amend=build-aux/git-log-fix				\
	    --since=$(gen_start_date) ) > $(distdir)/cl-t;		\
          cat $(top_srcdir)/build-aux/git-log-footer >> $(distdir)/cl-t;\
	  rm -f $(distdir)/ChangeLog;					\
	  mv $(distdir)/cl-t $(distdir)/ChangeLog;			\
	fi
