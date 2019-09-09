# Makefile.am - Makefile in tests/ for scute.
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

noinst_HEADERS = t-support.h
TESTS = t-link t-getfunctionlist t-initialize t-getinfo t-getslotlist \
	t-getslotinfo t-gettokeninfo t-getmechanismlist t-getmechanisminfo \
	t-opensession t-closeallsessions t-getsessioninfo \
	t-findobjects t-getattribute t-auth t-generaterandom

noinst_PROGRAMS = $(TESTS)

EXTRA_DIST = clean-socketdir

TESTS_ENVIRONMENT = GNUPGHOME=`/bin/pwd` GPG_AGENT_INFO= LC_ALL=C

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src
if HAVE_DARWIN_SYSTEM
LDADD = ../src/libscute.la
else
LDADD = ../src/scute.la
endif

clean-local:
	$(TESTS_ENVIRONMENT) $(srcdir)/clean-socketdir
