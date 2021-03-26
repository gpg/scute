# Makefile.am - Doc directory Makefile for scute.
# Copyright (C) 2006, 2007 g10 Code GmbH
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

images = firefox-cm.png firefox-cm-view-detail.png firefox-cm-view.png \
	firefox-dm-load-after.png firefox-dm-load-before.png \
	firefox-dm-load.png firefox-dm-token-present.png firefox-pref.png \
	firefox-pref-view.png firefox-bad-pin.png \
	thunderbird-account-settings.png thunderbird-smime-button.png \
	libreoffice-certificate-selection.png \
	libreoffice-digital-signatures.png libreoffice-pdf-signature.png

EXTRA_DIST = $(images)

DISTCLEANFILES = scute.tmp yat2m-stamp.tmp yat2m-stamp $(myman_pages)


info_TEXINFOS = scute.texi
scute_TEXINFOS = lesser.texi

YAT2M = yat2m
YAT2M_OPTIONS = -I $(srcdir) \
	--release "Scute @PACKAGE_VERSION@" --source "Scute"

myman_sources = scute.texi
myman_pages   = scute.7

man_MANS = $(myman_pages)


yat2m-stamp: $(myman_sources)
	@rm -f yat2m-stamp.tmp
	@touch yat2m-stamp.tmp
	for file in $(myman_sources) ; do \
            $(YAT2M) $(YAT2M_OPTIONS) --store \
	          `test -f '$$file' || echo '$(srcdir)/'`$$file ; done
	@mv -f yat2m-stamp.tmp $@

$(myman_pages) : yat2m-stamp
	@if test -f $@; then :; else \
            trap 'rm -rf yat2m-stamp yat2m-lock' 1 2 13 15; \
               if mkdir yat2m-lock 2>/dev/null; then \
                 rm -f yat2m-stamp; \
                 $(MAKE) $(AM_MAKEFLAGS) yat2m-stamp; \
                 rmdir yat2m-lock; \
               else \
                 while test -d yat2m-lock; do sleep 1; done; \
                 test -f yat2m-stamp; exit $$?; \
               fi; \
             fi


# Make sure that scute.texi is touched if any other source file has
# been modified.  This is required so that the version.texi magic
# updates the release date.
scute.texi : $(scute_TEXINFOS) $(images)
	touch $(srcdir)/scute.texi


online: scute.html scute.pdf
	set -e; \
	echo "Uploading current manuals to www.gnupg.org ..."; \
	for f in $(images); do \
          cp $(srcdir)/$$f scute.html/; \
	done ; \
        user=werner ; webhost="ftp.gnupg.org"; \
	rsync -v scute.pdf \
              $${user}@$${webhost}:webspace/manuals/ ; \
	cd scute.html ; \
        rsync -vr -C .  \
              $${user}@$${webhost}:webspace/manuals/scute/
