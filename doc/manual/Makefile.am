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

DISTCLEANFILES = scute.tmp

images = firefox-cm.png firefox-cm-view-detail.png firefox-cm-view.png \
	firefox-dm-load-after.png firefox-dm-load-before.png \
	firefox-dm-load.png firefox-dm-token-present.png firefox-pref.png \
	firefox-pref-view.png firefox-bad-pin.png \
	thunderbird-account-settings.png thunderbird-smime-button.png \
	libreoffice-certificate-selection.png \
	libreoffice-digital-signatures.png libreoffice-pdf-signature.png

images_eps = $(images:.png=.eps)

EXTRA_DIST = $(images)
CLEANFILES = $(images_eps)

info_TEXINFOS = scute.texi
scute_TEXINFOS = lesser.texi

scute.html: scute.texi $(foreach i,$(images),scute.html/$(i))
	$(MAKEINFO) --html --output "$@" "$<"
scute.html/%.png: %.png
	@mkdir -p scute.html
	cp -v "$<" "$@"

scute.dvi: $(images_eps)
scute.pdf: $(images)

%.eps : %.png
	$(CONVERT) `test -f '$<' || echo '$(srcdir)/'`$< $@
