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

# The same as images but eps suffix.
images_eps = firefox-cm.eps firefox-cm-view-detail.eps firefox-cm-view.eps \
	firefox-dm-load-after.eps firefox-dm-load-before.eps \
	firefox-dm-load.eps firefox-dm-token-present.eps firefox-pref.eps \
	firefox-pref-view.eps firefox-bad-pin.eps \
	thunderbird-account-settings.eps thunderbird-smime-button.eps \
	libreoffice-certificate-selection.eps \
	libreoffice-digital-signatures.eps libreoffice-pdf-signature.eps


EXTRA_DIST = $(images)

CLEANFILES =  $(images_eps)
DISTCLEANFILES = scute.tmp

BUILT_SOURCES = $(images_eps)

info_TEXINFOS = scute.texi
scute_TEXINFOS = lesser.texi

.png.eps:
	$(CONVERT) `test -f '$<' || echo '$(srcdir)/'`$< $@

.png.pdf:
	$(CONVERT) `test -f '$<' || echo '$(srcdir)/'`$< $@


# Do not include the generated EPS files.
dist-hook:
	cd $(distdir) && rm -f $(images_eps)


# Make sure that scute.texi is touched if any other source file has
# been modified.  This is required so that the version.texi magic
# updates the release date.
scute.texi : $(scute_TEXINFOS) $(images)
	touch $(srcdir)/scute.texi
