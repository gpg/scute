/* t-getinfo.c - Regression test.
   Copyright (C) 2006 g10 Code GmbH

   This file is part of scute[1].

   [1] Derived from the RSA Security Inc. PKCS #11 Cryptographic Token
   Interface (Cryptoki).
 
   Scute is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   Scute is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Scute; if not, write to the Free Software Foundation,
   Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

   In addition, as a special exception, g10 Code GmbH gives permission
   to link this library: with the Mozilla Foundation's code for
   Mozilla (or with modified versions of it that use the same license
   as the "Mozilla" code), and distribute the linked executables.  You
   must obey the GNU General Public License in all respects for all of
   the code used other than "Mozilla".  If you modify this file, you
   may extend this exception to your version of the file, but you are
   not obligated to do so.  If you do not wish to do so, delete this
   exception statement from your version.  */

#include <stdio.h>
#include <stdbool.h>

#include "t-support.h"

int
main (int argc, char *argv[])
{
  CK_RV err;
  CK_INFO info;

  init_cryptoki ();

  err = C_GetInfo (&info);
  fail_if_err (err);

  printf ("Cryptoki version: %i.%i\n", info.cryptokiVersion.major, 
	  info.cryptokiVersion.minor);
  if (info.cryptokiVersion.major != 2)
    fail ("Cryptoki major version is not 2");
  if (info.cryptokiVersion.minor != 20)
    fail ("Cryptoki minor version is not 20");

  printf ("Manufacturer ID: %.32s\n", info.manufacturerID);
  printf ("Flags: %#lx\n", info.flags);
  if (info.flags != 0)
    fail ("Flags is not 0");

  printf ("Library description: %.32s\n", info.libraryDescription);
  printf ("Library version: %i.%i\n", info.cryptokiVersion.major, 
	  info.cryptokiVersion.minor);

  return 0;
}
