/* t-getinfo.c - Regression test.
 * Copyright (C) 2006 g10 Code GmbH
 *
 * This file is part of Scute.
 *
 * Scute is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Scute is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <https://gnu.org/licenses/>.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <stdbool.h>

#include "t-support.h"

int
main (int argc, char *argv[])
{
  CK_RV err;
  CK_INFO info;

  (void) argc;
  (void) argv;

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
  printf ("Library version: %i.%i\n", info.libraryVersion.major,
	  info.libraryVersion.minor);

  return 0;
}
