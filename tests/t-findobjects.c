/* t-findobjects.c - Regression test.
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
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  unsigned int i;

  (void) argc;
  (void) argv;

  init_cryptoki ();

  err = C_GetSlotList (true, NULL, &slots_count);
  fail_if_err (err);

  if (slots_count == 0)
    {
      printf ("Skipping test because no token is present.\n");
      return 77;
    }

  printf ("Number of slots with tokens: %lu\n", slots_count);
  slots = malloc (sizeof (CK_SLOT_ID) * slots_count);
  if (!slots)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (true, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    {
      CK_SESSION_HANDLE session;
      CK_OBJECT_HANDLE object;
      CK_ULONG count;
      CK_BBOOL cert_token = CK_TRUE;
      CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
      CK_ATTRIBUTE attr[]
	= { { CKA_TOKEN, &cert_token, sizeof (cert_token) },
	    { CKA_CLASS, &cert_class, sizeof (cert_class) } };
      unsigned char issuer[] =
        "\x30\x78\x31\x0B\x30\x09\x06\x03\x55\x04\x06\x13\x02\x44\x45\x31"
        "\x16\x30\x14\x06\x03\x55\x04\x0A\x13\x0D\x67\x31\x30\x20\x43\x6F"
        "\x64\x65\x20\x47\x6D\x62\x48\x31\x10\x30\x0E\x06\x03\x55\x04\x0B"
        "\x13\x07\x54\x65\x73\x74\x6C\x61\x62\x31\x1E\x30\x1C\x06\x03\x55"
        "\x04\x03\x13\x15\x67\x31\x30\x20\x43\x6F\x64\x65\x20\x54\x45\x53"
        "\x54\x20\x43\x41\x20\x32\x30\x31\x39\x31\x1F\x30\x1D\x06\x09\x2A"
        "\x86\x48\x86\xF7\x0D\x01\x09\x01\x16\x10\x69\x6E\x66\x6F\x40\x67"
        "\x31\x30\x63\x6F\x64\x65\x2E\x63\x6F\x6D";
      CK_ATTRIBUTE attr2[]
	= { { CKA_ISSUER, issuer, sizeof issuer - 1},
	    { CKA_SERIAL_NUMBER, "\x02\x01\x01", 3 } };

      printf ("%2i. Slot ID %lu\n", i, slots[i]);
      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &session);
      fail_if_err (err);

      printf ("    Session ID: %lu\n", session);

      err = C_FindObjectsInit (session, NULL, 0);
      fail_if_err (err);

      do
	{
	  err = C_FindObjects (session, &object, 1, &count);
	  fail_if_err (err);

	  if (count)
	    printf ("    Object Handle: %lu\n", object);
	}
      while (count);

      printf ("    Template Search: Token, Class\n");
      err = C_FindObjectsInit (session, attr, DIM (attr));
      fail_if_err (err);

      do
	{
	  err = C_FindObjects (session, &object, 1, &count);
	  fail_if_err (err);

	  if (count)
	    printf ("    Object Handle: %lu\n", object);
	}
      while (count);

      err = C_FindObjectsFinal (session);
      fail_if_err (err);

      printf ("    Template Search: Issuer, Serial\n");
      err = C_FindObjectsInit (session, attr2, DIM (attr2));
      fail_if_err (err);

      do
	{
	  err = C_FindObjects (session, &object, 1, &count);
	  fail_if_err (err);

	  if (count)
	    printf ("    Object Handle: %lu\n", object);
	}
      while (count);

      err = C_FindObjectsFinal (session);
      fail_if_err (err);

      err = C_CloseSession (session);
      fail_if_err (err);
    }

  return 0;
}
