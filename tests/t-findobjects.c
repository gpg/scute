/* t-findobjects.c - Regression test.
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
   to link this library: with the Mozilla Fondations's code for
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
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  int i;

  init_cryptoki ();

  err = C_GetSlotList (true, NULL, &slots_count);
  fail_if_err (err);

  if (slots_count == 0)
    {
      printf ("Skipping test because no token is present.\n");
      return 0;
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

      err = C_CloseSession (session);
      fail_if_err (err);
    }

  return 0;
}
