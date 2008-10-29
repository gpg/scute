/* t-auth.c - Regression test.
   Copyright (C) 2006 g10 Code GmbH

   This file is part of Scute.
 
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

CK_RV
dump_one (unsigned char *data, int size)
{
  bool some;
  int i;

  some = false;
  for (i = 0; i < size; i++)
    {
      if (some == false)
	{
	  printf ("     ");
	  some = true;
	}
      printf ("%02x", data[i]);
      if (((i + 1) % 32) == 0)
	{
	  printf ("\n");
	  some = false;
	}
    }
  if (some)
    printf ("\n");

  return 0;
}


CK_RV
sign_with_object (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
  CK_RV err;
  CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
  CK_BYTE data[36] = "01234567890123456789012345678901234";
  CK_BYTE sig[128];
  CK_ULONG sig_len = sizeof (sig);

  err = C_SignInit (session, &mechanism, object);
  if (err)
    return err;

  err = C_Sign (session, data, sizeof (data), sig, &sig_len);
  if (err)
    return err;

  printf ("    Sign Result: Length %lu\n", sig_len);
  err = dump_one (sig, sig_len);
  if (err)
    return err;

  return 0;
}


int
main (int argc, char *argv[])
{
  CK_RV err;
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  unsigned int i;

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
      CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
      CK_ATTRIBUTE attr[] = { { CKA_CLASS, &obj_class, sizeof (obj_class) } };
      CK_OBJECT_HANDLE object;
      CK_ULONG count;

      printf ("%2i. Slot ID %lu\n", i, slots[i]);
      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &session);
      fail_if_err (err);
     
      printf ("    Session ID: %lu\n", session);

      err = C_FindObjectsInit (session, attr, DIM (attr));
      fail_if_err (err);

      do
	{
	  err = C_FindObjects (session, &object, 1, &count);
	  fail_if_err (err);

	  if (count)
	    {
	      printf ("    Object Handle: %lu\n", object);

	      err = sign_with_object (session, object);
	      fail_if_err (err);
	    }
	}
      while (count);

      err = C_FindObjectsFinal (session);
      fail_if_err (err);

      err = C_CloseSession (session);
      fail_if_err (err);
    }

  return 0;
}
