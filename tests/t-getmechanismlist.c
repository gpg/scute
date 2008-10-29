/* t-getmechanismlist.c - Regression test.
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
      CK_MECHANISM_TYPE_PTR mechanisms;
      CK_ULONG mechanisms_count;
      unsigned int j;

      printf ("%2i. Slot ID %lu\n", i, slots[i]);

      err = C_GetMechanismList (slots[i], NULL, &mechanisms_count);
      fail_if_err (err);

      printf ("    Mechanisms: %lu\n", mechanisms_count);
      mechanisms = malloc (sizeof (CK_MECHANISM_TYPE) * mechanisms_count);
      if (!mechanisms)
	fail_if_err (CKR_HOST_MEMORY);

      err = C_GetMechanismList (slots[i], mechanisms, &mechanisms_count);
      fail_if_err (err);

      for (j = 0; j < mechanisms_count; j++)
	printf ("    %2i. %s\n", j, mechanism_type_str (mechanisms[j]));

      free (mechanisms);
    }

  return 0;
}
