/* t-getslotinfo.c - Regression test.
   Copyright (C) 2006, 2008 g10 Code GmbH

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
  bool token = false;
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  unsigned int i;

  (void) argv;

  if (argc > 1)
    token = true;

  init_cryptoki ();

  err = C_GetSlotList (token, NULL, &slots_count);
  fail_if_err (err);

  printf ("Number of slots%s: %lu\n", token ? " (with tokens)" : "",
	  slots_count);
  slots = malloc (sizeof (CK_SLOT_ID) * slots_count);
  if (!slots)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (token, slots, &slots_count);
  fail_if_err (err);

  //  while (1)
    {
  for (i = 0; i < slots_count; i++)
    {
      CK_SLOT_INFO info;

      err = C_GetSlotInfo (slots[i], &info);
      fail_if_err (err);

      printf ("%2i. Slot ID %lu\n", i, slots[i]);

      printf ("    %.64s\n", info.slotDescription);
      printf ("    Manufacturer ID: %.32s\n", info.manufacturerID);
      printf ("    Flags: %#lx", info.flags);
      if (info.flags)
	{
	  bool any = false;
	  CK_FLAGS xflags;

	  xflags = info.flags & ~(CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE
				  | CKF_HW_SLOT);
	  printf (" == ");
	  if (info.flags & CKF_TOKEN_PRESENT)
	    {
	      printf ("TOKEN_PRESENT");
	      any = true;
	    }
	  if (info.flags & CKF_REMOVABLE_DEVICE)
	    {
	      printf ("%sREMOVABLE_DEVICE", any ? " | " : "");
	      any = true;
	    }
	  if (info.flags & CKF_HW_SLOT)
	    {
	      printf ("%sHW_SLOT", any ? " | " : "");
	      any = true;
	    }
	  if (xflags)
	    printf ("%s%#lx", any ? " | " : "", xflags);
	}
      printf ("\n");

      printf ("    Hardware version: %i.%i\n", info.hardwareVersion.major,
	      info.hardwareVersion.minor);
      printf ("    Firmware version: %i.%i\n", info.firmwareVersion.major,
	      info.firmwareVersion.minor);
    }
#ifdef WIN32
  _sleep (2);
#else
  sleep (2);
#endif
    }

  return 0;
}
