/* t-getsessioninfo.c - Regression test.
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
  CK_SESSION_HANDLE_PTR sessions;
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

  sessions = malloc (sizeof (CK_SESSION_HANDLE) * slots_count);
  if (!sessions)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (true, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    {
      CK_SESSION_INFO info;

      printf ("%2i. Slot ID %lu\n", i, slots[i]);
      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &sessions[i]);
      fail_if_err (err);

      printf ("    Session ID: %lu\n", sessions[i]);

      err = C_GetSessionInfo (sessions[i], &info);
      fail_if_err (err);

      printf ("    Slot ID: %lu\n", info.slotID);
      printf ("    State: %s\n", session_state_str (info.state));
      printf ("    Flags: %#lx", info.flags);

      if (info.flags)
	{
	  bool any = false;
	  CK_FLAGS xflags = 0;

	  printf (" == ");
#define DO_FLAG(sym)					\
	  if (info.flags & sym)				\
	    {						\
	      printf ("%s" #sym, any ? " | " : "");	\
	      any = true;				\
              xflags |= sym;				\
	    }
	  DO_FLAG (CKF_RW_SESSION);
	  DO_FLAG (CKF_SERIAL_SESSION);
	  
	  xflags = info.flags & ~xflags;
	  if (xflags)
	    printf ("%s%#lx", any ? " | " : "", xflags);
	}
      printf ("\n");
      printf ("    Device Error: %lu\n", info.ulDeviceError);

      fail_if_err (info.slotID != slots[i] ? CKR_GENERAL_ERROR : 0);
      fail_if_err (info.state != CKS_RO_PUBLIC_SESSION
		   ? CKR_GENERAL_ERROR : 0);
      fail_if_err (info.flags != CKF_SERIAL_SESSION ? CKR_GENERAL_ERROR : 0);
      fail_if_err (info.ulDeviceError ? CKR_GENERAL_ERROR : 0);
    }

  for (i = 0; i < slots_count; i++)
    {
      err = C_CloseSession (sessions[i]);
      fail_if_err (err);
    }

  return 0;
}
