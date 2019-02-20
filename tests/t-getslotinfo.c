/* t-getslotinfo.c - Regression test.
 * Copyright (C) 2006, 2008 g10 Code GmbH
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
#include <string.h>

#define PGM "t-getslotinfo"
#include "t-support.h"



int
main (int argc, char *argv[])
{
  int last_argc = -1;
  CK_RV err;
  int loop = 0;
  int token = 0;
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  unsigned int i;

  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " [options]\n"
                 "Options:\n"
                 "  --loop N        Run N times with a 2 second delay.\n"
                 "  --token         Only present tokens\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--loop"))
        {
          argc--; argv++;
          if (argc)
            {
              loop = atoi (*argv);
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "--token"))
        {
          argc--; argv++;
          token = 1;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, "unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  init_cryptoki ();

  err = C_GetSlotList (token, NULL, &slots_count);
  fail_if_err (err);

  printf ("Number of slots%s: %lu\n", token ? " (with tokens)" : "",
	  slots_count);
  if (!slots_count)
    return 0;  /* Nothing to do.  */

  slots = malloc (sizeof (CK_SLOT_ID) * slots_count);
  if (!slots)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (token, slots, &slots_count);
  fail_if_err (err);

 again:
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
	  int any = 0;
	  CK_FLAGS xflags;

	  xflags = info.flags & ~(CKF_TOKEN_PRESENT | CKF_REMOVABLE_DEVICE
				  | CKF_HW_SLOT);
	  printf (" == ");
	  if (info.flags & CKF_TOKEN_PRESENT)
	    {
	      printf ("TOKEN_PRESENT");
	      any = 1;
	    }
	  if (info.flags & CKF_REMOVABLE_DEVICE)
	    {
	      printf ("%sREMOVABLE_DEVICE", any ? " | " : "");
	      any = 1;
	    }
	  if (info.flags & CKF_HW_SLOT)
	    {
	      printf ("%sHW_SLOT", any ? " | " : "");
              any = 1;
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

  if (loop > 0)
    loop--;
  if (loop)
    {
#ifdef WIN32
      Sleep (2*1000);
#else
      sleep (2);  /* Why? */
#endif
      goto again;
    }

  return 0;
}
