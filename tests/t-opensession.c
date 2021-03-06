/* t-opensession.c - Regression test.
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
#include <string.h>

#define PGM "t-opensession"
#include "t-support.h"


int
main (int argc, char *argv[])
{
  int last_argc = -1;
  CK_RV err;
  CK_SLOT_ID_PTR slots;
  CK_SESSION_HANDLE_PTR sessions;
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
                 "No Options\n",
                 stdout);
          exit (0);
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, "unknown option '%s'\n", *argv);
          exit (1);
        }
    }

  init_cryptoki ();

  err = C_GetSlotList (1, NULL, &slots_count);
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

  sessions = malloc (sizeof (CK_SESSION_HANDLE) * slots_count);
  if (!sessions)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (1, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    {
      printf ("%2i. Slot ID %lu\n", i, slots[i]);
      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &sessions[i]);
      fail_if_err (err);

      printf ("    Session ID: %lu\n", sessions[i]);
    }

  for (i = 0; i < slots_count; i++)
    {
      err = C_CloseSession (sessions[i]);
      fail_if_err (err);
    }

  return 0;
}
