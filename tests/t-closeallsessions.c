/* t-closeallsessions.c - Regression test.
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
  CK_SESSION_HANDLE_PTR sessions;
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

  sessions = malloc (sizeof (CK_SESSION_HANDLE) * slots_count * 2);
  if (!sessions)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (true, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    {
      printf ("%2i. Slot ID %lu\n", i, slots[i]);
      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &sessions[2 * i]);
      fail_if_err (err);

      printf ("    Session ID 1: %lu\n", sessions[2 * i]);

      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &sessions[2 * i + 1]);
      fail_if_err (err);

      printf ("    Session ID 2: %lu\n", sessions[2 * i + 1]);
    }

  for (i = 0; i < slots_count; i++)
    {
      err = C_CloseAllSessions (slots[i]);
      fail_if_err (err);
    }

  return 0;
}
