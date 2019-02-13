/* t-getslotlist.c - Regression test.
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
#include <string.h>

#define PGM "t-getslotlist"
#include "t-support.h"

int
main (int argc, char *argv[])
{
  int last_argc = -1;
  CK_RV err;
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
                 "  --token         Only present tokens\n",
                 stdout);
          exit (0);
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
    return 0;

  slots = malloc (sizeof (CK_SLOT_ID) * slots_count);
  if (!slots)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (token, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    printf ("%2i. Slot ID %lu\n", i, slots[i]);

  return 0;
}
