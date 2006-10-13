/* table.c - Table abstraction implementation.
   Copyright (C) 2004, 2006 Marcus Brinkmann

   This file is part of Scute[1].

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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <string.h>

#include "table.h"


/* Initialize the table TABLE.  */
error_t
hurd_table_init (hurd_table_t table, unsigned int entry_size)
{
  assert (sizeof (entry_size) >= sizeof (void *));

  *table = (struct hurd_table) HURD_TABLE_INITIALIZER (entry_size);
  return 0;
}


/* Destroy the table TABLE.  */
void
hurd_table_destroy (hurd_table_t table)
{
  if (table->data)
    free (table->data);
}


/* The initial table size.  */
#define TABLE_START_SIZE	4

/* Add the table element DATA to the table TABLE.  The index for this
   element is returned in R_IDX.  Note that the data is added by
   copying ENTRY_SIZE bytes into the table (the ENTRY_SIZE parameter
   was provided at table initialization time).  */
error_t
hurd_table_enter (hurd_table_t table, void *data, unsigned int *r_idx)
{
  unsigned int idx;

  if (table->used == table->size)
    {
      unsigned int size_new = table->size ? 2 * table->size : TABLE_START_SIZE;
      void *data_new;

      data_new = realloc (table->data, size_new * table->entry_size);
      if (!data_new)
	return errno;

      table->first_free = table->size;
      table->data = data_new;
      table->size = size_new;
    }

  for (idx = table->first_free; idx < table->init_size; idx++)
    if (_HURD_TABLE_ENTRY_LOOKUP (table, idx) == HURD_TABLE_EMPTY)
      break;

  /* The following setting for FIRST_FREE is safe, because if this was
     the last table entry, then the table is full and we will grow the
     table the next time we are called (if no elements are removed in
     the meantime.  */
  table->first_free = idx + 1;

  if (idx == table->init_size)
    table->init_size++;
  if (idx == table->last_used)
    table->last_used++;

  memcpy (HURD_TABLE_LOOKUP (table, idx), data, table->entry_size);
  table->used++;
  *r_idx = idx;
  return 0;
}
 
