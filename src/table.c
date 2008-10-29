/* table.c - Indexed table implementation.
   Copyright (C) 2006, 2007 g10 Code GmbH

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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <assert.h>

#include <gpg-error.h>

#include "table.h"

/* Indices are 1 based externally, but 0 based internally.  */
#define INDEX_COPY_IN(idx) ((idx) - 1)
#define INDEX_COPY_OUT(idx) ((idx) + 1)

/* End of table marker.  */
#define INDEX_EOT (-1)


/* This is an indexed list implementation.  It only supports storing
   and retrieving pointers.  One would like to support arbitrary data
   types inline, but this is not possible in a portable manner,
   because of aliasing and alignment restrictions.

   Note that this implementation is only fast if the lists are very
   short.  */

struct scute_table
{
  /* The user data pointers.  */
  void **data;

  /* The size of DATA.  */
  int size;

  /* The number of used entries in DATA.  */
  int used;

  /* The index of the lowest entry that is unused.  */
  int first_free;

  /* The index after the highest entry that is used.  */
  int last_used;

  /* The allocator and deallocator callback.  */
  scute_table_alloc_cb_t alloc;
  scute_table_dealloc_cb_t dealloc;
};


/* Some support functions for iteration.  */

/* Return the first element in TABLE.  */
static int
index_first (scute_table_t table)
{
  int index = 0;

  while (index < table->last_used && table->data[index] == NULL)
    index++;

  if (index == table->last_used)
    return INDEX_EOT;

  return index;
}


/* Return the element following INDEX, or the end-of-list marker if
   INDEX is the last element on the list.  */
static int
index_next (scute_table_t table, int index)
{
  index++;

  while (index < table->last_used && table->data[index] == NULL)
    index++;

  if (index >= table->last_used)
    index = INDEX_EOT;

  return index;
}


/* TABLE interface implementation.  */

/* Create a new table and return it in TABLE_R.  */
gpg_error_t
scute_table_create (scute_table_t *table_r,
				scute_table_alloc_cb_t alloc,
				scute_table_dealloc_cb_t dealloc)
{
  scute_table_t table;

  table = malloc (sizeof (*table));
  if (!table)
    return gpg_error_from_syserror ();

  table->data = NULL;
  table->size = 0;
  table->used = 0;
  table->first_free = 0;
  table->last_used = 0;
  table->alloc = alloc;
  table->dealloc = dealloc;

  *table_r = table;
  return 0;
}


/* Destroy the indexed list TABLE.  The user has to make sure that the
   existing entries are not needed anymore before calling this
   function.  */
void
scute_table_destroy (scute_table_t table)
{
  int idx = 0;

  if (table == NULL)
    return;

  for (idx = 0; idx < table->last_used; idx++)
    if (table->data[idx] != NULL)
      (*table->dealloc) (table->data[idx]);

  if (table->data)
    free (table->data);
  free (table);
}


/* The initial table size.  */
#define TABLE_START_SIZE	4

/* Allocate a new table entry with a free index.  Returns the index
   pointing to the new list entry in INDEX_R.  This calls the
   allocator on the new entry before returning.  Also returns the
   table entry in *DATA_R if this is not NULL.  */
gpg_error_t
scute_table_alloc (scute_table_t table, int *index_r, void **data_r,
		   void *hook)
{
  gpg_error_t err;
  int idx;
  void *data;

  if (table->used == table->size)
    {
      unsigned int size_new = table->size ? 2 * table->size : TABLE_START_SIZE;
      void *data_new;

      data_new = realloc (table->data, size_new * sizeof (*(table->data)));
      if (!data_new)
	return gpg_error_from_syserror ();

      table->first_free = table->size;
      table->data = data_new;
      table->size = size_new;
    }

  /* We may needlessly have increased the table size if this fails,
     but that is not a problem.  */
  err = (*table->alloc) (&data, hook);
  if (err)
    return err;

  for (idx = table->first_free; idx < table->last_used; idx++)
    if (table->data[idx] == NULL)
      break;

  /* The following setting for FIRST_FREE is safe, because if this was
     the last table entry, then the table is full and we will grow the
     table the next time we are called (if no elements are removed in
     the meantime.  */
  table->first_free = idx + 1;

  if (idx == table->last_used)
    table->last_used++;

  table->data[idx] = data;
  table->used++;

  *index_r = INDEX_COPY_OUT (idx);
  if (data_r != NULL)
    *data_r = data;

  return 0;
}


/* Deallocate the list entry index.  Afterwards, INDEX points to the
   following entry.  This calls the deallocator on the entry before
   returning.  */
void
scute_table_dealloc (scute_table_t table, int *index)
{
  int idx = INDEX_COPY_IN (*index);
  void *data = NULL;

  if (idx == INDEX_EOT)
    return;

  assert (idx >= 0 && idx < table->last_used);
  assert (table->data[idx] != NULL);

  data = table->data[idx];
  table->data[idx] = NULL;

  table->used--;

  if (idx < table->first_free)
    table->first_free = idx;

  /* Update TABLE->last_used if necessary.  */
  if (idx + 1 == table->last_used)
    while (table->last_used > 0)
      {
	if (table->data[table->last_used - 1] != NULL)
	  break;
	table->last_used--;
      }

  *index = INDEX_COPY_OUT (index_next (table, idx));

  (*table->dealloc) (data);
}


/* Return the iterator for the beginning of the list TABLE.  */
int
scute_table_first (scute_table_t table)
{
  if (table->used)
    {
      if (table->data[0] != NULL)
	return INDEX_COPY_OUT (0);
      else
	return INDEX_COPY_OUT (index_first (table));
    }

  return 0;
}


/* Return the index following INDEX.  If INDEX is the last element in
   the list, return 0.  */
int
scute_table_next (scute_table_t table, int index)
{
  int idx = INDEX_COPY_IN (index);

  if (idx == INDEX_EOT)
    return 0;

  idx = index_next (table, idx);
  return INDEX_COPY_OUT (idx);
}


/* Return true iff INDEX is the end-of-list marker.  */
bool
scute_table_last (scute_table_t table, int index)
{
  return INDEX_COPY_IN (index) == INDEX_EOT;
}


/* Return the user data associated with INDEX.  Return NULL if INDEX
   is not valid.  */
void *
scute_table_data (scute_table_t table, int index)
{
  int idx = INDEX_COPY_IN (index);

  if (idx >= 0 && idx < table->last_used)
    return table->data[idx];

  return NULL;
}


/* Return the number of entries in the table TABLE.  */
int
scute_table_used (scute_table_t table)
{
  return table->used;
}
