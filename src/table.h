/* table.h - Table abstraction interface.
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
   to link this library: with the Mozilla Foundation's code for
   Mozilla (or with modified versions of it that use the same license
   as the "Mozilla" code), and distribute the linked executables.  You
   must obey the GNU General Public License in all respects for all of
   the code used other than "Mozilla".  If you modify this file, you
   may extend this exception to your version of the file, but you are
   not obligated to do so.  If you do not wish to do so, delete this
   exception statement from your version.  */

#ifndef _HURD_TABLE_H
#define _HURD_TABLE_H	1

#include <errno.h>
#include <stdlib.h>
#include <assert.h>


/* The hurd_table data type is a fancy array.  At initialization time,
   you have to provide the size ENTRY_SIZE of each table entry.  When
   you enter an element, you get an index number in return.  This
   index can be used for fast lookup of table elements.  You access
   the table elements through pointers to the beginning of the each
   block of ENTRY_SIZE bytes.

   Embedded at the beginning of the ENTRY_SIZE bytes in each slot is a
   void pointer.  You can use this void pointer freely for your own
   purpose with the following restriction: In a used table entry, it
   must never be NULL.  NULL at the beginning of a table entry
   indicates an unused (free) table entry.

   The table will grow (and eventually shrink, not yet implemented)
   automatically.  New elements are always allocated from the
   beginning of the table.  This means that when a new element is
   added, the free slot with the lowest index is always used.  This
   makes slot usage predictable and attempts to prevent fragmentation
   and sparse usage.

   Note that tables, unlike hashes, can not be reorganized, because
   the index is not stable under reorganization.

   Of all operations supported, only lookup is immediate.  Entering
   new elements is usually fast, too, unless the first free slot is
   unknown and has to be searched for, or there are no more free slots
   and the table has to be enlarged.

   Iterating over the used elements of the table is always
   of the order of the table size.

   In the future, removing an element can also shrink the table.  In
   order to be able to do this, the implementation keeps track of the
   last used slot.  For this reason, the remove operation is sometimes
   not immediate.  */


/* Because the first element in each table entry is a pointer, the
   table entry should be naturally aligned.  */
#define _HURD_TABLE_ALIGN(x) \
  (((x) + sizeof (void *) - 1) & ~(sizeof (void *) - 1))


/* The value used for empty table entries.  */
#define HURD_TABLE_EMPTY	(NULL)

struct hurd_table
{
  /* The size of one entry.  Must at least be sizeof (void *).  At the
     beginning of each entry, a void * should be present that is
     HURD_TABLE_EMPTY for unused elements and something else for used
     table elements.  */
  unsigned int entry_size;

  /* The number of allocated table entries.  */
  unsigned int size;

  /* The number of table entries that are initialized.  */
  unsigned int init_size;

  /* The number of used table entries.  */
  unsigned int used;

  /* The index of the lowest entry that is unused.  */
  unsigned int first_free;

  /* The index after the highest entry that is used.  */
  unsigned int last_used;

  /* The table data.  */
  char *data;
};
typedef struct hurd_table *hurd_table_t;


#define HURD_TABLE_INITIALIZER(size_of_one)				\
  { .entry_size = _HURD_TABLE_ALIGN (size_of_one), .size = 0,		\
    .init_size = 0, .used = 0, .first_free = 0, .last_used = 0,		\
    .data = NULL }

/* Fast accessor without range check.  */
#define HURD_TABLE_LOOKUP(table, idx)					\
  ((void *) (&(table)->data[(idx) * (table)->entry_size]))

/* For bound checks.  */
#define HURD_TABLE_EXTENT(table)					\
  ((table)->last_used)

/* For bound checks.  */
#define HURD_TABLE_USED(table)						\
  ((table)->used)

/* This is an lvalue for the pointer embedded in the table entry.  */
#define _HURD_TABLE_ENTRY(entry)	(*(void **) (entry))

#define _HURD_TABLE_ENTRY_LOOKUP(table, idx)				\
  _HURD_TABLE_ENTRY (HURD_TABLE_LOOKUP (table, idx))


/* Initialize the table TABLE.  */
error_t hurd_table_init (hurd_table_t table, unsigned int entry_size);


/* Destroy the table TABLE.  */
void hurd_table_destroy (hurd_table_t table);


/* Add the table element DATA to the table TABLE.  The index for this
   element is returned in R_IDX.  Note that the data is added by
   copying ENTRY_SIZE bytes into the table (the ENTRY_SIZE parameter
   was provided at table initialization time).  */
error_t hurd_table_enter (hurd_table_t table, void *data, unsigned int *r_idx);


/* Lookup the table element with the index IDX in the table TABLE.  If
   there is no element with this index, return NULL.  Otherwise a
   pointer to the table entry is returned.  */
static inline void *
hurd_table_lookup (hurd_table_t table, unsigned int idx)
{
  void *result;

  if (idx >= table->init_size)
    return NULL;

  result = HURD_TABLE_LOOKUP (table, idx);
  if (_HURD_TABLE_ENTRY (result) == HURD_TABLE_EMPTY)
    return NULL;

  return result;
}


/* Remove the table element with the index IDX from the table
   TABLE.  */
static inline void
hurd_table_remove (hurd_table_t table, unsigned int idx)
{
  void *entry;

  assert (idx < table->init_size);

  entry = HURD_TABLE_LOOKUP (table, idx);
  assert (_HURD_TABLE_ENTRY (entry) != HURD_TABLE_EMPTY);

  _HURD_TABLE_ENTRY (entry) = HURD_TABLE_EMPTY;

  if (idx < table->first_free)
    table->first_free = idx;

  if (idx + 1 == table->last_used)
    while (table->last_used > 0)
      {
	if (_HURD_TABLE_ENTRY_LOOKUP (table, table->last_used - 1)
	    != HURD_TABLE_EMPTY)
	  break;
	table->last_used--;
      }

  table->used--;
}


/* Iterate over all elements in the table.  You use this macro
   with a block, for example like this:

     error_t err;
     HURD_TABLE_ITERATE (table, idx)
       {
         err = foo (idx);
         if (err)
           break;
       }
     if (err)
       cleanup_and_return ();

   Or even like this:

     HURD_TABLE_ITERATE (ht, idx)
       foo (idx);

   The block will be run for every used element in the table.  Because
   IDX is already a verified valid table index, you can lookup the
   table entry with the fast macro HURD_TABLE_LOOKUP.  */
#define HURD_TABLE_ITERATE(table, idx)					\
  for (unsigned int idx = 0; idx < (table)->last_used; idx++)		\
    if (_HURD_TABLE_ENTRY_LOOKUP ((table), (idx)) != HURD_TABLE_EMPTY)

#endif	/* _HURD_TABLE_H */
