/* table.h - Iterative table interface.
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

#ifndef TABLE_H
#define TABLE_H	1

#include <stdbool.h>

#include <gpg-error.h>


/* The indexed list type.  */
struct scute_table;
typedef struct scute_table *scute_table_t;


/* TABLE interface.  */

/* A table entry allocator function callback.  Should return the new
   table entry in DATA_R.  */
typedef gpg_error_t (*scute_table_alloc_cb_t) (void **data_r, void *hook);

/* A table entry deallocator function callback.  */
typedef void (*scute_table_dealloc_cb_t) (void *data);

/* Allocate a new table and return it in TABLE_R.  */
gpg_error_t scute_table_create (scute_table_t *table_r,
				scute_table_alloc_cb_t alloc,
				scute_table_dealloc_cb_t dealloc);

/* Destroy the indexed list TABLE.  This also calls the deallocator on
   all entries.  */
void scute_table_destroy (scute_table_t table);

/* Allocate a new table entry with a free index.  Returns the index
   pointing to the new list entry in INDEX_R.  This calls the
   allocator on the new entry before returning.  Also returns the
   table entry in *DATA_R if this is not NULL.  */
gpg_error_t scute_table_alloc (scute_table_t table, int *index_r,
			       void **data_r, void *hook);

/* Deallocate the list entry index.  Afterwards, INDEX points to the
   following entry.  This calls the deallocator on the entry before
   returning.  */
void scute_table_dealloc (scute_table_t table, int *index);

/* Return the index for the beginning of the list TABLE.  */
int scute_table_first (scute_table_t table);

/* Return the index following INDEX.  If INDEX is the last element in
   the list, return 0.  */
int scute_table_next (scute_table_t table, int index);

/* Return true iff INDEX is the end-of-list marker.  */
bool scute_table_last (scute_table_t table, int index);

/* Return the user data associated with INDEX.  Return NULL if INDEX is
   the end-of-list marker.  */
void *scute_table_data (scute_table_t table, int index);

/* Return the number of entries in the table TABLE.  */
int scute_table_used (scute_table_t table);

#endif	/* !TABLE_H */
