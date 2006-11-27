/* locking.c - Locking support.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif
#include <string.h>


#include "locking.h"

/* Our copy of the initialization arguments.  */
static CK_C_INITIALIZE_ARGS init_args;

/* The global lock.  */
mutex_t scute_lock;


/* Initialize the locking support.  ARGS is as provided to
   C_Initialize.  */
CK_RV
scute_locking_initialize (CK_C_INITIALIZE_ARGS_PTR args)
{
  CK_RV err;

  if (args)
    init_args = *args;

  err = scute_mutex_create (&scute_lock);
  if (err)
    {
      if (args)
	memset (&init_args, 0, sizeof (init_args));
      return err;
    }

  return CKR_OK;
}


/* Finalize the locking support.  ARGS is as provided to
   C_Initialize.  */
void
scute_locking_finalize (void)
{
  (void) scute_mutex_destroy (scute_lock);

  memset (&init_args, 0, sizeof (init_args));
}


CK_RV
scute_mutex_create (mutex_t *mutexp)
{
  if (init_args.CreateMutex)
    return (*init_args.CreateMutex) (mutexp);

  return 0;
}


CK_RV
scute_mutex_destroy (mutex_t mutex)
{
  if (init_args.DestroyMutex)
    return (*init_args.DestroyMutex) (mutex);

  return 0;
}


CK_RV
scute_mutex_lock (mutex_t mutex)
{
  if (init_args.LockMutex)
    return (*init_args.LockMutex) (mutex);

  return 0;
}


CK_RV
scute_mutex_unlock (mutex_t mutex)
{
  if (init_args.LockMutex)
    return (*init_args.UnlockMutex) (mutex);

  return 0;
}
