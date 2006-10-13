/* locking.h - Scute locking interface.
   Copyright (C) 2006 g10 Code GmbH

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

#ifndef LOCKING_H
#define LOCKING_H	1

#include "cryptoki.h"


/* The lock type.  */
typedef void *mutex_t;


/* Initialize the locking support.  ARGS is as provided to
   C_Initialize.  */
CK_RV scute_locking_initialize (CK_C_INITIALIZE_ARGS_PTR args);

/* Finalize the locking support.  ARGS is as provided to
   C_Initialize.  */
void scute_locking_finalize (void);


/* Create a new mutex object.  */
CK_RV scute_mutex_create (mutex_t *mutexp);

/* Destroy an existing mutex object.  */
CK_RV scute_mutex_destroy (mutex_t mutex);

/* Lock a mutex object.  */
CK_RV scute_mutex_lock (mutex_t mutex);

/* Unlock a mutex object.  */
CK_RV scute_mutex_unlock (mutex_t mutex);


/* Scute is single-threaded, thus there is a single global lock taken
   at all entry points except for C_GetFunctionList, C_Initialize,
   C_Finalize and stubs.  */

/* The global lock.  */
extern mutex_t scute_lock;

/* Take the global lock.  */
static inline CK_RV
scute_global_lock (void)
{
  return scute_mutex_lock (scute_lock);
}

/* Release the global lock.  */
static inline void
scute_global_unlock (void)
{
  (void) scute_mutex_unlock (scute_lock);
}

#endif	/* !LOCKING_H */
