/* p11-initialize.c - Cryptoki implementation.
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

#include <stdbool.h>

#include <assuan.h>
#include <gpg-error.h>

#include "cryptoki.h"

#include "settings.h"
#include "locking.h"
#include "agent.h"
#include "error-mapping.h"
#include "slots.h"
#include "debug.h"


CK_DEFINE_FUNCTION(CK_RV, C_Initialize) (CK_VOID_PTR pInitArgs)
{
  CK_RV err;

  /* This is one of the few functions which do not need to take the
     global lock.  */

  assuan_set_gpg_err_source (GPG_ERR_SOURCE_ANY);

  _scute_debug_init ();

  /* Check the threading configuration.  */
  if (pInitArgs != NULL_PTR)
    {
      CK_C_INITIALIZE_ARGS_PTR args = pInitArgs;
      bool callbacks;

      if (args->pReserved != NULL_PTR)
	return CKR_ARGUMENTS_BAD;

      if (NEED_TO_CREATE_THREADS
	  && (args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS))
	return CKR_NEED_TO_CREATE_THREADS;

      /* Either all pointers are provided, or none are.  */
      if (args->CreateMutex == NULL_PTR)
	{
	  if (args->DestroyMutex != NULL_PTR || args->LockMutex != NULL_PTR
	      || args->UnlockMutex != NULL_PTR)
	    return CKR_ARGUMENTS_BAD;

	  callbacks = false;
	}
      else
	{
	  if (args->DestroyMutex == NULL_PTR || args->LockMutex == NULL_PTR
	      || args->UnlockMutex == NULL_PTR)
	    return CKR_ARGUMENTS_BAD;

	  callbacks = true;
	}

      /* FIXME: At this point, we do not support using the native
	 thread package.  */
      if (!callbacks && (args->flags & CKF_OS_LOCKING_OK))
	return CKR_CANT_LOCK;
    }

  err = scute_locking_initialize (pInitArgs);
  if (err)
    return err;

  err = scute_agent_initialize ();
  if (err)
    {
      scute_locking_finalize ();
      return scute_gpg_err_to_ck (err);
    }

  err = scute_slots_initialize ();
  if (err)
    {
      scute_agent_finalize ();
      scute_locking_finalize ();
      return err;
    }

  return err;
}
