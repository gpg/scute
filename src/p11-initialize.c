/* p11-initialize.c - Cryptoki implementation.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>

#ifdef HAVE_W32_SYSTEM
#define __USE_W32_SOCKETS 1
# include <winsock2.h>
# include <windows.h>
#endif

#include <assuan.h>
#include <gpg-error.h>

#include "cryptoki.h"

#include "settings.h"
#include "locking.h"
#include "agent.h"
#include "error-mapping.h"
#include "slots.h"
#include "debug.h"
#include "options.h"


CK_RV CK_SPEC
C_Initialize (CK_VOID_PTR pInitArgs)
{
  CK_RV err;

#ifdef HAVE_W32_SYSTEM
  WSADATA wsadat;

  WSAStartup (0x202, &wsadat);
#endif

  /* This is one of the few functions which do not need to take the
     global lock.  */

  assuan_set_gpg_err_source (GPG_ERR_SOURCE_ANY);

  _scute_debug_init ();
  _scute_read_conf ();

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
        if (!_scute_opt.assume_single_threaded)
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

  return err;
}
