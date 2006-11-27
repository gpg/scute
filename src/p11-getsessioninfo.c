/* p11-getsessioninfo.c - Cryptoki implementation.
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

#include <assert.h>

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
     (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  session_iterator_t session;
  bool rw;

  if (pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &session);
  if (err)
    goto out;

  err = slots_update_slot (slot);
  if (err)
    goto out;

  /* We have to re-lookup the session handle, as it might just have
     become invalid.  */
  err = slots_lookup_session (hSession, &slot, &session);
  if (err)
    goto out;

  rw = session_get_rw (slot, session);
  switch (slot_get_status (slot))
    {
    case SLOT_LOGIN_PUBLIC:
      pInfo->state = rw ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
      break;

    case SLOT_LOGIN_USER:
      pInfo->state = rw ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
      break;

    case SLOT_LOGIN_SO:
      assert (rw);
      pInfo->state = CKS_RW_SO_FUNCTIONS;
      break;

    default:
      assert (!"Unhandled slot login state.");
      break;
    }

  pInfo->slotID = slot_get_id (slot);
  pInfo->flags = CKF_SERIAL_SESSION
    | (rw ? CKF_RW_SESSION : 0);
  pInfo->ulDeviceError = 0;

 out:
  scute_global_unlock ();
  return err;
}
