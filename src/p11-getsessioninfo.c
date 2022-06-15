/* p11-getsessioninfo.c - Cryptoki implementation.
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

#include <assert.h>

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"


CK_RV CK_SPEC
C_GetSessionInfo (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
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
