/* p11-signinit.c - Cryptoki implementation.
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

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"

/* Prepare a signature operation.  HSESSION is the session's handle.
 * PMECHANISM describes the mechanism to be used.  HKEY describes the
 * key to be used.  After calling this function either C_Sign or
 * (C_SignUpdate, C_SignFinal) can be used to actually sign the data.
 * The preparation is valid until C_Sign or C_SignFinal.   */
CK_RV CK_SPEC
C_SignInit (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
            CK_OBJECT_HANDLE hKey)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  session_iterator_t sid;

  if (pMechanism == NULL_PTR || pMechanism->mechanism != CKM_RSA_PKCS)
    return CKR_ARGUMENTS_BAD;

  if (hKey == CK_INVALID_HANDLE)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &sid);
  if (!err)
    err = session_set_signing_key (slot, sid, hKey);

  scute_global_unlock ();
  return err;
}
