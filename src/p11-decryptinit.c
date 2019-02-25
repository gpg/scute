/* p11-decryptinit.c - Cryptoki implementation.
 * Copyright (C) 2006, 2019 g10 Code GmbH
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


/* Prepare a decryption operation.  HSESSION is the session's handle,
 * MECHANISM points to an object describing the mechanism to be used,
 * and HKEY is a handle to the decryption key.  After calling this
 * function either C_Decrypt or (C_DecryptUpdate, C_DecryptFinal) can
 * be used to actually decrypt the data.  The preparation is valid
 * until a C_Decrypt or C_DecryptFinal.
 */

CK_RV CK_SPEC
C_DecryptInit (CK_SESSION_HANDLE hsession, CK_MECHANISM *mechanism,
               CK_OBJECT_HANDLE hkey)
{
  CK_RV rv;
  slot_iterator_t slot;
  session_iterator_t sid;

  if (!hsession || !mechanism || hkey == CK_INVALID_HANDLE)
    return CKR_ARGUMENTS_BAD;

  rv = scute_global_lock ();
  if (rv)
    return rv;

  rv = slots_lookup_session (hsession, &slot, &sid);
  if (!rv)
    rv = session_init_decrypt (slot, sid, mechanism, hkey);

  scute_global_unlock ();
  return rv;
}
