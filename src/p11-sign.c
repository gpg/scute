/* p11-sign.c - Cryptoki implementation.
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


/* Sign the data (PDATA,ULDATALEN) using the information recorded in
 * the HSESSION by C_SignInit.  PSIGNAURE is a buffer to receive the
 * signature.  The length of that buffer must be stored in a variable
 * to which PULSIGNATURELEN points to; on success that length is
 * updated to the actual length of the signature in PULSIGNATURE.
 *
 * If the function returns CKR_BUFFER_TOO_SMALL no further C_SignInit
 * is required, instead the function can be called again with a larger
 * buffer.  On a successful operation CKR_OK is returned and other
 * signatures may be created without an new C_SignInit.  On all other
 * return codes a new C_SignInit is required.
 */
CK_RV CK_SPEC
C_Sign (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
        CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  session_iterator_t session;

  if (pData == NULL_PTR || pulSignatureLen == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &session);
  if (err)
    goto out;

  /* FIXME: Check that C_SignInit has been called.  */

  err = session_sign (slot, session, pData, ulDataLen,
		      pSignature, pulSignatureLen);

 out:
  /* FIXME: Update the flag which indicates whether C_SignInit has
   * been called.  */
  scute_global_unlock ();
  return err;
}
