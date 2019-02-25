/* p11-decrypt.c - Cryptoki implementation.
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

/* Decrypt the data (ENCDATA,ENCDATALEN) using the information
 * recorded in HSESSION by C_DecryptInit.  R_DATA is a buffer to
 * receive the decrypted data.  The length of that buffer must be
 * stored in a variable to which R_DATALEN points to; on success that
 * length is updated to the actual length of the decrypted data at
 * R_DATA.  In-place decryption is supported; that is ENCDATA and
 * R_DATA may be the same buffer.
 *
 * If the function returns CKR_BUFFER_TOO_SMALL no further
 * C_DecryptInit is required, instead the function can be called again
 * with a larger buffer.  On all other return codes a new
 * C_DecryptInit is required.  However, in contrast to the specs the
 * return code CKR_ARGUMENTS_BAD may not require a new C_DecryptInit
 * because this can be considered a bug in the caller's code.  In case
 * the input cannot be decrypted because it has an inappropriate
 * length, then either CKR_ENCRYPTED_DATA_INVALID or
 * CKR_ENCRYPTED_DATA_LEN_RANGE may be returned.
 */
CK_RV CK_SPEC
C_Decrypt (CK_SESSION_HANDLE hsession,
           CK_BYTE *encdata, CK_ULONG encdatalen,
           CK_BYTE *r_data, CK_ULONG *r_datalen)
{
  CK_RV rv;
  slot_iterator_t slot;
  session_iterator_t sid;

  if (!hsession || !encdata || !r_datalen)
    return CKR_ARGUMENTS_BAD;

  rv = scute_global_lock ();
  if (rv)
    return rv;

  rv = slots_lookup_session (hsession, &slot, &sid);
  if (!rv)
    rv = session_decrypt (slot, sid, encdata, encdatalen, r_data, r_datalen);

  scute_global_unlock ();
  return rv;
}
