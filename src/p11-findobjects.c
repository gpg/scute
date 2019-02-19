/* p11-findobjects.c - Cryptoki implementation.
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
#include <string.h>

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))


CK_RV CK_SPEC
C_FindObjects (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
               CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
  CK_RV err = CKR_OK;
  CK_ULONG count;
  slot_iterator_t slot;
  session_iterator_t session;
  object_iterator_t *oids;
  int oids_len;

  if (!pulObjectCount)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &session);
  if (err)
    goto out;

  err = session_get_search_result (slot, session, &oids, &oids_len);
  assert (!err);

  count = MIN ((int) ulMaxObjectCount, oids_len);
  memcpy (phObject, oids, sizeof (CK_OBJECT_HANDLE) * count);

  oids_len = oids_len - count;
  memmove (oids, oids + count, sizeof (CK_OBJECT_HANDLE) * oids_len);
  err = session_set_search_result (slot, session, oids, oids_len);
  assert (!err);

  *pulObjectCount = count;

 out:
  scute_global_unlock ();
  return err;
}
