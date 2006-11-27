/* p11-findobjects.c - Cryptoki implementation.
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
#include <string.h>

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
     (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
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

  count = MIN (ulMaxObjectCount, oids_len);
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
