/* p11-opensession.c - Cryptoki implementation.
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

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
     (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
      CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  session_iterator_t session;

  if (!(flags & CKF_SERIAL_SESSION))
    return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

  /* We only support read-only operation for now.  */
  if (flags & CKF_RW_SESSION)
    return CKR_TOKEN_WRITE_PROTECTED;

  /* We ignore the notification callback data in pApplication and
     Notify.  We never call back into the application.  */

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup (slotID, &slot);
  if (err)
    goto out;
  
  err = slot_create_session (slot, &session, flags & CKF_RW_SESSION);
  if (err)
    goto out;
  
  /* FIXME: Further initialisation comes here.  */
  
  *phSession = session;

 out:
  scute_global_unlock ();
  return err;
}
