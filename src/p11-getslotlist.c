/* p11-getslotlist.c - Cryptoki implementation.
   Copyright (C) 2006 g10 Code GmbH

   This file is part of Scute[1].

   [1] Derived from the RSA Security Inc. PKCS #11 Cryptographic Token
   Interface (Cryptoki).
 
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


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
     (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
  CK_RV err = CKR_OK;
  CK_ULONG left;
  slot_iterator_t slot;

  if (pulCount == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  if (pSlotList == NULL_PTR)
    {
      err = slots_update ();
      if (err)
	goto out;
    }

  /* Leave LEFT positive for the whole search when only counting.  */
  left = pSlotList ? *pulCount : 1;
  *pulCount = 0;
  err = slots_iterate_first (&slot);
  if (err)
    goto out;

  while (!slots_iterate_last (&slot) && left && !err)
    {
      if (!tokenPresent || slot_token_present (slot))
	{
	  (*pulCount)++;

	  if (pSlotList)
	    {
	      *(pSlotList++) = slot_get_id (slot);
	      left--;
	    }
	}
      err = slots_iterate_next (&slot);
    }

  if (err)
    goto out;

  if (!slots_iterate_last (&slot) && !left)
    {
      err = CKR_BUFFER_TOO_SMALL;
      goto out;
    }

 out:
  scute_global_unlock ();
  return err;
}
