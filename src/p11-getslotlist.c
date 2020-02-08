/* p11-getslotlist.c - Cryptoki implementation.
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


/* Return the list of available slots.  With TOKENPRESENT set only
 * slots with a present tokens are returned.  If PSLOTLIST is NULL the
 * function only counts the number of slots and stores that number at
 * PULCOUNT.  Further this also updates the internal state and thus
 * this needs to be called to check for new devices.  If PSLOTLIST is
 * not NULL it must point to an array which receives the slot
 * information.  PULCOUNT must point to a variable which initially
 * holds the number of allocated slot items and will be updated on
 * return to the stored number of slot items.
 */
CK_RV CK_SPEC
C_GetSlotList (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
               CK_ULONG_PTR pulCount)
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
      err = slots_update_all ();
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
