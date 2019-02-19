/* p11-getmechanisminfo.c - Cryptoki implementation.
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


CK_RV CK_SPEC
C_GetMechanismInfo (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                    CK_MECHANISM_INFO_PTR pInfo)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  mechanism_iterator_t mechanism;

  if (pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup (slotID, &slot);
  if (err)
    goto out;

  err = mechanisms_lookup (slot, &mechanism, type);
  if (err)
    goto out;

  *pInfo = *(mechanism_get_info (slot, mechanism));

 out:
  scute_global_unlock ();
  return CKR_OK;
}
