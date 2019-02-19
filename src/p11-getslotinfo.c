/* p11-getslotinfo.c - Cryptoki implementation.
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

#include <stdlib.h>
#include <string.h>

#include "cryptoki.h"

#include "agent.h"
#include "locking.h"
#include "support.h"
#include "settings.h"
#include "slots.h"


CK_RV CK_SPEC
C_GetSlotInfo (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  const char *s;
  int minor;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup (slotID, &slot);
  if (err)
    goto out;

  err = slots_update_slot (slot);
  if (err)
    goto out;

  /* FIXME: Query some of this from SCD.  */
  scute_copy_string (pInfo->slotDescription, SLOT_DESCRIPTION, 64);
  scute_copy_string (pInfo->manufacturerID, SLOT_MANUFACTURER_ID, 32);

  pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
  if (slot_token_present (slot))
    pInfo->flags |= CKF_TOKEN_PRESENT;

  /* Use the gpg-agent version for the hardware version.. */
  pInfo->hardwareVersion.major = scute_agent_get_agent_version (&minor);
  pInfo->hardwareVersion.minor = minor;

  /* Use Scute version as Firmware version.  */
  s = PACKAGE_VERSION;
  pInfo->firmwareVersion.major = atoi (s);
  s = strchr (s, '.');
  pInfo->firmwareVersion.minor = s? atoi (s+1): 0;

 out:
  scute_global_unlock ();
  return err;
}
