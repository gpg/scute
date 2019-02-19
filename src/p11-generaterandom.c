/* p11-generaterandom.c - Cryptoki implementation.
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
#include "agent.h"
#include "error-mapping.h"


CK_RV CK_SPEC
C_GenerateRandom (CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
  CK_RV err;
  slot_iterator_t slot;
  session_iterator_t session;

  if (pRandomData == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &session);
  if (!err)
    err = scute_gpg_err_to_ck (scute_agent_get_random (pRandomData,
                                                       ulRandomLen));

  scute_global_unlock ();
  return err;
}
