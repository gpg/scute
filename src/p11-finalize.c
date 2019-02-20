/* p11-finalize.c - Cryptoki implementation.
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
#ifdef HAVE_W32_SYSTEM
# include <winsock2.h>
# include <windows.h>
#endif

#include "cryptoki.h"

#include "slots.h"
#include "agent.h"
#include "locking.h"


CK_RV CK_SPEC
C_Finalize (CK_VOID_PTR pReserved)
{
  /* This is one of the few functions which do not need to take the
     global lock.  */

  if (pReserved != NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  scute_slots_finalize ();
  scute_agent_finalize ();
  scute_locking_finalize ();

#ifdef HAVE_W32_SYSTEM
  WSACleanup ();
#endif

  return CKR_OK;
}
