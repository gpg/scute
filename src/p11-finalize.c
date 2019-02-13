/* p11-finalize.c - Cryptoki implementation.
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
#ifdef HAVE_W32_SYSTEM
#define __USE_W32_SOCKETS 1
#include <windows.h>
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
