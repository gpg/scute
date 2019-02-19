/* p11-getinfo.c - Cryptoki implementation.
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

#include "support.h"
#include "settings.h"


CK_RV CK_SPEC
C_GetInfo (CK_INFO_PTR pInfo)
{
  if (pInfo == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
  pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
  scute_copy_string (pInfo->manufacturerID, MANUFACTURER_ID, 32);
  pInfo->flags = 0;
  scute_copy_string (pInfo->libraryDescription, LIBRARY_DESCRIPTION, 32);
  pInfo->libraryVersion.major = VERSION_MAJOR;
  pInfo->libraryVersion.minor = VERSION_MINOR;

  return CKR_OK;
}
