/* p11-generatekeypair.c - Cryptoki implementation.
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


CK_RV CK_SPEC
C_GenerateKeyPair (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                   CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                   CK_ULONG ulPublicKeyAttributeCount,
                   CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                   CK_ULONG ulPrivateKeyAttributeCount,
                   CK_OBJECT_HANDLE_PTR phPublicKey,
                   CK_OBJECT_HANDLE_PTR phPrivateKey)
{
  (void) hSession;
  (void) pMechanism;
  (void) pPublicKeyTemplate;
  (void) ulPublicKeyAttributeCount;
  (void) pPrivateKeyTemplate;
  (void) ulPrivateKeyAttributeCount;
  (void) phPublicKey;
  (void) phPrivateKey;
  return CKR_FUNCTION_NOT_SUPPORTED;
}
