/* t-link.c - Simple linking regression test.
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

#include <stdio.h>

#include "t-support.h"

#define DO_ONE(fnc) printf (#fnc ": %p\n", fnc)

int
main (int argc, char *argv[])
{
  (void) argc;
  (void) argv;

  /* We don't do anything useful.  We just print a list of function
     pointers to avoid elimination of dead code.  */
  DO_ONE (C_CancelFunction);
  DO_ONE (C_CloseAllSessions);
  DO_ONE (C_CloseSession);
  DO_ONE (C_CopyObject);
  DO_ONE (C_CreateObject);
  DO_ONE (C_Decrypt);
  DO_ONE (C_DecryptDigestUpdate);
  DO_ONE (C_DecryptFinal);
  DO_ONE (C_DecryptInit);
  DO_ONE (C_DecryptUpdate);
  DO_ONE (C_DecryptVerifyUpdate);
  DO_ONE (C_DeriveKey);
  DO_ONE (C_DestroyObject);
  DO_ONE (C_Digest);
  DO_ONE (C_DigestEncryptUpdate);
  DO_ONE (C_DigestFinal);
  DO_ONE (C_DigestInit);
  DO_ONE (C_DigestKey);
  DO_ONE (C_DigestUpdate);
  DO_ONE (C_Encrypt);
  DO_ONE (C_EncryptFinal);
  DO_ONE (C_EncryptInit);
  DO_ONE (C_EncryptUpdate);
  DO_ONE (C_Finalize);
  DO_ONE (C_FindObjects);
  DO_ONE (C_FindObjectsFinal);
  DO_ONE (C_FindObjectsInit);
  DO_ONE (C_GenerateKey);
  DO_ONE (C_GenerateKeyPair);
  DO_ONE (C_GenerateRandom);
  DO_ONE (C_GetAttributeValue);
  DO_ONE (C_GetFunctionList);
  DO_ONE (C_GetFunctionStatus);
  DO_ONE (C_GetInfo);
  DO_ONE (C_GetMechanismInfo);
  DO_ONE (C_GetMechanismList);
  DO_ONE (C_GetObjectSize);
  DO_ONE (C_GetOperationState);
  DO_ONE (C_GetSessionInfo);
  DO_ONE (C_GetSlotInfo);
  DO_ONE (C_GetSlotList);
  DO_ONE (C_GetTokenInfo);
  DO_ONE (C_InitPIN);
  DO_ONE (C_InitToken);
  DO_ONE (C_Initialize);
  DO_ONE (C_Login);
  DO_ONE (C_Logout);
  DO_ONE (C_OpenSession);
  DO_ONE (C_SeedRandom);
  DO_ONE (C_SetAttributeValue);
  DO_ONE (C_SetOperationState);
  DO_ONE (C_SetPIN);
  DO_ONE (C_Sign);
  DO_ONE (C_SignEncryptUpdate);
  DO_ONE (C_SignFinal);
  DO_ONE (C_SignInit);
  DO_ONE (C_SignRecover);
  DO_ONE (C_SignRecoverInit);
  DO_ONE (C_SignUpdate);
  DO_ONE (C_UnwrapKey);
  DO_ONE (C_Verify);
  DO_ONE (C_VerifyFinal);
  DO_ONE (C_VerifyInit);
  DO_ONE (C_VerifyRecover);
  DO_ONE (C_VerifyRecoverInit);
  DO_ONE (C_VerifyUpdate);
  DO_ONE (C_WaitForSlotEvent);
  DO_ONE (C_WrapKey);

  return 0;
}
