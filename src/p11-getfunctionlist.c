/* p11-getfunctionlist.c - Cryptoki implementation.
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

#include "cryptoki.h"

#include "settings.h"


/* The list of exported functions.  */
static CK_FUNCTION_LIST function_list =
  {
    version: { major: VERSION_MAJOR, minor: VERSION_MINOR },
    C_Initialize: C_Initialize,
    C_Finalize: C_Finalize,
    C_GetInfo: C_GetInfo,
    C_GetFunctionList: C_GetFunctionList,
    C_GetSlotList: C_GetSlotList,
    C_GetSlotInfo: C_GetSlotInfo,
    C_GetTokenInfo: C_GetTokenInfo,
    C_GetMechanismList: C_GetMechanismList,
    C_GetMechanismInfo: C_GetMechanismInfo,
    C_InitToken: C_InitToken,
    C_InitPIN: C_InitPIN,
    C_SetPIN: C_SetPIN,
    C_OpenSession: C_OpenSession,
    C_CloseSession: C_CloseSession,
    C_CloseAllSessions: C_CloseAllSessions,
    C_GetSessionInfo: C_GetSessionInfo,
    C_GetOperationState: C_GetOperationState,
    C_SetOperationState: C_SetOperationState,
    C_Login: C_Login,
    C_Logout: C_Logout,
    C_CreateObject: C_CreateObject,
    C_CopyObject: C_CopyObject,
    C_DestroyObject: C_DestroyObject,
    C_GetObjectSize: C_GetObjectSize,
    C_GetAttributeValue: C_GetAttributeValue,
    C_SetAttributeValue: C_SetAttributeValue,
    C_FindObjectsInit: C_FindObjectsInit,
    C_FindObjects: C_FindObjects,
    C_FindObjectsFinal: C_FindObjectsFinal,
    C_EncryptInit: C_EncryptInit,
    C_Encrypt: C_Encrypt,
    C_EncryptUpdate: C_EncryptUpdate,
    C_EncryptFinal: C_EncryptFinal,
    C_DecryptInit: C_DecryptInit,
    C_Decrypt: C_Decrypt,
    C_DecryptUpdate: C_DecryptUpdate,
    C_DecryptFinal: C_DecryptFinal,
    C_DigestInit: C_DigestInit,
    C_Digest: C_Digest,
    C_DigestUpdate: C_DigestUpdate,
    C_DigestKey: C_DigestKey,
    C_DigestFinal: C_DigestFinal,
    C_SignInit: C_SignInit,
    C_Sign: C_Sign,
    C_SignUpdate: C_SignUpdate,
    C_SignFinal: C_SignFinal,
    C_SignRecoverInit: C_SignRecoverInit,
    C_SignRecover: C_SignRecover,
    C_VerifyInit: C_VerifyInit,
    C_Verify: C_Verify,
    C_VerifyUpdate: C_VerifyUpdate,
    C_VerifyFinal: C_VerifyFinal,
    C_VerifyRecoverInit: C_VerifyRecoverInit,
    C_VerifyRecover: C_VerifyRecover,
    C_DigestEncryptUpdate: C_DigestEncryptUpdate,
    C_DecryptDigestUpdate: C_DecryptDigestUpdate,
    C_SignEncryptUpdate: C_SignEncryptUpdate,
    C_DecryptVerifyUpdate: C_DecryptVerifyUpdate,
    C_GenerateKey: C_GenerateKey,
    C_GenerateKeyPair: C_GenerateKeyPair,
    C_WrapKey: C_WrapKey,
    C_UnwrapKey: C_UnwrapKey,
    C_DeriveKey: C_DeriveKey,
    C_SeedRandom: C_SeedRandom,
    C_GenerateRandom: C_GenerateRandom,
    C_GetFunctionStatus: C_GetFunctionStatus,
    C_CancelFunction: C_CancelFunction,
    C_WaitForSlotEvent: C_WaitForSlotEvent
  };


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)
     (CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  /* This is one of the few functions which do not need to take the
     global lock.  */

  if (ppFunctionList == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  *ppFunctionList = &function_list;

  return CKR_OK;
}
