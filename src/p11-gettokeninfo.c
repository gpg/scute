/* p11-gettokeninfo.c - Cryptoki implementation.
   Copyright (C) 2006 g10 Code GmbH

   This file is part of Scute[1].

   [1] Derived from the RSA Security Inc. PKCS #11 Cryptographic Token
   Interface (Cryptoki).
 
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

#include "locking.h"
#include "support.h"
#include "settings.h"
#include "slots.h"


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
     (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  int len;
  int max;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup (slotID, &slot);
  if (err)
    goto out;

  if (!slot_token_present (slot))
    {
      err = CKR_TOKEN_NOT_PRESENT;
      goto out;
    }

  scute_copy_string (pInfo->label, slot_token_label (slot), 32);
  scute_copy_string (pInfo->manufacturerID,
		     slot_token_manufacturer (slot), 32);
  scute_copy_string (pInfo->model, slot_token_application (slot), 16);
  len = slot_token_serial (slot, pInfo->serialNumber);
  while (len < 16)
    pInfo->serialNumber[len++] = ' ';

  pInfo->flags = CKF_TOKEN_INITIALIZED
    | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_WRITE_PROTECTED
    | CKF_USER_PIN_INITIALIZED;
  /* FIXME: Support this later: CKF_RNG.
     FIXME: CKF_USER_PIN_INITIALIZED only if PIN is not default pin?
     FIXME: CKF_LOGIN_REQUIRED needed?  We could implement login via
     the "SCD CHECKPIN" command.  I am not sure how this mixes with
     CKF_PROTECTED_AUTHENTICATION_PATH.

     Not supported: 
     CKF_RESTORE_KEY_NOT_NEEDED, CKF_DUAL_CRYPTO_OPERATIONS.

     FIXME: We can support those, but do we worry about SO operations?
     CKF_SO_PIN_COUNT_LOW, CKF_SO_PIN_FINAL_TRY, CKF_SO_PIN_LOCKED.

     Not supported: CKF_USER_PIN_TO_BE_CHANGED, CKF_SO_PIN_TO_BE_CHANGED.  */
  
  slot_token_pincount (slot, &max, &len);
  if (len < max)
    pInfo->flags |= CKF_USER_PIN_COUNT_LOW;
  if (len == 1)
    pInfo->flags |= CKF_USER_PIN_FINAL_TRY;
  else if (len == 0)
    pInfo->flags |= CKF_USER_PIN_LOCKED;

  pInfo->ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
  slot_token_maxpinlen (slot, &pInfo->ulMaxPinLen, &pInfo->ulMinPinLen);

  /* FIXME: Get the data from SCD?  */
  pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  slot_token_version (slot, &pInfo->hardwareVersion.major,
		      &pInfo->hardwareVersion.minor,
		      &pInfo->firmwareVersion.major,
		      &pInfo->firmwareVersion.minor);
  scute_copy_string (pInfo->utcTime, "0000000000000000", 16);

 out:
  scute_global_unlock ();
  return err;
}
