/* p11-getattributevalue.c - Cryptoki implementation.
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

#include <string.h>

#include "cryptoki.h"

#include "locking.h"
#include "slots.h"


CK_RV CK_SPEC
C_GetAttributeValue (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                     CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  session_iterator_t session;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;

  if (pTemplate == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &session);
  if (err)
    goto out;

  err = slot_get_object (slot, hObject, &attr, &attr_count);
  if (err)
    goto out;

  while (ulCount--)
    {
      CK_ULONG i;

      for (i = 0; i < attr_count; i++)
	if (attr[i].type == pTemplate[ulCount].type)
	  break;

      if (i == attr_count)
	{
	  pTemplate[ulCount].ulValueLen = -1;
	  err = CKR_ATTRIBUTE_TYPE_INVALID;
	}
      else
	{
	  CK_ATTRIBUTE_PTR attribute = &attr[i];

	  pTemplate[ulCount].ulValueLen = attribute->ulValueLen;

	  if (pTemplate[ulCount].pValue)
	    {
	      if (pTemplate[ulCount].ulValueLen >= attribute->ulValueLen)
		memcpy (pTemplate[ulCount].pValue,
			attribute->pValue, attribute->ulValueLen);
	      else
		{
		  pTemplate[ulCount].ulValueLen = -1;
		  err = CKR_BUFFER_TOO_SMALL;
		}
	    }
	}
    }

 out:
  scute_global_unlock ();
  return err;
}
