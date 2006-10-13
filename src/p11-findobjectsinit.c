/* p11-findobjectsinit.c - Cryptoki implementation.
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

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "cryptoki.h"

#include "locking.h"
#include "error-mapping.h"
#include "slots.h"


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
     (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  object_iterator_t object;
  object_iterator_t *search_result;
  int search_result_len = 0;

  if (ulCount && pTemplate == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot);
  if (err)
    goto out;

  err = slot_get_object_count (slot, &search_result_len);
  if (err)
    goto out;

  search_result = malloc (search_result_len * sizeof (object_iterator_t));
  if (!search_result)
    {
      err = scute_sys_to_ck (errno);
      goto out;
    }
  search_result_len = 0;

  err = objects_iterate_begin (slot, &object);
  if (err)
    {
      free (search_result);
      goto out;
    }

  while (!objects_iterate_last (slot, &object) && !err)
    {
      CK_ATTRIBUTE_PTR attr;
      CK_ULONG attr_count;

      err = slot_get_object (slot, object, &attr, &attr_count);
      if (!err)
	{
	  CK_ULONG count = ulCount;

	  /* For each template attribute, check if it matches the
	     object.  */
	  while (count--)
	    {
	      CK_ULONG i;

	      for (i = 0; i < attr_count; i++)
		if (attr[i].type == pTemplate[count].type)
		  break;

	      /* Lots of ways not to match.  */
	      if (i == attr_count)
		break;
	      if (pTemplate[count].ulValueLen != attr[i].ulValueLen)
		break;
	      if (memcmp (pTemplate[count].pValue, attr[i].pValue,
			  attr[i].ulValueLen))
		break;
	    }

	  if (count == (CK_ULONG) -1)
	    {
	      /* Got a match.  */
	      search_result[search_result_len++] = object;
	    }

	  err = objects_iterate_next (slot, &object);
	}
    }

  /* Always call this after an iteration.  */
  objects_iterate_end (slot, &object);

  if (err)
    {
      free (search_result);
      goto out;
    }

  err = session_set_search_result (slot, hSession, search_result,
				   search_result_len);

 out:
  scute_global_unlock ();
  return err;
}
