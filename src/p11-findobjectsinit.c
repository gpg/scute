/* p11-findobjectsinit.c - Cryptoki implementation.
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

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "cryptoki.h"

#include "locking.h"
#include "error-mapping.h"
#include "slots.h"


CK_RV CK_SPEC
C_FindObjectsInit (CK_SESSION_HANDLE hSession,
                   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  CK_RV err = CKR_OK;
  slot_iterator_t slot;
  session_iterator_t session;
  object_iterator_t object;
  object_iterator_t *search_result;
  int search_result_len = 0;

  if (ulCount && pTemplate == NULL_PTR)
    return CKR_ARGUMENTS_BAD;

  err = scute_global_lock ();
  if (err)
    return err;

  err = slots_lookup_session (hSession, &slot, &session);
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

  err = objects_iterate_first (slot, &object);
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

  if (err)
    {
      free (search_result);
      goto out;
    }

  if (!search_result_len)
    {
      /* We do not yet known about this object.  If CKA_ISSUER and
       * CKA_SERIAL_NUMBER was requested, try to look it up via
       * gpgsm.  The way we can implement this would be a new option to
       * gpgsm's LISTKEYS, named "--der" which takes the raw DER
       * encoding of both items.  The advantage of doing this in gpgsm
       * is that we can use libksba there to build the actual
       * rfc-2253 search string from the DER. */

    }

  err = session_set_search_result (slot, session, search_result,
				   search_result_len);

 out:
  scute_global_unlock ();
  return err;
}
