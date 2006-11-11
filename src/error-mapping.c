/* error-mapping.c - Scute error mapping.
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

#include <errno.h>
#include <error.h>

#include <gpg-error.h>

#include "cryptoki.h"
#include "debug.h"

#include "error-mapping.h"


/* Map a system error code to a cryptoki return value.  */
CK_RV
scute_sys_to_ck (error_t err)
{
  switch (err)
    {
    case 0:
      return CKR_OK;
      
    case ENOMEM:
      return CKR_HOST_MEMORY;

    default:
      /* CKR_GENERAL_ERROR is too strong.  */
      return CKR_FUNCTION_FAILED;
    }
}


/* Map a GnuPG error code to a cryptoki return value.  */
CK_RV
scute_gpg_err_to_ck (gpg_error_t err)
{
  if (err)
    DEBUG ("Error occured: %s (%s)\n", gpg_strerror (err),
	   gpg_strsource (err));

  switch (gpg_err_code (err))
    {
    case GPG_ERR_NO_ERROR:
      return CKR_OK;

    case GPG_ERR_NO_AGENT:
      return CKR_GENERAL_ERROR;

    case GPG_ERR_ENOMEM:
      return CKR_HOST_MEMORY;

    default:
      /* CKR_GENERAL_ERROR is too strong.  */
      return CKR_FUNCTION_FAILED;
    }
}
