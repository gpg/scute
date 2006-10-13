/* gpgsm.c - Talking to gpgsm.
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
   to link this library: with the Mozilla Fondations's code for
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

#include <assert.h>
#include <locale.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include <assuan.h>
#include <gpg-error.h>

#include "cryptoki.h"
#include "support.h"
#include "cert.h"


struct search
{
  bool found;
  CK_ATTRIBUTE_PTR *attrp;
  CK_ULONG *attr_countp;
  CK_ATTRIBUTE_PTR *prv_attrp;
  CK_ULONG *prv_attr_countp;
};


static gpg_error_t
search_cb (void *hook, struct cert *cert)
{
  struct search *ctx = hook;
  gpg_error_t err;
  
  /* FIXME: Support more than one certificate.  */
  if (ctx->found)
    return 0;

  /* Turn this into a certificate object.  */
  err = scute_attr_cert (cert, ctx->attrp, ctx->attr_countp);
  if (err)
    return err;

  err = scute_attr_prv (cert, ctx->prv_attrp, ctx->prv_attr_countp);
  if (err)
    {
      scute_attr_free (*ctx->attrp, *ctx->attr_countp);
      *ctx->attrp = NULL;
      *ctx->attr_countp = 0;
    }

  ctx->found = true;
  return err;
}


/* Create the attributes required for a new certificate object.
   Returns allocated attributes for the certificate object in ATTRP
   and ATTR_COUNTP, and for the private key object in PRV_ATTRP
   and PRV_ATTR_COUNTP.  */
gpg_error_t
gpgsm_get_cert (char *grip, CK_ATTRIBUTE_PTR *attrp, CK_ULONG *attr_countp,
		CK_ATTRIBUTE_PTR *prv_attrp, CK_ULONG *prv_attr_countp)
{
  gpg_error_t err;
  struct search search;

  *attrp = NULL;
  *attr_countp = 0;
  *prv_attrp = NULL;
  *prv_attr_countp = 0;

  search.found = false;
  search.attrp = attrp;
  search.attr_countp = attr_countp;
  search.prv_attrp = prv_attrp;
  search.prv_attr_countp = prv_attr_countp;

  err = scute_gpgsm_search_certs_by_grip (grip, search_cb, &search);
  
  return err;
}
