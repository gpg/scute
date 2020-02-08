/* gpgsm.c - Talking to gpgsm.
 * Copyright (C) 2006, 2008 g10 Code GmbH
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
#include "agent.h"
#include "gpgsm.h"
#include "debug.h"


/* Communication object for search_cb.  */
struct search_cb_parm
{
  bool found;    /* Set to true if a private key object was found.  */
  cert_get_cb_t cert_get_cb;
  void *hook;
  bool with_chain;
  key_info_t kinfo;
};


static gpg_error_t
search_cb (void *hook, struct cert *cert)
{
  struct search_cb_parm *ctx = hook;
  gpg_error_t err = 0;

  CK_ATTRIBUTE_PTR attrp;
  CK_ULONG attr_countp;

  /* Add the private key object only once.  */
  if (!ctx->found)
    {
      err = scute_attr_prv (cert, ctx->kinfo, &attrp, &attr_countp);
      if (err)
	return err;

      err = (*ctx->cert_get_cb) (ctx->hook, attrp, attr_countp);
      if (err)
	{
	  scute_attr_free (attrp, attr_countp);
	  return err;
	}

      ctx->found = true;
    }

  /* Add the certificate chain recursively before adding the
     certificate.  But ignore errors.  If the chain is incomplete, we
     might still be able to proceed, for example with client
     authentication.  */
  if (ctx->with_chain && strcmp (cert->chain_id, cert->fpr))
    scute_gpgsm_search_certs (KEYLIST_BY_FPR, cert->chain_id, search_cb, ctx);

  /* Turn this certificate into a certificate object.  */
  err = scute_attr_cert (cert, ctx->kinfo->grip, &attrp, &attr_countp);
  if (err)
    return err;

  err = (*ctx->cert_get_cb) (ctx->hook, attrp, attr_countp);
  if (err)
    {
      scute_attr_free (attrp, attr_countp);
      return err;
    }

  return err;
}


/* Create the attributes required for a new certificate object.  If
 * KINFO->KEYREF is not NULL it is used to locate the cert directly
 * from the card; if KINFO->KEYREF is NULL or a cert was not found on
 * the card, KINFO->GRIP is used to find the certificate in the local
 * key store of gpgsm.
 *
 * Returns allocated attributes for the certificate object in ATTRP
 * and ATTR_COUNTP, and for the private key object in PRV_ATTRP and
 * PRV_ATTR_COUNTP.  */
gpg_error_t
scute_gpgsm_get_cert (key_info_t kinfo, cert_get_cb_t cert_get_cb, void *hook)
{
  gpg_error_t err;
  struct search_cb_parm search;

  search.found = false;
  search.cert_get_cb = cert_get_cb;
  search.hook = hook;
  search.with_chain = false;
  search.kinfo = kinfo;

  DEBUG (DBG_INFO, "scute_gpgsm_get_cert: keyref='%s'", kinfo->keyref);

  /* If the cert is requested from the card, we try to get it from
   * the card as well.  */
  if (kinfo->keyref)
    {
      struct cert cert;

      memset (&cert, '\0', sizeof (cert));
      err = scute_agent_get_cert (kinfo->keyref, &cert);
      if (!err)
        return search_cb (&search, &cert);
    }

  DEBUG (DBG_INFO, "scute_gpgsm_get_cert: falling back to gpgsm");
  search.with_chain = true;
  err = scute_gpgsm_search_certs (KEYLIST_BY_GRIP, kinfo->grip,
                                  search_cb, &search);
  return err;
}
