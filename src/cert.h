/* cert.h - Scute certificate management.
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

#ifndef CERT_H
#define CERT_H	1

#include <stdbool.h>
#include <time.h>

#include <gpg-error.h>
#include <assuan.h>

#include "cryptoki.h"


/* A certificate structure holds all information of a certificate
   during a certificate search.  */
struct cert
{
  /* True if we started to fill in a certificate.  */
  bool valid;

  /* The key length.  */
  int length;

  /* The public key algorithm.  */
  int pubkey_algo;

  /* The key ID.  */
  unsigned char keyid[17];

  /* The timestamp.  */
  time_t timestamp;

  /* The expiration time.  */
  time_t expires;

  /* The X.509 serial number.  */
  char *issuer_serial;

  /* The X.509 issuer name.  */
  char *issuer_name;

  /* The user ID strings.  */
  char *uid;

  /* The fingerprint.  */
  unsigned char fpr[41];

  /* The key grip.  */
  unsigned char grip[41];

  /* The certificate in DER format.  This is not entered by the search
     function, but afterwards by the filter before converting it into
     a PKCS #11 object.  */
#define MAX_CERT_SIZE 4096
  unsigned char cert_der[MAX_CERT_SIZE];
  int cert_der_len;
};


/* From cert-gpgsm.c.  */

/* The callback type invoked for each certificate found in the
   search.  */
typedef gpg_error_t (*cert_search_cb_t) (void *hook, struct cert *cert);

/* Invoke SEARCH_CB for each certificate found using assuan connection
   CTX to GPGSM.  */
gpg_error_t scute_gpgsm_search_certs_by_grip (const char *grip,
					      cert_search_cb_t search_cb,
					      void *search_cb_hook);


/* From cert-object.c.  */

gpg_error_t scute_attr_cert (struct cert *cert,
			     CK_ATTRIBUTE_PTR *attrp, CK_ULONG *attr_countp);

gpg_error_t scute_attr_prv (struct cert *cert, CK_ATTRIBUTE_PTR *attrp,
			    CK_ULONG *attr_countp);

void scute_attr_free (CK_ATTRIBUTE_PTR attr, CK_ULONG attr_count);

#endif	/* !CERT_H */
