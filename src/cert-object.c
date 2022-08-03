/* cert-object.c - Convert a GPGSM certificate into a PKCS #11 object.
 * Copyright (C) 2006, 2007 g10 Code GmbH
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

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#include <gpg-error.h>

#include "cryptoki.h"
#include "support.h"
#include "cert.h"
#include "debug.h"


#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))


#if 0 /* Currently not used.  */
static bool
time_to_ck_date (time_t *atime, CK_DATE *ckdate)
{
  struct tm broken_time;
  int nr;

  if (!*atime)
    return false;

#ifdef HAVE_LOCALTIME_R
  if (!localtime_r (atime, &broken_time))
    return false;
#else
  {
    /* FIXME: This is not thread-safe, but it minimizes risk.  */
    struct tm *b_time = localtime (atime);
    if (!b_time)
      return false;
    memcpy (&broken_time, b_time, sizeof (*b_time));
  }
#endif

  /* We can only represent years until 9999.  */
  if (!(broken_time.tm_year >= 0 && broken_time.tm_year <= 8099
	&& broken_time.tm_mon >= 0 && broken_time.tm_mon <= 11
	&& broken_time.tm_mday >= 1 && broken_time.tm_mday <= 31))
    {
      DEBUG (DBG_INFO, "unrepresentable time %i-%i-%i",
	     broken_time.tm_year, broken_time.tm_mon, broken_time.tm_mday);
      return false;
    }

#define LAST_DIGIT(d) (((d) % 10) + '0')
  nr = broken_time.tm_year + 1900;
  ckdate->year[3] = LAST_DIGIT (nr);
  nr = nr / 10;
  ckdate->year[2] = LAST_DIGIT (nr);
  nr = nr / 10;
  ckdate->year[1] = LAST_DIGIT (nr);
  nr = nr / 10;
  ckdate->year[0] = LAST_DIGIT (nr);

  nr = broken_time.tm_mon + 1;
  ckdate->month[1] = LAST_DIGIT (nr);
  nr = nr / 10;
  ckdate->month[0] = LAST_DIGIT (nr);

  nr = broken_time.tm_mday;
  ckdate->day[1] = LAST_DIGIT (nr);
  nr = nr / 10;
  ckdate->day[0] = LAST_DIGIT (nr);

  return true;
}
#endif /*0*/

static gpg_error_t
asn1_get_len (unsigned char **asn1, int *asn1_len, int *rlen)
{
  unsigned char *ptr = *asn1;
  int len = *asn1_len;
  int cnt;
  int result = 0;

  if (len < 1)
    {
      DEBUG (DBG_INFO, "unexpected end of certificate");
      return gpg_error (GPG_ERR_GENERAL);
    }

  if (*ptr & 0x80)
    {
      cnt = *ptr & 0x7f;
      ptr++;
      len--;
    }
  else
    cnt = 1;

  /* We only support a limited number of length bytes.  */
  if (cnt > 2)
    {
      DEBUG (DBG_INFO, "unsupported length field");
      return gpg_error (GPG_ERR_GENERAL);
    }
  if (len < cnt)
    {
      DEBUG (DBG_INFO, "unexpected end of certificate");
      return gpg_error (GPG_ERR_GENERAL);
    }

  while (cnt--)
    {
      result = (result << 8) | *ptr;
      ptr++;
      len--;
    }

  *asn1 = ptr;
  *asn1_len = len;
  *rlen = result;
  return 0;
}


/* A path to an ASN.1 element that can be looked up with
   asn1_get_element.  The last element in the list is returned (that
   one should have ENTER being false.  */
struct asn1_path
{
  unsigned char tag;
  /* True if we should enter the element, false if we should skip
     it.  */
  bool enter;
};

static gpg_error_t
asn1_get_element (unsigned char *cert, int cert_len,
		  unsigned char **sub_start, int *sub_len,
		  struct asn1_path *path, int path_size)
{
  gpg_error_t err;
  unsigned char *prev_certp = NULL;
  unsigned char *certp = cert;
  int cert_left = cert_len;
  int len;
  int i;

  for (i = 0; i < path_size; i++)
    {
      prev_certp = certp;
      if (cert_left < 1)
	{
	  DEBUG (DBG_INFO, "unexpected end of certificate");
	  return gpg_error (GPG_ERR_GENERAL);
	}
      if (*certp != path[i].tag)
	{
	  DEBUG (DBG_INFO, "wrong element in lookup path");
	  return gpg_error (GPG_ERR_GENERAL);
	}
      certp++;
      cert_left--;
      err = asn1_get_len (&certp, &cert_left, &len);
      if (err)
	return err;
      if (!path[i].enter)
	{
	  if (cert_left < len)
	    {
	      DEBUG (DBG_INFO, "unexpected end of certificate");
	      return gpg_error (GPG_ERR_GENERAL);
	    }
	  certp += len;
	  cert_left -= len;
	}
      else
	{
	  /* Special code to deal with ASN.1 data encapsulated in a
	     bit string.  */
	  if (path[i].tag == '\x03')
	    {
	      if (cert_left < 1)
		{
		  DEBUG (DBG_INFO, "unexpected end of certificate");
		  return gpg_error (GPG_ERR_GENERAL);
		}
	      if (*certp != '\x00')
		{
		  DEBUG (DBG_INFO, "expected binary encapsulation missing");
		  return gpg_error (GPG_ERR_GENERAL);
		}
	      certp++;
	      cert_left--;
	    }
	}
    }

  /* We found the subject.  */
  *sub_start = prev_certp;
  *sub_len = certp - prev_certp;

  return 0;
}


static gpg_error_t
asn1_get_issuer (unsigned char *cert, int cert_len,
		 unsigned char **sub_start, int *sub_len)
{
  /* The path to the issuer entry in the DER file.  This is
     Sequence->Sequence->Version,Serial,AlgID,Issuer.  */
  struct asn1_path path[] = { { '\x30', true }, { '\x30', true },
			      { '\xa0', false }, { '\x02', false },
			      { '\x30', false }, { '\x30', false } };

  return asn1_get_element (cert, cert_len, sub_start, sub_len,
			   path, DIM (path));
}


static gpg_error_t
asn1_get_subject (unsigned char *cert, int cert_len,
		  unsigned char **sub_start, int *sub_len)
{
  /* The path to the subject entry in the DER file.  This is
     Sequence->Sequence->Version,Serial,AlgID,Issuer,Time,Subject.  */
  struct asn1_path path[] = { { '\x30', true }, { '\x30', true },
			      { '\xa0', false }, { '\x02', false },
			      { '\x30', false }, { '\x30', false },
			      { '\x30', false }, { '\x30', false } };

  return asn1_get_element (cert, cert_len, sub_start, sub_len,
			   path, DIM (path));
}


static gpg_error_t
asn1_get_serial (unsigned char *cert, int cert_len,
		 unsigned char **sub_start, int *sub_len)
{
  /* The path to the serial entry in the DER file.  This is
     Sequence->Sequence->Version,Serial.  */
  struct asn1_path path[] = { { '\x30', true }, { '\x30', true },
			      { '\xa0', false }, { '\x02', false } };

  return asn1_get_element (cert, cert_len, sub_start, sub_len,
			   path, DIM (path));
}


static gpg_error_t
asn1_get_modulus (unsigned char *cert, int cert_len,
		  unsigned char **sub_start, int *sub_len)
{
  gpg_error_t err;
  int len;
  struct asn1_path path[] = { { '\x30', true }, { '\x30', true },
			      { '\xa0', false }, { '\x02', false },
			      { '\x30', false }, { '\x30', false },
			      { '\x30', false }, { '\x30', false },
			      { '\x30', true }, { '\x30', false },
			      { '\x03', true }, { '\x30', true },
			      { '\x02', false } };

  /* The path to the modulus entry in the DER file.  This is
     Sequence->Sequence->Version,Serial,AlgID,Issuer,Time,Subject,
     Sequence->Sequence,Bitstring->Sequence->Integer,Integer  */

  err = asn1_get_element (cert, cert_len, sub_start, sub_len,
			  path, DIM (path));
  if (err)
    return err;

  if (*sub_len < 1)
    {
      DEBUG (DBG_INFO, "modulus too short");
      return gpg_error (GPG_ERR_GENERAL);
    }

  (*sub_start)++;
  (*sub_len)--;
  err = asn1_get_len (sub_start, sub_len, &len);
  if (err)
    return err;

  /* PKCS #11 expects an unsigned big integer.  */
  while (**sub_start == '\x00' && *sub_len > 0)
    {
      (*sub_start)++;
      (*sub_len)--;
    }

  return 0;
}

static gpg_error_t
asn1_get_public_exp (unsigned char *cert, int cert_len,
		     unsigned char **sub_start, int *sub_len)
{
  gpg_error_t err;
  int len;

  /* The path to the public exp entry in the DER file.  This is
     Sequence->Sequence->Version,Serial,AlgID,Issuer,Time,Subject,
     Sequence->Sequence,Bitstring->Sequence->Integer,Integer  */
  struct asn1_path path[] = { { '\x30', true }, { '\x30', true },
			      { '\xa0', false }, { '\x02', false },
			      { '\x30', false }, { '\x30', false },
			      { '\x30', false }, { '\x30', false },
			      { '\x30', true }, { '\x30', false },
			      { '\x03', true }, { '\x30', true },
			      { '\x02', false }, { '\x02', false } };

  err = asn1_get_element (cert, cert_len, sub_start, sub_len,
			  path, DIM (path));
  if (err)
    return err;

  if (*sub_len < 1)
    {
      DEBUG (DBG_INFO, "public exponent too short");
      return gpg_error (GPG_ERR_GENERAL);
    }

  (*sub_start)++;
  (*sub_len)--;
  err = asn1_get_len (sub_start, sub_len, &len);
  if (err)
    return err;

  /* PKCS #11 expects an unsigned big integer.  */
  while (**sub_start == '\x00' && *sub_len > 0)
    {
      (*sub_start)++;
      (*sub_len)--;
    }

  return 0;
}


static gpg_error_t
attr_one (CK_ATTRIBUTE_PTR attr, CK_ULONG *attr_count,
	  CK_ATTRIBUTE_TYPE type, CK_VOID_PTR val, CK_ULONG size)
{
  CK_ULONG i = *attr_count;
  attr[i].type = type;
  attr[i].ulValueLen = size;
  attr[i].pValue = malloc (size);
  if (attr[i].pValue == NULL)
    {
      DEBUG (DBG_CRIT, "out of memory");
      return gpg_error (GPG_ERR_ENOMEM);
    }
  memcpy (attr[i].pValue, val, size);
  (*attr_count)++;
  return 0;
}


static gpg_error_t
attr_empty (CK_ATTRIBUTE_PTR attr, CK_ULONG *attr_count,
	    CK_ATTRIBUTE_TYPE type)
{
  CK_ULONG i = *attr_count;
  attr[i].type = type;
  attr[i].ulValueLen = 0;
  attr[i].pValue = NULL_PTR;
  (*attr_count)++;
  return 0;
}


void
scute_attr_free (CK_ATTRIBUTE_PTR attr, CK_ULONG attr_count)
{
  while (0 < attr_count--)
    free (attr[attr_count].pValue);
}


gpg_error_t
scute_attr_cert (struct cert *cert, const char *grip,
		 CK_ATTRIBUTE_PTR *attrp, CK_ULONG *attr_countp)
{
  CK_RV err = 0;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;

  unsigned char *subject_start;
  int subject_len;
  unsigned char *issuer_start;
  int issuer_len;
  unsigned char *serial_start;
  int serial_len;

  CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
  CK_BBOOL obj_token = CK_TRUE;
  CK_BBOOL obj_private = CK_FALSE;
  CK_BBOOL obj_modifiable = CK_FALSE;
  CK_CERTIFICATE_TYPE obj_cert_type = CKC_X_509;
  CK_BBOOL obj_trusted = cert->is_trusted;
  CK_ULONG obj_cert_cat = 0;
  CK_BYTE obj_check_value[3] = { '\0', '\0', '\0' };
  CK_DATE obj_start_date;
  CK_DATE obj_end_date;
  CK_ULONG obj_java_midp_sec_domain = 0;

  err = asn1_get_subject (cert->cert_der, cert->cert_der_len,
			  &subject_start, &subject_len);
  if (err)
    {
      DEBUG (DBG_INFO, "rejecting certificate: could not get subject: %s",
	     gpg_strerror (err));
      return err;
    }

  err = asn1_get_issuer (cert->cert_der, cert->cert_der_len,
			 &issuer_start, &issuer_len);
  if (err)
    {
      DEBUG (DBG_INFO, "rejecting certificate: could not get issuer: %s",
	     gpg_strerror (err));
      return err;
    }

  err = asn1_get_serial (cert->cert_der, cert->cert_der_len,
			 &serial_start, &serial_len);
  if (err)
    {
      DEBUG (DBG_INFO, "rejecting certificate: could not get serial: %s",
	     gpg_strerror (err));
      return err;
    }


#define NR_ATTR_CERT 20
  attr = malloc (sizeof (CK_ATTRIBUTE) * NR_ATTR_CERT);
  attr_count = 0;
  if (!attr)
    {
      DEBUG (DBG_INFO, "out of memory");
      return gpg_error (GPG_ERR_ENOMEM);
    }

  if (!err)
    err = attr_one (attr, &attr_count, CKA_CLASS,
                    &obj_class, sizeof obj_class);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_TOKEN,
                    &obj_token, sizeof obj_token);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_PRIVATE,
                    &obj_private, sizeof obj_private);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_MODIFIABLE,
                    &obj_modifiable, sizeof obj_modifiable);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_LABEL, "Scute", 5);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_CERTIFICATE_TYPE,
                    &obj_cert_type, sizeof obj_cert_type);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_TRUSTED,
                    &obj_trusted, sizeof obj_trusted);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_CERTIFICATE_CATEGORY,
                    &obj_cert_cat, sizeof obj_cert_cat);

  /* FIXME: Calculate check_value.  */
  if (!err)
    err = attr_one (attr, &attr_count, CKA_CHECK_VALUE,
                    &obj_check_value, sizeof obj_check_value);

#if 0
  if (time_to_ck_date (&cert->timestamp, &obj_start_date))
    {
      if (!err)
        err = attr_one (attr, &attr_count, CKA_START_DATE,
                        &obj_start_date, sizeof obj_start_date);
    }

  if (time_to_ck_date (&cert->expires, &obj_end_date))
    {
      if (!err)
        err = attr_one (attr, &attr_count, CKA_END_DATE,
                        &obj_end_date, sizeof obj_end_date);
    }
#else
  /* For now, we disable these fields.  We can parse them from the
     certificate just as the other data.  However, we would like to
     avoid parsing the certificates at all, let's see how much
     functionality we really need in the PKCS#11 token first.  */
  (void)obj_start_date;
  (void)obj_end_date;
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_START_DATE);
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_END_DATE);
#endif

  /* Note: This attribute is mandatory.  Without it, Firefox client
     authentication won't work.  */
  if (!err)
    err = attr_one (attr, &attr_count, CKA_SUBJECT,
                    subject_start, subject_len);

  if (!err)
    err = attr_one (attr, &attr_count, CKA_ID, (void *)grip, strlen (grip));

  if (!err)
    err = attr_one (attr, &attr_count, CKA_ISSUER,
                    issuer_start, issuer_len);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_SERIAL_NUMBER,
                    serial_start, serial_len);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_VALUE,
                    cert->cert_der, cert->cert_der_len);

  if (!err)
    err = attr_empty (attr, &attr_count, CKA_URL);
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_HASH_OF_ISSUER_PUBLIC_KEY);

  if (!err)
    err = attr_one (attr, &attr_count, CKA_JAVA_MIDP_SECURITY_DOMAIN,
                    &obj_java_midp_sec_domain, sizeof obj_java_midp_sec_domain);

  if (err)
    {
      DEBUG (DBG_INFO, "could not build certificate object: %s",
	     gpg_strerror (err));
      scute_attr_free (attr, attr_count);
      return err;
    }

  /* FIXME: Not completely safe.  */
  assert (NR_ATTR_CERT >= attr_count);

  *attrp = attr;
  *attr_countp = attr_count;
  return 0;
}


gpg_error_t
scute_attr_prv (struct cert *cert, const char *grip,
                CK_ATTRIBUTE_PTR *attrp, CK_ULONG *attr_countp)
{
  CK_RV err = 0;
  CK_ATTRIBUTE_PTR attr;
  CK_ULONG attr_count;

  unsigned char *subject_start;
  int subject_len;
  unsigned char *modulus_start;
  int modulus_len;
  unsigned char *public_exp_start;
  int public_exp_len;

  CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
  CK_BBOOL obj_token = CK_TRUE;
  CK_BBOOL obj_private = CK_FALSE;
  CK_BBOOL obj_modifiable = CK_FALSE;
  CK_KEY_TYPE obj_key_type = CKK_RSA;
  CK_DATE obj_start_date;
  CK_DATE obj_end_date;
  CK_BBOOL obj_derive = CK_FALSE;
  CK_BBOOL obj_local = CK_FALSE;	/* FIXME: Unknown.  */
  CK_MECHANISM_TYPE obj_key_gen;
  CK_MECHANISM_TYPE obj_mechanisms[1];
  CK_BBOOL obj_sensitive = CK_TRUE;
  CK_BBOOL obj_decrypt = CK_FALSE;      /* Updated below.  */
  CK_BBOOL obj_sign = CK_FALSE;         /* Updated below.  */
  CK_BBOOL obj_sign_recover = CK_FALSE;
  CK_BBOOL obj_unwrap = CK_FALSE;
  CK_BBOOL obj_extractable = CK_FALSE;
  CK_BBOOL obj_always_sensitive = CK_TRUE;
  CK_BBOOL obj_never_extractable = CK_TRUE;
  CK_BBOOL obj_wrap_with_trusted = CK_FALSE;
  CK_BBOOL obj_always_authenticate = CK_FALSE;

  if (cert->pubkey_algo == 1)  /* GCRY_PK_RSA==1 from gpgsm */
    {
      obj_key_gen = CKM_RSA_PKCS_KEY_PAIR_GEN;
      obj_mechanisms[0] = CKM_RSA_PKCS;
    }
  else if (cert->pubkey_algo == 18)  /* GCRY_PK_ECC==18 from gpgsm */
    {
      obj_key_gen = CKM_EC_KEY_PAIR_GEN;
      if (cert->length == 256)
        obj_mechanisms[0] = CKM_ECDSA_SHA256;
      else if (cert->length == 384)
        obj_mechanisms[0] = CKM_ECDSA_SHA384;
      else /* if (cert->length == 512) */
        obj_mechanisms[0] = CKM_ECDSA_SHA512;
    }
  else
    {
      obj_key_gen = CKM_EC_EDWARDS_KEY_PAIR_GEN;
      obj_mechanisms[0] = CKM_EDDSA;
    }

  obj_sign = CK_TRUE;

  err = asn1_get_subject (cert->cert_der, cert->cert_der_len,
			  &subject_start, &subject_len);
  if (err)
    {
      DEBUG (DBG_INFO, "rejecting certificate: could not get subject: %s",
	     gpg_strerror (err));
      return err;
    }
  err = asn1_get_modulus (cert->cert_der, cert->cert_der_len,
			  &modulus_start, &modulus_len);
  if (err)
    {
      DEBUG (DBG_INFO, "rejecting certificate: could not get modulus: %s",
	     gpg_strerror (err));
      return err;
    }
  err = asn1_get_public_exp (cert->cert_der, cert->cert_der_len,
			     &public_exp_start, &public_exp_len);
  if (err)
    {
      DEBUG (DBG_INFO, "rejecting certificate: could not get public exp: %s",
	     gpg_strerror (err));
      return err;
    }

#define NR_ATTR_PRV 27
  attr = malloc (sizeof (CK_ATTRIBUTE) * NR_ATTR_PRV);
  attr_count = 0;
  if (!attr)
    {
      DEBUG (DBG_INFO, "out of core");
      return gpg_error (GPG_ERR_ENOMEM);
    }

  if (!err)
    err = attr_one (attr, &attr_count, CKA_CLASS,
                    &obj_class, sizeof obj_class);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_TOKEN,
                    &obj_token, sizeof obj_token);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_PRIVATE,
                    &obj_private, sizeof obj_private);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_MODIFIABLE,
                    &obj_modifiable, sizeof obj_modifiable);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_LABEL, "Scute", 5);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_KEY_TYPE,
                    &obj_key_type, sizeof obj_key_type);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_ID, (void *)grip, strlen (grip));

#if 0
  /* For now, we disable these fields.  We can parse them from the
     certificate just as the other data.  However, we would like to
     avoid parsing the certificates at all, let's see how much
     functionality we really need in the PKCS#11 token first.  */

  /* This code currently only works for certificates retrieved through
     gpgsm.  */
  if (time_to_ck_date (&cert->timestamp, &obj_start_date))
    {
      if (!err)
        err = attr_one (attr, &attr_count, CKA_START_DATE,
                        &obj_start_date, sizeof obj_start_date);
    }

  if (time_to_ck_date (&cert->expires, &obj_end_date))
    {
      if (!err)
        err = attr_one (attr, &attr_count, CKA_END_DATE,
                        &obj_end_date, sizeof obj_end_date);
    }
#else
  /* For now, we disable these fields.  We can parse them from the
     certificate just as the other data.  However, we would like to
     avoid parsing the certificates at all, let's see how much
     functionality we really need in the PKCS#11 token first.  */
  (void)obj_start_date;
  (void)obj_end_date;
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_START_DATE);
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_END_DATE);
#endif

  if (!err)
    err = attr_one (attr, &attr_count, CKA_DERIVE,
                    &obj_derive, sizeof obj_derive);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_LOCAL,
                    &obj_local, sizeof obj_local);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_KEY_GEN_MECHANISM,
                    &obj_key_gen, sizeof obj_key_gen);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_ALLOWED_MECHANISMS,
                    &obj_mechanisms, sizeof obj_mechanisms);

  if (!err)
    err = attr_one (attr, &attr_count, CKA_SUBJECT,
                    subject_start, subject_len);

  if (!err)
    err = attr_one (attr, &attr_count, CKA_SENSITIVE,
                    &obj_sensitive, sizeof obj_sensitive);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_DECRYPT,
                    &obj_decrypt, sizeof obj_decrypt);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_SIGN,
                    &obj_sign, sizeof obj_sign);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_SIGN_RECOVER,
                    &obj_sign_recover, sizeof obj_sign_recover);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_UNWRAP,
                    &obj_unwrap, sizeof obj_unwrap);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_EXTRACTABLE,
                    &obj_extractable, sizeof obj_extractable);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_ALWAYS_SENSITIVE,
                    &obj_always_sensitive, sizeof obj_always_sensitive);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_NEVER_EXTRACTABLE,
                    &obj_never_extractable, sizeof obj_never_extractable);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_WRAP_WITH_TRUSTED,
                    &obj_wrap_with_trusted, sizeof obj_wrap_with_trusted);
  if (!err)
    err = attr_empty (attr, &attr_count, CKA_UNWRAP_TEMPLATE);
  if (!err)
    err = attr_one (attr, &attr_count, CKA_ALWAYS_AUTHENTICATE,
                    &obj_always_authenticate, sizeof obj_always_authenticate);

  /* FIXME: appropriate objects should be provided.  */
  if (cert->pubkey_algo == 1)
    {
      if (!err)
        err = attr_one (attr, &attr_count, CKA_MODULUS,
                        modulus_start, modulus_len);
      if (!err)
        err = attr_one (attr, &attr_count, CKA_PUBLIC_EXPONENT,
                        public_exp_start, public_exp_len);
    }
  /* FIXME: CKA_EC_POINT, CKA_EC_PARAMS */

  if (err)
    {
      DEBUG (DBG_INFO, "could not build private certificate object: %s",
	     gpg_strerror (err));
      scute_attr_free (attr, attr_count);
      return err;
    }

#if 0
  /* FIXME: Not completely safe.  */
  assert (NR_ATTR_PRV >= attr_count);
#endif

  *attrp = attr;
  *attr_countp = attr_count;
  return 0;
}
