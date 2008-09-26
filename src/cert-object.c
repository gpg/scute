/* cert-object.c - Convert a GPGSM certificate into a PKCS #11 object.
   Copyright (C) 2006, 2007 g10 Code GmbH

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

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#include <gpg-error.h>

#include "cryptoki.h"
#include "support.h"
#include "cert.h"



#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))


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
    return false;

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


static gpg_error_t
asn1_get_len (unsigned char **asn1, int *asn1_len, int *rlen)
{
  unsigned char *ptr = *asn1;
  int len = *asn1_len;
  int cnt;
  int result = 0;

  if (len < 1)
    return gpg_error (GPG_ERR_GENERAL);

  if (*ptr & 0x80)
    {
      cnt = *ptr & 0x7f;
      ptr++;
      len--;
    }
  else
    cnt = 1;

  /* We only support a limited number of length bytes.  */
  if (cnt > 2 || len < cnt)
    return gpg_error (GPG_ERR_GENERAL);

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
      if (cert_left < 1 || *certp != path[i].tag)
	return gpg_error (GPG_ERR_GENERAL);
      certp++;
      cert_left--;
      err = asn1_get_len (&certp, &cert_left, &len);
      if (err)
	return err;
      if (!path[i].enter)
	{
	  if (cert_left < len)
	    return gpg_error (GPG_ERR_GENERAL);
	  certp += len;
	  cert_left -= len;
	}
      else
	{
	  /* Special code to deal with ASN.1 data encapsulated in a
	     bit string.  */
	  if (path[i].tag == '\x03')
	    {
	      if (cert_left < 1 || *certp != '\x00')
		return gpg_error (GPG_ERR_GENERAL);
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
    return gpg_error (GPG_ERR_GENERAL);

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
    return gpg_error (GPG_ERR_GENERAL);

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
    return gpg_error (GPG_ERR_ENOMEM);
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
scute_attr_cert (struct cert *cert,
		 CK_ATTRIBUTE_PTR *attrp, CK_ULONG *attr_countp)
{
  CK_RV err;
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
  CK_BYTE obj_label[] = { 'D', 'u', 'm', 'm', 'y', ' ',
			  'L', 'a', 'b', 'e', 'l' };

  CK_CERTIFICATE_TYPE obj_cert_type = CKC_X_509;
  CK_BBOOL obj_trusted = cert->is_trusted;
  CK_ULONG obj_cert_cat = 0;
  CK_BYTE obj_check_value[3] = { '\0', '\0', '\0' };
  CK_DATE obj_start_date;
  CK_DATE obj_end_date;
  CK_ULONG obj_java_midp_sec_domain = 0;

  err = asn1_get_subject (cert->cert_der, cert->cert_der_len,
			  &subject_start, &subject_len);
  if (!err)
    err = asn1_get_issuer (cert->cert_der, cert->cert_der_len,
			   &issuer_start, &issuer_len);
  if (!err)
    err = asn1_get_serial (cert->cert_der, cert->cert_der_len,
			   &serial_start, &serial_len);
  if (err)
    return err;

#define NR_ATTR_CERT 20
  attr = malloc (sizeof (CK_ATTRIBUTE) * NR_ATTR_CERT);
  attr_count = 0;
  if (!attr)
    return gpg_error (GPG_ERR_ENOMEM);

#define one_attr_ext(type, val, size)					\
  if (!err)								\
    err = attr_one (attr, &attr_count, type, val, size)

#define one_attr(type, val) one_attr_ext (type, &val, sizeof (val))

#define empty_attr(type)						\
  if (!err)								\
    err = attr_empty (attr, &attr_count, type)

  one_attr (CKA_CLASS, obj_class);
  one_attr (CKA_TOKEN, obj_token);
  one_attr (CKA_PRIVATE, obj_private);
  one_attr (CKA_MODIFIABLE, obj_modifiable);
  one_attr (CKA_LABEL, obj_label);
  one_attr (CKA_CERTIFICATE_TYPE, obj_cert_type);
  one_attr (CKA_TRUSTED, obj_trusted);
  one_attr (CKA_CERTIFICATE_CATEGORY, obj_cert_cat);

  /* FIXME: Calculate check_value.  */
  one_attr (CKA_CHECK_VALUE, obj_check_value);

#if 0
  if (time_to_ck_date (&cert->timestamp, &obj_start_date))
    {
      one_attr (CKA_START_DATE, obj_start_date);
    }
  else
    {
      empty_attr (CKA_START_DATE);
    }

  if (time_to_ck_date (&cert->expires, &obj_end_date))
    {
      one_attr (CKA_END_DATE, obj_end_date);
    }
  else
    {
      empty_attr (CKA_END_DATE);
    }
#else
  /* For now, we disable these fields.  We can parse them from the
     certificate just as the other data.  However, we would like to
     avoid parsing the certificates at all, let's see how much
     functionality we really need in the PKCS#11 token first.  */
  empty_attr (CKA_START_DATE);
  empty_attr (CKA_END_DATE);
#endif

  one_attr_ext (CKA_SUBJECT, subject_start, subject_len);
#if 0
  /* If we get the info directly from the card, we don't have a
     fingerprint, and parsing the subject key identifier is quite a
     mouth full.  Let's try a different approach for now.  */
  one_attr_ext (CKA_ID, cert->fpr, 40);
#else
  {
    char certptr[40];
    snprintf (certptr, DIM (certptr), "%p", cert);
    one_attr_ext (CKA_ID, certptr, strlen (certptr));
  }
#endif

  one_attr_ext (CKA_ISSUER, issuer_start, issuer_len);
  one_attr_ext (CKA_SERIAL_NUMBER, serial_start, serial_len);
  one_attr_ext (CKA_VALUE, cert->cert_der, cert->cert_der_len);
  
  empty_attr (CKA_URL);
  empty_attr (CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
  empty_attr (CKA_HASH_OF_ISSUER_PUBLIC_KEY);

  one_attr (CKA_JAVA_MIDP_SECURITY_DOMAIN, obj_java_midp_sec_domain);

  if (err)
    {
      scute_attr_free (attr, attr_count);
      return err;
    }

  /* FIXME: Not completely safe.  */
  assert (NR_ATTR_CERT == attr_count);

  *attrp = attr;
  *attr_countp = attr_count;
  return 0;
}


gpg_error_t
scute_attr_prv (struct cert *cert, CK_ATTRIBUTE_PTR *attrp,
		CK_ULONG *attr_countp)
{
  CK_RV err;
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
  CK_BYTE obj_label[] = { 'O', 'P', 'E', 'N', 'P', 'G',
			  'P', '.', '3' };

  CK_KEY_TYPE obj_key_type = CKK_RSA;
  CK_DATE obj_start_date;
  CK_DATE obj_end_date;
  CK_BBOOL obj_derive = CK_FALSE;
  CK_BBOOL obj_local = CK_FALSE;	/* FIXME: Unknown.  */
  CK_MECHANISM_TYPE obj_key_gen = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_MECHANISM_TYPE obj_mechanisms[] = { CKM_RSA_PKCS };

  CK_BBOOL obj_sensitive = CK_TRUE;
  CK_BBOOL obj_decrypt = CK_FALSE;	/* Authentication only for now.  */
  CK_BBOOL obj_sign = CK_TRUE;
  CK_BBOOL obj_sign_recover = CK_FALSE;
  CK_BBOOL obj_unwrap = CK_FALSE;
  CK_BBOOL obj_extractable = CK_FALSE;
  CK_BBOOL obj_always_sensitive = CK_TRUE;
  CK_BBOOL obj_never_extractable = CK_TRUE;
  CK_BBOOL obj_wrap_with_trusted = CK_FALSE;
  CK_BBOOL obj_always_authenticate = CK_FALSE;

  err = asn1_get_subject (cert->cert_der, cert->cert_der_len,
			  &subject_start, &subject_len);
  if (!err)
    err = asn1_get_modulus (cert->cert_der, cert->cert_der_len,
			    &modulus_start, &modulus_len);
  if (!err)
    err = asn1_get_public_exp (cert->cert_der, cert->cert_der_len,
			       &public_exp_start, &public_exp_len);
  if (err)
    return err;

#define NR_ATTR_PRV 27
  attr = malloc (sizeof (CK_ATTRIBUTE) * NR_ATTR_PRV);
  attr_count = 0;
  if (!attr)
    return gpg_error (GPG_ERR_ENOMEM);

#undef one_attr_ext
#define one_attr_ext(type, val, size)					\
  if (!err)								\
    err = attr_one (attr, &attr_count, type, val, size)

#undef one_attr
#define one_attr(type, val) one_attr_ext (type, &val, sizeof (val))

#undef empty_attr
#define empty_attr(type)						\
  if (!err)								\
    err = attr_empty (attr, &attr_count, type)

  one_attr (CKA_CLASS, obj_class);
  one_attr (CKA_TOKEN, obj_token);
  one_attr (CKA_PRIVATE, obj_private);
  one_attr (CKA_MODIFIABLE, obj_modifiable);
  one_attr (CKA_LABEL, obj_label);

  one_attr (CKA_KEY_TYPE, obj_key_type);
#if 0
  /* If we get the info directly from the card, we don't have a
     fingerprint, and parsing the subject key identifier is quite a
     mouth full.  Let's try a different approach for now.  */
  one_attr_ext (CKA_ID, cert->fpr, 40);
#else
  {
    char certptr[40];
    snprintf (certptr, DIM (certptr), "%p", cert);
    one_attr_ext (CKA_ID, certptr, strlen (certptr));
  }
#endif

#if 0
  if (time_to_ck_date (&cert->timestamp, &obj_start_date))
    {
      one_attr (CKA_START_DATE, obj_start_date);
    }
  else
    {
      empty_attr (CKA_START_DATE);
    }

  if (time_to_ck_date (&cert->expires, &obj_end_date))
    {
      one_attr (CKA_END_DATE, obj_end_date);
    }
  else
    {
      empty_attr (CKA_END_DATE);
    }
#else
  /* For now, we disable these fields.  We can parse them from the
     certificate just as the other data.  However, we would like to
     avoid parsing the certificates at all, let's see how much
     functionality we really need in the PKCS#11 token first.  */
  empty_attr (CKA_START_DATE);
  empty_attr (CKA_END_DATE);
#endif

  one_attr (CKA_DERIVE, obj_derive);
  one_attr (CKA_LOCAL, obj_local);
  one_attr (CKA_KEY_GEN_MECHANISM, obj_key_gen);
  one_attr (CKA_ALLOWED_MECHANISMS, obj_mechanisms);
  
  one_attr_ext (CKA_SUBJECT, subject_start, subject_len);
  one_attr (CKA_SENSITIVE, obj_sensitive);
  one_attr (CKA_DECRYPT, obj_decrypt);
  one_attr (CKA_SIGN, obj_sign);
  one_attr (CKA_SIGN_RECOVER, obj_sign_recover);
  one_attr (CKA_UNWRAP, obj_unwrap);
  one_attr (CKA_EXTRACTABLE, obj_extractable);
  one_attr (CKA_ALWAYS_SENSITIVE, obj_always_sensitive);
  one_attr (CKA_NEVER_EXTRACTABLE, obj_never_extractable);
  one_attr (CKA_WRAP_WITH_TRUSTED, obj_wrap_with_trusted);
  empty_attr (CKA_UNWRAP_TEMPLATE);
  one_attr (CKA_ALWAYS_AUTHENTICATE, obj_always_authenticate);

  one_attr_ext (CKA_MODULUS, modulus_start, modulus_len);
  one_attr_ext (CKA_PUBLIC_EXPONENT, public_exp_start, public_exp_len);

  if (err)
    {
      scute_attr_free (attr, attr_count);
      return err;
    }

  /* FIXME: Not completely safe.  */
  assert (NR_ATTR_PRV == attr_count);

  *attrp = attr;
  *attr_countp = attr_count;
  return 0;
}
