/* t-getattribute.c - Regression test.
   Copyright (C) 2006 g10 Code GmbH

   This file is part of scute[1].

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

#include <stdio.h>
#include <stdbool.h>

#include "t-support.h"

CK_RV
dump_one (CK_ATTRIBUTE_PTR attr, unsigned char *data, int max_size)
{
  bool some;
  int i;

  if (attr->ulValueLen < 0 || attr->ulValueLen > max_size)
    return CKR_GENERAL_ERROR;

  some = false;
  for (i = 0; i < attr->ulValueLen; i++)
    {
      if (some == false)
	{
	  printf ("     ");
	  some = true;
	}
      printf ("%02x", data[i]);
      if (((i + 1) % 32) == 0)
	{
	  printf ("\n");
	  some = false;
	}
    }
  if (some)
    printf ("\n");

  return 0;
}


CK_RV
dump_object (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
  CK_RV err;
  CK_OBJECT_CLASS obj_class;
  CK_ATTRIBUTE attr_class = { CKA_CLASS, &obj_class, sizeof (obj_class) };

  err = C_GetAttributeValue (session, object, &attr_class, 1);
  if (err)
    return err;

  printf ("    Object Class: %lu = ", obj_class);
  switch (obj_class)
    {
#define MAX_CERT_LEN 4096
    case CKO_CERTIFICATE:
      {
	CK_CERTIFICATE_TYPE cert_type;
	CK_BBOOL cert_token;
	CK_BBOOL cert_private;
	CK_BBOOL cert_modifiable;
	CK_BYTE cert_label[MAX_CERT_LEN];
	CK_BBOOL cert_trusted;
	CK_ULONG cert_cc;
	CK_BYTE cert_check[3];
	CK_DATE cert_sdate;
	CK_DATE cert_edate;
	CK_BYTE cert_subject[MAX_CERT_LEN];
	CK_BYTE cert_id[MAX_CERT_LEN];
	CK_BYTE cert_issuer[MAX_CERT_LEN];
	CK_BYTE cert_serial[MAX_CERT_LEN];
	CK_BYTE cert_value[MAX_CERT_LEN];
	CK_ULONG cert_jm;

	/* Note that the order is encoded below in the various length
	   checks.  */
	CK_ATTRIBUTE cert_attr[]
	  = { { CKA_CERTIFICATE_TYPE, &cert_type, sizeof (cert_type) },
	      { CKA_TOKEN, &cert_token, sizeof (cert_token) },
	      { CKA_PRIVATE, &cert_private, sizeof (cert_private) },
	      { CKA_MODIFIABLE, &cert_modifiable, sizeof (cert_modifiable) },
	      { CKA_LABEL, &cert_label, sizeof (cert_label) },
	      { CKA_TRUSTED, &cert_trusted, sizeof (cert_trusted) },
	      { CKA_CERTIFICATE_CATEGORY, &cert_cc, sizeof (cert_cc) },
	      { CKA_CHECK_VALUE, &cert_check, sizeof (cert_check) },
	      { CKA_START_DATE, &cert_sdate, sizeof (cert_sdate) },
	      { CKA_END_DATE, &cert_edate, sizeof (cert_edate) },
	      { CKA_SUBJECT, &cert_subject, sizeof (cert_subject) },
	      { CKA_ID, &cert_id, sizeof (cert_id) },
	      { CKA_ISSUER, &cert_issuer, sizeof (cert_issuer) },
	      { CKA_SERIAL_NUMBER, &cert_serial, sizeof (cert_serial) },
	      { CKA_VALUE, cert_value, sizeof (cert_value) },
	      { CKA_URL, NULL, 0 },
	      { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NULL, 0 },
	      { CKA_HASH_OF_ISSUER_PUBLIC_KEY, NULL, 0 },
	      { CKA_JAVA_MIDP_SECURITY_DOMAIN, &cert_jm, sizeof (cert_jm) } };

	printf ("CKO_CERTIFICATE\n");

	err = C_GetAttributeValue (session, object,
				   cert_attr, DIM (cert_attr));
	if (err)
	  return err;

	fail_if_err ((cert_attr[0].ulValueLen != sizeof (cert_type)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Type: %lu = ", cert_type);
	switch (cert_type)
	  {
	  case CKC_X_509:
	    printf ("CKC_X_509");
	    break;

	  case CKC_WTLS:
	    printf ("CKC_WTLS");
	    break;

	  case CKC_X_509_ATTR_CERT:
	    printf ("CKC_X_509_ATTR_CERT");
	    break;

	  default:
	    printf ("(unknown");
	    break;
	  }
	printf ("\n");

	fail_if_err ((cert_attr[1].ulValueLen != sizeof (cert_token)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Token: %s\n",
		cert_token ? "true" : "false");

	fail_if_err ((cert_attr[2].ulValueLen != sizeof (cert_private)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Private: %s\n",
		cert_private ? "true" : "false");

	fail_if_err ((cert_attr[3].ulValueLen != sizeof (cert_modifiable)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Modifiable: %s\n",
		cert_modifiable ? "true" : "false");

	printf ("     Certificate Label: Length %lu\n",
		cert_attr[4].ulValueLen);
	err = dump_one (&cert_attr[4], cert_label, sizeof (cert_label));
	fail_if_err (err);

	fail_if_err ((cert_attr[5].ulValueLen != sizeof (cert_trusted)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Trusted: %s\n",
		cert_trusted ? "true" : "false");

	fail_if_err ((cert_attr[6].ulValueLen != sizeof (cert_cc)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Category: %lu = ", cert_cc);
	switch (cert_cc)
	  {
	  case 0:
	    printf ("unspecified");
	    break;

	  case 1:
	    printf ("token user");
	    break;

	  case 2:
	    printf ("authority");
	    break;

	  case 3:
	    printf ("other entity");
	    break;

	  default:
	    printf ("(unknown)");
	    break;
	  }
	printf ("\n");

	fail_if_err ((cert_attr[7].ulValueLen != sizeof (cert_check)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Check Value: %02x%02x%02x\n",
		cert_check[0], cert_check[1], cert_check[2]);

	fail_if_err ((cert_attr[8].ulValueLen != sizeof (cert_sdate)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Start Date: %.4s/%.2s/%.2s\n",
		cert_sdate.year, cert_sdate.month, cert_sdate.day);

	fail_if_err ((cert_attr[9].ulValueLen != sizeof (cert_edate)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate End Date: %.4s/%.2s/%.2s\n",
		cert_edate.year, cert_edate.month, cert_edate.day);

	printf ("     Certificate Subject: Length %lu\n",
		cert_attr[10].ulValueLen);
	err = dump_one (&cert_attr[10], cert_subject, sizeof (cert_subject));
	fail_if_err (err);

	printf ("     Certificate ID: Length %lu\n",
		cert_attr[11].ulValueLen);
	err = dump_one (&cert_attr[11], cert_id, sizeof (cert_id));
	fail_if_err (err);

	printf ("     Certificate Issuer: Length %lu\n",
		cert_attr[12].ulValueLen);
	err = dump_one (&cert_attr[12], cert_issuer, sizeof (cert_issuer));
	fail_if_err (err);

	printf ("     Certificate Serial Number: Length %lu\n",
		cert_attr[13].ulValueLen);
	err = dump_one (&cert_attr[13], cert_serial, sizeof (cert_serial));
	fail_if_err (err);

	printf ("     Certificate Value: Length %lu\n",
		cert_attr[14].ulValueLen);
	err = dump_one (&cert_attr[14], cert_value, sizeof (cert_value));
	fail_if_err (err);

	fail_if_err ((cert_attr[15].ulValueLen != 0) ? CKR_GENERAL_ERROR : 0);
	fail_if_err ((cert_attr[16].ulValueLen != 0) ? CKR_GENERAL_ERROR : 0);
	fail_if_err ((cert_attr[17].ulValueLen != 0) ? CKR_GENERAL_ERROR : 0);

	fail_if_err ((cert_attr[18].ulValueLen != sizeof (cert_jm)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Certificate Java MIDP Security Domain: %lu = ", cert_jm);
	switch (cert_jm)
	  {
	  case 0:
	    printf ("unspecified");
	    break;

	  case 1:
	    printf ("manufacturer");
	    break;

	  case 2:
	    printf ("operator");
	    break;

	  case 3:
	    printf ("third party");
	    break;

	  default:
	    printf ("(unknown)");
	    break;
	  }
	printf ("\n");
      }
      break;

    case CKO_PRIVATE_KEY:
      {
	CK_KEY_TYPE key_type;
	CK_BBOOL key_token;
	CK_BBOOL key_private;
	CK_BBOOL key_modifiable;
	CK_BYTE key_label[MAX_CERT_LEN];
	CK_BYTE key_id[MAX_CERT_LEN];
	CK_DATE key_sdate;
	CK_DATE key_edate;
	CK_BBOOL key_derive;
	CK_BBOOL key_local;
	CK_MECHANISM_TYPE key_gen;
	CK_MECHANISM_TYPE key_mechanisms[1]; /* FIXME, hard-coded constant.  */
	CK_BYTE key_subject[MAX_CERT_LEN];
	CK_BBOOL key_sensitive;
	CK_BBOOL key_decrypt;
	CK_BBOOL key_sign;
	CK_BBOOL key_sign_recover;
	CK_BBOOL key_unwrap;
	CK_BBOOL key_extractable;
	CK_BBOOL key_always_sensitive;
	CK_BBOOL key_never_extractable;
	CK_BBOOL key_wrap_with_trusted;
	CK_BBOOL key_always_authenticate;
	CK_BYTE key_modulus[MAX_CERT_LEN];
	CK_BYTE key_public_exp[MAX_CERT_LEN];

	/* Note that the order is encoded below in the various length
	   checks.  */
	CK_ATTRIBUTE key_attr[]
	  = { { CKA_KEY_TYPE, &key_type, sizeof (key_type) },
	      { CKA_TOKEN, &key_token, sizeof (key_token) },
	      { CKA_PRIVATE, &key_private, sizeof (key_private) },
	      { CKA_MODIFIABLE, &key_modifiable, sizeof (key_modifiable) },
	      { CKA_LABEL, &key_label, sizeof (key_label) },
	      { CKA_ID, &key_id, sizeof (key_id) },
	      { CKA_START_DATE, &key_sdate, sizeof (key_sdate) },
	      { CKA_END_DATE, &key_edate, sizeof (key_edate) },
	      { CKA_DERIVE, &key_derive, sizeof (key_derive) },
	      { CKA_LOCAL, &key_local, sizeof (key_local) },
	      { CKA_KEY_GEN_MECHANISM, &key_gen, sizeof (key_gen) },
	      { CKA_ALLOWED_MECHANISMS, &key_mechanisms,
		sizeof (key_mechanisms) },
	      { CKA_SUBJECT, &key_subject, sizeof (key_subject) },
	      { CKA_SENSITIVE, &key_sensitive, sizeof (key_sensitive) },
	      { CKA_DECRYPT, &key_decrypt, sizeof (key_decrypt) },
	      { CKA_SIGN, &key_sign, sizeof (key_sign) },
	      { CKA_SIGN_RECOVER, &key_sign_recover,
		sizeof (key_sign_recover) },
	      { CKA_UNWRAP, &key_unwrap, sizeof (key_unwrap) },
	      { CKA_EXTRACTABLE, &key_extractable, sizeof (key_extractable) },
	      { CKA_ALWAYS_SENSITIVE, &key_always_sensitive,
		sizeof (key_always_sensitive) },
	      { CKA_NEVER_EXTRACTABLE, &key_never_extractable,
		sizeof (key_never_extractable) },
	      { CKA_WRAP_WITH_TRUSTED, &key_wrap_with_trusted,
		sizeof (key_wrap_with_trusted) },
	      { CKA_UNWRAP_TEMPLATE, NULL, 0 },
	      { CKA_ALWAYS_AUTHENTICATE, &key_always_authenticate,
		sizeof (key_always_authenticate) },
	      { CKA_MODULUS, &key_modulus, sizeof (key_modulus) },
	      { CKA_PUBLIC_EXPONENT, &key_public_exp,
		sizeof (key_public_exp) } };

	printf ("CKO_PRIVATE_KEY\n");

	err = C_GetAttributeValue (session, object,
				   key_attr, DIM (key_attr));
	if (err)
	  return err;

	fail_if_err ((key_attr[0].ulValueLen != sizeof (key_type)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Type: %lu = ", key_type);
	switch (key_type)
	  {
	  case CKK_RSA:
	    printf ("CKK_RSA");
	    break;

	  case CKK_DSA:
	    printf ("CKK_DSA");
	    break;

	  default:
	    printf ("(unknown");
	    break;
	  }
	printf ("\n");

	fail_if_err ((key_attr[1].ulValueLen != sizeof (key_token)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Token: %s\n",
		key_token ? "true" : "false");

	fail_if_err ((key_attr[2].ulValueLen != sizeof (key_private)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Private: %s\n",
		key_private ? "true" : "false");

	fail_if_err ((key_attr[3].ulValueLen != sizeof (key_modifiable)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Modifiable: %s\n",
		key_modifiable ? "true" : "false");

	printf ("     Key Label: Length %lu\n",
		key_attr[4].ulValueLen);
	err = dump_one (&key_attr[4], key_label, sizeof (key_label));
	fail_if_err (err);

	printf ("     Key ID: Length %lu\n",
		key_attr[5].ulValueLen);
	err = dump_one (&key_attr[5], key_id, sizeof (key_id));
	fail_if_err (err);

	fail_if_err ((key_attr[6].ulValueLen != sizeof (key_sdate)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Start Date: %.4s/%.2s/%.2s\n",
		key_sdate.year, key_sdate.month, key_sdate.day);

	fail_if_err ((key_attr[7].ulValueLen != sizeof (key_edate)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key End Date: %.4s/%.2s/%.2s\n",
		key_edate.year, key_edate.month, key_edate.day);

	fail_if_err ((key_attr[8].ulValueLen != sizeof (key_derive)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Derive: %s\n",
		key_derive ? "true" : "false");

	fail_if_err ((key_attr[9].ulValueLen != sizeof (key_local)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Local: %s\n",
		key_local ? "true" : "false");

	fail_if_err ((key_attr[10].ulValueLen != sizeof (key_gen)) ?
		     CKR_GENERAL_ERROR : 0);
	/* FIXME: Print Mechanism.  */
	printf ("     Key Gen Mechanism: %lu\n", key_gen);

	/* FIXME: Print supported mechanisms.  11 */

	printf ("     Key Subject: Length %lu\n",
		key_attr[12].ulValueLen);
	err = dump_one (&key_attr[12], key_subject, sizeof (key_subject));
	fail_if_err (err);

	fail_if_err ((key_attr[13].ulValueLen != sizeof (key_sensitive)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Sensitive: %s\n",
		key_sensitive ? "true" : "false");

	fail_if_err ((key_attr[14].ulValueLen != sizeof (key_decrypt)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Decrypt: %s\n",
		key_decrypt ? "true" : "false");

	fail_if_err ((key_attr[15].ulValueLen != sizeof (key_sign)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Sign: %s\n",
		key_sign ? "true" : "false");

	fail_if_err ((key_attr[16].ulValueLen != sizeof (key_sign_recover)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Sign Recover: %s\n",
		key_sign_recover ? "true" : "false");

	fail_if_err ((key_attr[17].ulValueLen != sizeof (key_unwrap)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Unwrap: %s\n",
		key_unwrap ? "true" : "false");

	fail_if_err ((key_attr[18].ulValueLen != sizeof (key_extractable)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Extractable: %s\n",
		key_extractable ? "true" : "false");

	fail_if_err ((key_attr[19].ulValueLen
		      != sizeof (key_always_sensitive)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Always Sensitive: %s\n",
		key_always_sensitive ? "true" : "false");

	fail_if_err ((key_attr[20].ulValueLen
		      != sizeof (key_never_extractable)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Never Extractable: %s\n",
		key_never_extractable ? "true" : "false");

	fail_if_err ((key_attr[21].ulValueLen
		      != sizeof (key_wrap_with_trusted)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Wrap With Trusted: %s\n",
		key_wrap_with_trusted ? "true" : "false");

	fail_if_err ((key_attr[22].ulValueLen != 0) ? CKR_GENERAL_ERROR : 0);

	fail_if_err ((key_attr[23].ulValueLen
		      != sizeof (key_always_authenticate)) ?
		     CKR_GENERAL_ERROR : 0);
	printf ("     Key Always Authenticate: %s\n",
		key_always_authenticate ? "true" : "false");

	printf ("     Key Modulus: Length %lu\n",
		key_attr[24].ulValueLen);
	err = dump_one (&key_attr[24], key_modulus, sizeof (key_modulus));
	fail_if_err (err);

	printf ("     Key Subject: Length %lu\n",
		key_attr[25].ulValueLen);
	err = dump_one (&key_attr[25], key_public_exp,
			sizeof (key_public_exp));
	fail_if_err (err);
      }
      break;

    default:
      printf ("(unknown)\n");
    }

  return 0;
}


int
main (int argc, char *argv[])
{
  CK_RV err;
  CK_SLOT_ID_PTR slots;
  CK_ULONG slots_count;
  int i;

  init_cryptoki ();

  err = C_GetSlotList (true, NULL, &slots_count);
  fail_if_err (err);

  if (slots_count == 0)
    {
      printf ("Skipping test because no token is present.\n");
      return 0;
    }

  printf ("Number of slots with tokens: %lu\n", slots_count);
  slots = malloc (sizeof (CK_SLOT_ID) * slots_count);
  if (!slots)
    fail_if_err (CKR_HOST_MEMORY);

  err = C_GetSlotList (true, slots, &slots_count);
  fail_if_err (err);

  for (i = 0; i < slots_count; i++)
    {
      CK_SESSION_HANDLE session;
      CK_OBJECT_HANDLE object;
      CK_ULONG count;

      printf ("%2i. Slot ID %lu\n", i, slots[i]);
      err = C_OpenSession (slots[i], CKF_SERIAL_SESSION, NULL, NULL,
			   &session);
      fail_if_err (err);
     
      printf ("    Session ID: %lu\n", session);

      err = C_FindObjectsInit (session, NULL, 0);
      fail_if_err (err);

      do
	{
	  err = C_FindObjects (session, &object, 1, &count);
	  fail_if_err (err);

	  if (count)
	    {
	      printf ("    Object Handle: %lu\n", object);

	      err = dump_object (session, object);
	      fail_if_err (err);
	    }
	}
      while (count);

      err = C_FindObjectsFinal (session);
      fail_if_err (err);

      err = C_CloseSession (session);
      fail_if_err (err);
    }

  return 0;
}
