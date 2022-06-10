/* agent.h - Interface for talking to gpg-agent.
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

#ifndef AGENT_H
#define AGENT_H	1

#include <gpg-error.h>
#include <stdbool.h>

#include "cert.h"


/* The information structure for a smart card.  */
struct agent_card_info_s
{
  char *serialno;	/* Malloced hex string.  */
  char *cardtype;       /* Null or malloced string with the card type.  */
  char *disp_name;	/* Malloced.  */
  char *disp_lang;	/* Malloced.  */
  int  disp_sex;	/* 0 = unspecified, 1 = male, 2 = female.  */
  char *pubkey_url;	/* Malloced.  */
  char *login_data;	/* Malloced.  */
  char *private_do[4];	/* Malloced.  */
  char cafpr1valid;
  char cafpr2valid;
  char cafpr3valid;
  char cafpr1[20];
  char cafpr2[20];
  char cafpr3[20];
  key_info_t kinfo;     /* Linked list with all keypair related data.  */
  char fpr1valid;       /* Duplicated info for the legacy parts of the code. */
  char fpr2valid;
  char fpr3valid;
  char fpr1[20];
  char fpr2[20];
  char fpr3[20];
  unsigned int fpr1time;
  unsigned int fpr2time;
  unsigned int fpr3time;
  unsigned long sig_counter;
  int chv1_cached;	/* True if a PIN is not required for each
			   signing.  Note that the gpg-agent might
			   cache it anyway.  */
  int chvmaxlen[3];	/* Maximum allowed length of a CHV.  */
  int chvretry[3];	/* Allowed retries for the CHV; 0 = blocked.  */
  int rng_available;    /* True if the GET CHALLENGE operation
                           is supported. */
  int is_piv;           /* True if this is a PIV card or has PIV as an
                         * additional application.  */
  int is_opgp;          /* True if this is a OpenPGP card or has
                         * OpenPGP as an additional application.  */
};
typedef struct agent_card_info_s *agent_card_info_t;



struct keyinfo
{
  struct keyinfo *next;
  char grip[41];
  char *serialno;
  char *keyref;
  char *usage; /* only available from "SCD KEYINFO" not "KEYINFO" */
};

/* Try to connect to the agent via socket.  Handle the server's
   initial greeting.  */
gpg_error_t scute_agent_initialize (void);

/* Tear down the agent connection and release all associated
   resources.  */
void scute_agent_finalize (void);

gpg_error_t scute_agent_keyinfo_list (struct keyinfo **l_p);
void scute_agent_free_keyinfo (struct keyinfo *l);

/* Check the agent status.  This returns 0 if a token is present,
   GPG_ERR_CARD_REMOVED if no token is present, and an error code
   otherwise.  */
gpg_error_t scute_agent_check_status (const char *grip);


/* Call the agent to learn about a smartcard.  */
gpg_error_t scute_agent_learn (const char *grip,
                               struct agent_card_info_s *info);

/* Release the card info structure INFO.  */
void scute_agent_release_card_info (struct agent_card_info_s *info);

/* Sign the data DATA of length LEN with the key HEXGRIP and return
 * the signature in SIG_RESULT and SIG_LEN.  */
gpg_error_t scute_agent_sign (const char *hexgrip, CK_MECHANISM_TYPE mechtype,
                              unsigned char *data, int len,
			      unsigned char *sig_result, unsigned int *sig_len);

/* Decrypt data.  */
gpg_error_t scute_agent_decrypt (const char *hexgrip,
                                 unsigned char *encdata, int encdatalen,
                                 unsigned char *r_plaindata,
                                 unsigned int *r_plaindatalen);

/* Determine if FPR is trusted.  */
gpg_error_t scute_agent_is_trusted (const char *fpr, bool *is_trusted);

/* Try to get certificate for key numer NO.  */
gpg_error_t scute_agent_get_cert (const char *grip, struct cert *cert);

/* Get random bytes from the card. */
gpg_error_t scute_agent_get_random (unsigned char *data, size_t len);

#endif	/* AGENT_H */
