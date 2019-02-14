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


/* An object to store information pertaining to a keypair as stored on
 * a card.  This is commonly used as a linked list of all keys known
 * for a card.  */
struct key_info_s
{
  struct key_info_s *next;

  char grip[41];/* The keygrip as hex encoded string.  */

  unsigned char xflag;   /* Temporary flag to help processing a list. */

  /* The three next items are mostly useful for OpenPGP cards.  */
  unsigned char fprlen;  /* Use length of the next item.  */
  unsigned char fpr[32]; /* The binary fingerprint of length FPRLEN.  */
  unsigned long created; /* The time the key was created.  */

  char keyref[1];        /* String with the keyref (e.g. OPENPGP.1).  */
};
typedef struct key_info_s *key_info_t;


/* The information structure for a smart card.  */
struct agent_card_info_s
{
  char *serialno;	/* Malloced hex string.  */
  char *cardtype;       /* Null or mallcoed string with the card type.  */
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
  int is_piv;           /* True if this is a PIV card.  */
};
typedef struct agent_card_info_s *agent_card_info_t;



/* Try to connect to the agent via socket.  Handle the server's
   initial greeting.  */
gpg_error_t scute_agent_initialize (void);

/* Return the major and minor version of the agent.  */
int scute_agent_get_agent_version (int *minor);

/* Tear down the agent connection and release all associated
   resources.  */
void scute_agent_finalize (void);


/* Check the agent status.  This returns 0 if a token is present,
   GPG_ERR_CARD_REMOVED if no token is present, and an error code
   otherwise.  */
gpg_error_t scute_agent_check_status (void);


/* Call the agent to learn about a smartcard.  */
gpg_error_t scute_agent_learn (struct agent_card_info_s *info);

/* Release the card info structure INFO.  */
void scute_agent_release_card_info (struct agent_card_info_s *info);

key_info_t scute_find_kinfo (agent_card_info_t info, const char *keyref);


/* Sign the data DATA of length LEN with the key HEXGRIP and return
 * the signature in SIG_RESULT and SIG_LEN.  */
gpg_error_t scute_agent_sign (const char *hexgrip,
                              unsigned char *data, int len,
			      unsigned char *sig_result, unsigned int *sig_len);

/* Determine if FPR is trusted.  */
gpg_error_t scute_agent_is_trusted (char *fpr, bool *is_trusted);

/* Try to get certificate for key numer NO.  */
gpg_error_t scute_agent_get_cert (const char *certref, struct cert *cert);

/* Get random bytes from the card. */
gpg_error_t scute_agent_get_random (unsigned char *data, size_t len);

#endif	/* AGENT_H */
