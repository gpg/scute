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

struct keyinfo
{
  struct keyinfo *next;
  char grip[41];
  char *serialno;
};

/* Try to connect to the agent via socket.  Handle the server's
   initial greeting.  */
gpg_error_t scute_agent_initialize (void);

/* Tear down the agent connection and release all associated
   resources.  */
void scute_agent_finalize (void);

gpg_error_t scute_agent_keyinfo_list (struct keyinfo **l_p);
void scute_agent_free_keyinfo (struct keyinfo *l);

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

/* Get random bytes from the card. */
gpg_error_t scute_agent_get_random (unsigned char *data, size_t len);

gpg_error_t scute_agent_keyinfo_list (struct keyinfo **keyinfo_p);

gpg_error_t scute_agent_serialno (void);

#endif	/* AGENT_H */
