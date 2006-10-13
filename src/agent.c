/* agent.c - Talking to gpg-agent.
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

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <errno.h>
#include <string.h>

#include <assuan.h>
#include <gpg-error.h>

#include "debug.h"
#include "agent.h"
#include "support.h"


/* The global agent context.  */
static assuan_context_t agent_ctx = NULL;


/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting.  */
gpg_error_t
scute_agent_initialize (void)
{
  assuan_error_t err = 0;
  char *infostr;
  char *p;
  assuan_context_t ctx;
  char *dft_display = NULL;
  char *dft_ttyname = NULL;
  char *dft_ttytype = NULL;
  char *old_lc = NULL;
  char *dft_lc = NULL;
  int pid;
  int prot;

  if (agent_ctx)
    return 0;

  infostr = getenv ("GPG_AGENT_INFO");
  if (!infostr)
    {
      DEBUG ("no GPG agent detected");
      return gpg_error (GPG_ERR_NO_AGENT);
    }

  infostr = strdup (infostr);
  if (!infostr)
    return gpg_error_from_errno (errno);

  if (!(p = strchr (infostr, ':')) || p == infostr)
    {
      DEBUG ("malformed GPG_AGENT_INFO environment variable");
      free (infostr);
      return gpg_error (GPG_ERR_NO_AGENT);
    }
  *p++ = 0;
  pid = atoi (p);
  while (*p && *p != ':')
    p++;
  prot = *p ? atoi (p + 1) : 0;
  if (prot != 1)
    {
      DEBUG ("gpg-agent protocol version %d is not supported", prot);
      free (infostr);
      return gpg_error (GPG_ERR_NO_AGENT);
    }

  err = assuan_socket_connect (&ctx, infostr, pid);
  free (infostr);
  if (err)
    {
      DEBUG ("can't connect to GPG agent: %s", assuan_strerror (err));
      return gpg_error (GPG_ERR_NO_AGENT);
    }
  agent_ctx = ctx;

  err = assuan_transact (agent_ctx, "RESET",
			 NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    return err;

  /* Set up display, terminal and locale options.  */
  dft_display = getenv ("DISPLAY");
  if (dft_display)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION display=%s", dft_display) < 0)
	err = gpg_error_from_errno (errno);
      else
	{
	  err = assuan_transact (agent_ctx, optstr,
				 NULL, NULL, NULL, NULL, NULL, NULL);
	  free (optstr);
	}
    }
  dft_ttyname = getenv ("GPG_TTY");
  if ((!dft_ttyname || !*dft_ttyname) && ttyname (0))
    dft_ttyname = ttyname (0);
  if (!err)
    {
      if (dft_ttyname)
	{
	  char *optstr;
	  if (asprintf (&optstr, "OPTION ttyname=%s", dft_ttyname) < 0)
	    err = gpg_error_from_errno (errno);
	  else
	    {
	      err = assuan_transact (agent_ctx, optstr,
				     NULL, NULL, NULL, NULL, NULL, NULL);
	      free (optstr);
	    }
	}
    }
  dft_ttytype = getenv ("TERM");
  if (!err && dft_ttyname && dft_ttytype)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION ttytype=%s", dft_ttytype) < 0)
	err = gpg_error_from_errno (errno);
      else
	{
	  err = assuan_transact (agent_ctx, optstr,
				 NULL, NULL, NULL, NULL, NULL, NULL);
	  free (optstr);
	}
    }
  old_lc = setlocale (LC_CTYPE, NULL);
  if (!err && old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
        err = gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_CTYPE, "");
  if (!err && dft_ttyname && dft_lc)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-ctype=%s", dft_lc) < 0)
	err = gpg_error_from_errno (errno);
      else
	{
	  err = assuan_transact (agent_ctx, optstr,
				 NULL, NULL, NULL, NULL, NULL, NULL);
	  free (optstr);
	}
    }
#if defined(HAVE_SETLOCALE) && defined(LC_CTYPE)
  if (!err && old_lc)
    {
      setlocale (LC_CTYPE, old_lc);
      free (old_lc);
    }
#endif

  old_lc = setlocale (LC_MESSAGES, NULL);
  if (!err && old_lc)
    {
      old_lc = strdup (old_lc);
      if (!old_lc)
        err = gpg_error_from_errno (errno);
    }
  dft_lc = setlocale (LC_MESSAGES, "");
  if (!err && dft_ttyname && dft_lc)
    {
      char *optstr;
      if (asprintf (&optstr, "OPTION lc-messages=%s", dft_lc) < 0)
	err = gpg_error_from_errno (errno);
      else
	{
	  err = assuan_transact (agent_ctx, optstr,
				 NULL, NULL, NULL, NULL, NULL, NULL);
	  free (optstr);
	}
    }
#if defined(HAVE_SETLOCALE) && defined(LC_MESSAGES)
  if (!err && old_lc)
    {
      setlocale (LC_MESSAGES, old_lc);
      free (old_lc);
    }
#endif

  if (err)
    {
      /* Setting some options failed.  Tear down the agent
	 connection.  */
      assuan_disconnect (agent_ctx);
    }

  return err;
}


/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status.  */
static char *
unescape_status_string (const unsigned char *s)
{
  char *buffer, *d;

  buffer = d = malloc (strlen (s) + 1);
  if (!buffer)
    return NULL;
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
  return buffer;
}


/* Take a 20 byte hexencoded string and put it into the the provided
   20 byte buffer FPR in binary format.  */
static int
unhexify_fpr (const char *hexstr, unsigned char *fpr)
{
  const char *s;
  int n;

  for (s = hexstr, n = 0; hexdigitp (s); s++, n++)
    ;
  if ((*s && !spacep (s)) || (n != 40))
    return 0;	/* No fingerprint (invalid or wrong length).  */
  n /= 2;
  for (s = hexstr, n = 0; *s && !spacep (s); s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* Okay.  */
}


/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned.  */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s = line; hexdigitp (s); s++)
    ;
  p = malloc (s + 1 - line);
  if (p)
    {
      memcpy (p, line, s-line);
      p[s-line] = 0;
    }
  return p;
}


/* Release the card info structure INFO.  */
void
agent_release_card_info (struct agent_card_info_s *info)
{
  if (!info)
    return;

  free (info->serialno);
  free (info->disp_name);
  free (info->disp_lang);
  free (info->pubkey_url);
  free (info->login_data);

  memset (info, 0, sizeof (*info));
}


/* FIXME: We are not returning out of memory errors.  */
static assuan_error_t
learn_status_cb (void *opaque, const char *line)
{
  struct agent_card_info_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  int i;

  for (keywordlen = 0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (parm->serialno)
	free (parm->serialno);
      parm->serialno = store_serialno (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      if (parm->disp_name)
	free (parm->disp_name);
      parm->disp_name = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      if (parm->disp_lang)
	free (parm->disp_lang);
      parm->disp_lang = unescape_status_string (line);
    }
  else if (keywordlen == 8 && !memcmp (keyword, "DISP-SEX", keywordlen))
    {
      parm->disp_sex = *line == '1'? 1 : *line == '2' ? 2: 0;
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      if (parm->pubkey_url)
	free (parm->pubkey_url);
      parm->pubkey_url = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      if (parm->login_data)
	free (parm->login_data);
      parm->login_data = unescape_status_string (line);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "SIG-COUNTER", keywordlen))
    {
      parm->sig_counter = strtoul (line, NULL, 0);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "CHV-STATUS", keywordlen))
    {
      char *p, *buf;

      buf = p = unescape_status_string (line);
      if (buf)
        {
          while (spacep (p))
            p++;
          parm->chv1_cached = atoi (p);
          while (*p && !spacep (p))
            p++;
          while (spacep (p))
            p++;
          for (i = 0; *p && i < 3; i++)
            {
              parm->chvmaxlen[i] = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          for (i=0; *p && i < 3; i++)
            {
              parm->chvretry[i] = atoi (p);
              while (*p && !spacep (p))
                p++;
              while (spacep (p))
                p++;
            }
          free (buf);
        }
    }
  else if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1valid = unhexify_fpr (line, parm->fpr1);
      else if (no == 2)
        parm->fpr2valid = unhexify_fpr (line, parm->fpr2);
      else if (no == 3)
        parm->fpr3valid = unhexify_fpr (line, parm->fpr3);
    }
  else if (keywordlen == 6 && !memcmp (keyword, "CA-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->cafpr1valid = unhexify_fpr (line, parm->cafpr1);
      else if (no == 2)
        parm->cafpr2valid = unhexify_fpr (line, parm->cafpr2);
      else if (no == 3)
        parm->cafpr3valid = unhexify_fpr (line, parm->cafpr3);
    }
  else if (keywordlen == 11 && !memcmp (keyword, "KEYPAIRINFO", keywordlen))
    {
      const char *grip = line;
      while (*line && !spacep (line))
        line++;

      if (line - grip == 40)
	{
	  while (spacep (line))
	    line++;
	  if (!memcmp (line, "OPENPGP.", 8))
	    {
	      int no;
	      line += 8;

	      no = atoi (line);

	      if (no == 1)
		{
		  memcpy (parm->grip1, grip, 40);
		  parm->grip1valid = 1;
		}
	      else if (no == 2)
		{
		  memcpy (parm->grip2, grip, 40);
		  parm->grip2valid = 1;
		}
	      else if (no == 3)
		{
		  memcpy (parm->grip3, grip, 40);
		  parm->grip3valid = 1;
		}
	    }
	}
    }
  return 0;
}


/* Call the agent to learn about a smartcard.  */
gpg_error_t
agent_learn (struct agent_card_info_s *info)
{
  assuan_error_t err;

  memset (info, 0, sizeof (*info));
  err = assuan_transact (agent_ctx, "LEARN --send",
			 NULL, NULL, NULL, NULL, learn_status_cb, info);

  return err;
}


static assuan_error_t
read_status_cb (void *opaque, const void *buffer, size_t length)
{
  char *flag = opaque;

  if (length == 0)
    *flag = 'r';
  else
    *flag = *((char *) buffer);

  return 0;
}


/* Call the agent to learn about a smartcard.  */
gpg_error_t
agent_check_status (void)
{
  assuan_error_t err;
  char flag = '-';

  err = assuan_transact (agent_ctx, "SCD GETINFO status",
			 read_status_cb, &flag, NULL, NULL, NULL, NULL);

  if (err)
    return err;

  if (flag == 'r')
    return gpg_error (GPG_ERR_CARD_REMOVED);

  return 0;
}


#define MAX_SIGNATURE_LEN 256

struct signature
{
  unsigned char data[MAX_SIGNATURE_LEN];
  int len;
};

static assuan_error_t
pksign_cb (void *opaque, const void *buffer, size_t length)
{
  struct signature *sig = opaque;
  int i;

  if (sig->len + length > MAX_SIGNATURE_LEN)
    return gpg_error (GPG_ERR_BAD_DATA);

  memcpy (&sig->data[sig->len], buffer, length);
  sig->len += length;

  return 0;
}


#define SIG_PREFIX "(7:sig-val(3:rsa(1:s128:"
#define SIG_PREFIX_LEN (sizeof (SIG_PREFIX) - 1)
#define SIG_POSTFIX ")))"
#define SIG_POSTFIX_LEN (sizeof (SIG_POSTFIX) - 1)
#define SIG_LEN 128

/* Call the agent to learn about a smartcard.  */
gpg_error_t
agent_sign (char *grip, unsigned char *data, int len,
	    unsigned char *sig_result, unsigned int *sig_len)
{
  char cmd[150];
  assuan_error_t err;
#define MAX_DATA_LEN 36
  unsigned char pretty_data[2 * MAX_DATA_LEN + 1];
  int i;
  struct signature sig;

  sig.len = 0;

  if (sig_len == NULL)
    return gpg_error (GPG_ERR_INV_ARG);

  if (sig_result == NULL)
    {
      *sig_len = SIG_LEN;
      return 0;
    }

  if (len > MAX_DATA_LEN)
    return gpg_error (GPG_ERR_INV_ARG);

  if (grip == NULL || sig_result == NULL || *sig_len < SIG_LEN)
    return gpg_error (GPG_ERR_INV_ARG);

  snprintf (cmd, sizeof (cmd), "SIGKEY %s", grip);
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    return err;

  for (i = 0; i < len; i++)
    sprintf (&pretty_data[2 * i], "%02X", data[i]);
  pretty_data[2 * len] = '\0';

  snprintf (cmd, sizeof (cmd), "sethash --hash=tls-md5sha1 %s", pretty_data);
  err = assuan_transact (agent_ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (err)
    return err;

  err = assuan_transact (agent_ctx, "PKSIGN",
			 pksign_cb, &sig, NULL, NULL, NULL, NULL);
  printf ("Returning ERR = %u\n", err);
  if (err)
    return err;

  if (sig.len != SIG_PREFIX_LEN + SIG_LEN + SIG_POSTFIX_LEN)
    return gpg_error (GPG_ERR_BAD_SIGNATURE);
  if (memcmp (sig.data, SIG_PREFIX, SIG_PREFIX_LEN))
    return gpg_error (GPG_ERR_BAD_SIGNATURE);
  if (memcmp (sig.data + sig.len - SIG_POSTFIX_LEN,
	      SIG_POSTFIX, SIG_POSTFIX_LEN))
    return gpg_error (GPG_ERR_BAD_SIGNATURE);

  memcpy (sig_result, sig.data + SIG_PREFIX_LEN, SIG_LEN);
  *sig_len = SIG_LEN;
  
  return 0;
}


void
scute_agent_finalize (void)
{
  if (agent_ctx)
    assuan_disconnect (agent_ctx);
}
