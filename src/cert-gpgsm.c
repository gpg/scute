/* cert-gpgsm.c - Scute certificate searching.
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

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <gpg-error.h>
#include <assuan.h>

#include "agent.h"
#include "cert.h"
#include "support.h"
#include "debug.h"


/* The maximum length of a key listing line.  We take the double of
 * the allowed Assuan line length plus some extra space to avoid a
 * memmove after a part of a line has been processed.  */
#define MAX_LINE_LEN	(ASSUAN_LINELENGTH*2 + 200)

struct keylist_ctx
{
  /* The pending line in an active key listing.  */
  char pending[MAX_LINE_LEN + 1];
  unsigned int pending_len;

  /* The current certificate.  */
  struct cert cert;

  /* The caller's search callback, invoked for each certificate.  */
  cert_search_cb_t search_cb;
  void *search_cb_hook;
};


/* Support macros  */
#define atoi_1(p)   (*(p) - '0' )
#define atoi_2(p)   ((atoi_1(p) * 10) + atoi_1((p)+1))
#define atoi_4(p)   ((atoi_2(p) * 100) + atoi_2((p)+2))


/*** Local prototypes  ***/
static gpg_error_t export_cert (const char *fpr, struct cert *cert);




/* Release allocated storage for the certificate CERT and reset the
   certificate.  */
static void
cert_reset (struct cert *cert)
{
  if (cert->issuer_serial)
    free (cert->issuer_serial);
  if (cert->issuer_name)
    free (cert->issuer_name);
  if (cert->uid)
    free (cert->uid);
  if (cert->cert_der)
    free (cert->cert_der);

  memset (cert, '\0', sizeof (struct cert));
}


/* Parse the string TIMESTAMP into a time_t.  The string may either be
   seconds since Epoch or in the ISO 8601 format like
   "20390815T143012".  Returns 0 for an empty string or seconds since
   Epoch. Leading spaces are skipped. If ENDP is not NULL, it will
   point to the next non-parsed character in TIMESTRING. */
static time_t
parse_timestamp (const char *timestamp, char **endp)
{
  /* Need to skip leading spaces, because that is what strtoul does
     but not our ISO 8601 checking code. */
  while (*timestamp && *timestamp== ' ')
    timestamp++;
  if (!*timestamp)
    return 0;

  if (strlen (timestamp) >= 15 && timestamp[8] == 'T')
    {
      struct tm buf;
      int year;

      year = atoi_4 (timestamp);
      if (year < 1900)
        return (time_t)(-1);

      /* Fixme: We would better use a configure test to see whether
         mktime can handle dates beyond 2038. */
      if (sizeof (time_t) <= 4 && year >= 2038)
        return (time_t)2145914603; /* 2037-12-31 23:23:23 */

      memset (&buf, 0, sizeof buf);
      buf.tm_year = year - 1900;
      buf.tm_mon = atoi_2 (timestamp+4) - 1;
      buf.tm_mday = atoi_2 (timestamp+6);
      buf.tm_hour = atoi_2 (timestamp+9);
      buf.tm_min = atoi_2 (timestamp+11);
      buf.tm_sec = atoi_2 (timestamp+13);

      if (endp)
        *endp = (char*)(timestamp + 15);
#ifdef HAVE_TIMEGM
      return timegm (&buf);
#else
      /* FIXME: Need to set TZ to UTC, but that is not
	 thread-safe.  */
      return mktime (&buf);
#endif

    }
  else
    return (time_t)strtoul (timestamp, endp, 10);
}


/* Decode the C formatted string SRC and store the result in the
   buffer *DESTP which is LEN bytes long.  If LEN is zero, then a
   large enough buffer is allocated with malloc and *DESTP is set to
   the result.  Currently, LEN is only used to specify if allocation
   is desired or not, the caller is expected to make sure that *DESTP
   is large enough if LEN is not zero.  */
static gpg_error_t
decode_c_string (const char *src, char **destp, size_t len)
{
  char *dest;

  /* Set up the destination buffer.  */
  if (len)
    {
      if (len < strlen (src) + 1)
	return gpg_error (GPG_ERR_INTERNAL);

      dest = *destp;
    }
  else
    {
      /* The converted string will never be larger than the original
	 string.  */
      dest = malloc (strlen (src) + 1);
      if (!dest)
	return gpg_error_from_syserror ();

      *destp = dest;
    }

  /* Convert the string.  */
  while (*src)
    {
      if (*src != '\\')
	{
	  *(dest++) = *(src++);
	  continue;
	}

      switch (src[1])
	{
#define DECODE_ONE(match,result)	\
	case match:			\
	  src += 2;			\
	  *(dest++) = result;		\
	  break;

	  DECODE_ONE ('\'', '\'');
	  DECODE_ONE ('\"', '\"');
	  DECODE_ONE ('\?', '\?');
	  DECODE_ONE ('\\', '\\');
	  DECODE_ONE ('a', '\a');
	  DECODE_ONE ('b', '\b');
	  DECODE_ONE ('f', '\f');
	  DECODE_ONE ('n', '\n');
	  DECODE_ONE ('r', '\r');
	  DECODE_ONE ('t', '\t');
	  DECODE_ONE ('v', '\v');

	case 'x':
	  {
	    int val = xtoi_2 (&src[2]);

	    if (val == -1)
	      {
		/* Should not happen.  */
		*(dest++) = *(src++);
		*(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
		if (*src)
		  *(dest++) = *(src++);
	      }
	    else
	      {
		if (!val)
		  {
		    /* A binary zero is not representable in a C
		       string.  */
		    *(dest++) = '\\';
		    *(dest++) = '0';
		  }
		else
		  *((unsigned char *) dest++) = val;
		src += 4;
	      }
	  }
	  break;

	default:
	  {
	    /* Should not happen.  */
	    *(dest++) = *(src++);
	    *(dest++) = *(src++);
	  }
        }
    }
  *(dest++) = 0;

  return 0;
}



/* Helper for keylist_cb.  This fucntion is invoked for each complete
 * line assembled by keylist_cb.  */
static gpg_error_t
keylist_cb_line (struct keylist_ctx *ctx)
{
  char *line;
  enum { RT_NONE, RT_CRT, RT_CRS, RT_FPR, RT_GRP, RT_UID } rectype = RT_NONE;
#define NR_FIELDS 16
  char *field[NR_FIELDS];
  int fields = 0;
  struct cert *cert;

  /* Strip a trailing carriage return.  */
  if (ctx->pending_len > 0
      && ctx->pending[ctx->pending_len - 1] == '\r')
    ctx->pending_len--;
  ctx->pending[ctx->pending_len - 1] = '\0';
  ctx->pending_len = 0;

  cert = &ctx->cert;
  line = ctx->pending;
  while (line && fields < NR_FIELDS)
    {
      field[fields++] = line;
      line = strchr (line, ':');
      if (line)
	*(line++) = '\0';
    }

  if (!strcmp (field[0], "crt"))
    rectype = RT_CRT;
  else if (!strcmp (field[0], "crs"))
    rectype = RT_CRS;
  else if (!strcmp (field[0], "fpr"))
    rectype = RT_FPR;
  else if (!strcmp (field[0], "grp"))
    rectype = RT_GRP;
  else if (!strcmp (field[0], "uid"))
    rectype = RT_UID;
  else
    rectype = RT_NONE;

  switch (rectype)
    {
    case RT_CRT:
    case RT_CRS:
      /* Reinitialize CERT.  */
      if (cert->valid)
	{
	  gpg_error_t err;

          /* Return the cert.  */
          err = export_cert (ctx->cert.fpr, &ctx->cert);
          if (!err)
            err = ctx->search_cb (ctx->search_cb_hook, &ctx->cert);
          if (err)
	    return err;

	  cert_reset (cert);
	}

      cert->valid = true;

#if 0
      /* Field 2 has the trust info.  */
      if (fields >= 2)
	set_mainkey_trust_info (key, field[1]);
#endif

      /* Field 3 has the key length.  */
      if (fields >= 3)
	{
	  int i = atoi (field[2]);
	  /* Ignore invalid values.  */
	  if (i > 1)
	    cert->length = i;
	}

      /* Field 4 has the public key algorithm.  */
      if (fields >= 4)
	{
	  int i = atoi (field[3]);
	  if (i >= 1 && i < 128)
	    cert->pubkey_algo = i;
	}

      /* Field 5 has the long keyid.  Allow short key IDs for the
	 output of an external keyserver listing.  */
      if (fields >= 5 && strlen (field[4]) <= sizeof (cert->keyid) - 1)
	strcpy (cert->keyid, field[4]);

      /* Field 6 has the timestamp (seconds).  */
      if (fields >= 6)
	cert->timestamp = parse_timestamp (field[5], NULL);

      /* Field 7 has the expiration time (seconds).  */
      if (fields >= 7)
	cert->expires = parse_timestamp (field[6], NULL);

      /* Field 8 has the X.509 serial number.  */
      if (fields >= 8)
	{
	  cert->issuer_serial = strdup (field[7]);
	  if (!cert->issuer_serial)
	    return gpg_error_from_syserror ();
	}

#if 0
      /* Field 9 has the ownertrust.  */
      if (fields >= 9)
	set_ownertrust (key, field[8]);
#endif

      /* Field 10 is the issuer name.  */
      if (fields >= 10)
	if (decode_c_string (field[9], &cert->issuer_name, 0))
	  return gpg_error (GPG_ERR_ENOMEM);	/* FIXME */

      /* Field 11 has the signature class.  */

#if 0
      /* Field 12 has the capabilities.  */
      if (fields >= 12)
	set_mainkey_capability (key, field[11]);
#endif
      break;

    case RT_UID:
      if (cert->valid)
	{
	  /* Field 2 has the trust info, and field 10 has the user ID.
	     Note that more than one UID field can appear.  We only
	     remember the last one.  It's not used anyway.  */
	  if (fields >= 10 && !cert->uid)
	    {
	      if (decode_c_string (field[9], &cert->uid, 0))
		return gpg_error (GPG_ERR_ENOMEM);	/* FIXME */
	    }
	}
      break;

    case RT_FPR:
      if (cert->valid)
	{
	  /* Field 10 has the fingerprint (take only the first one).  */
	  if (fields >= 10 && strlen (field[9]) <= sizeof (cert->fpr) - 1)
	    strcpy (cert->fpr, field[9]);

	  /* Field 13 has the gpgsm chain ID (take only the first one).  */
	  if (fields >= 13 && strlen (field[12])
	      <= sizeof (cert->chain_id) - 1)
	    strcpy (cert->chain_id, field[12]);
	}
      break;

    case RT_GRP:
      if (cert->valid)
	{
	  /* Field 10 has the key grip.  */
	}
      break;

    case RT_NONE:
      /* Unknown record.  */
      break;
    }

  return 0;
}


/* This is the data line callback handler provided to assuan_transact
 * in scute_gpgsm_search_certs_by_{grip,fpr}.  It buffers incomplete
 * lines, and is also used to handle the EOF signal directly outside
 * of assuan_transact.  */
static gpg_error_t
keylist_cb (void *hook, const void *line_data, size_t line_len)
{
  struct keylist_ctx *ctx = hook;
  const char *line = line_data;
  gpg_error_t err;

  if (!line)
    {
      /* This indicates an EOF.  */

      /* Check for a pending line, in case GPGSM didn't close with a
	 newline.  */
      if (ctx->pending_len)
	{
	  err = keylist_cb_line (ctx);
	  if (err)
	    return err;
	}

      /* Check for a pending certificate and return it.  */
      if (ctx->cert.valid)
        {
          err = export_cert (ctx->cert.fpr, &ctx->cert);
          if (!err)
            err = ctx->search_cb (ctx->search_cb_hook, &ctx->cert);
        }
      else
        err = 0;

      return err;
    }

  while (line_len)
    {
      if (*line == '\n')
	{
	  err = keylist_cb_line (ctx);
	  if (err)
	    return err;
	}
      else
	{
	  if (ctx->pending_len >= MAX_LINE_LEN)
	    return gpg_error (GPG_ERR_LINE_TOO_LONG);

	  ctx->pending[ctx->pending_len++] = *line;
	}
      line++;
      line_len--;
    }

  return 0;
}




struct export_hook
{
  /* The exported data.  */
  char *buffer;

  /* The length of the exported data buffer.  */
  unsigned int buffer_len;

  /* The size of the allocated exported data buffer.  */
  unsigned int buffer_size;
};

#define EXP_DATA_START 4096

static gpg_error_t
export_cert_cb (void *hook, const void *line_data, size_t line_len)
{
  struct export_hook *exp = hook;
  const char *line = line_data;

  if (exp->buffer_size - exp->buffer_len < line_len)
    {
      unsigned int new_buffer_size = exp->buffer_size ?
	(exp->buffer_size * 2) : EXP_DATA_START;
      char *new_buffer = realloc (exp->buffer, new_buffer_size);

      if (!new_buffer)
	return gpg_error_from_syserror ();

      exp->buffer = new_buffer;
      exp->buffer_size = new_buffer_size;
    }

  memcpy (exp->buffer + exp->buffer_len, line, line_len);
  exp->buffer_len += line_len;

  return 0;
}


/* Export the certifciate using a second assuan connection.  This is
 * called during the key listing after a "crt" record has been
 * received.  */
static gpg_error_t
export_cert (const char *fpr, struct cert *cert)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[] = { "gpgsm", "--server", NULL };
#define COMMANDLINELEN 80
  char cmd[COMMANDLINELEN];
  struct export_hook exp;

  err = assuan_new (&ctx);
  if (err)
    {
      DEBUG (DBG_CRIT, "failed to allocate assuan context: %s",
	     gpg_strerror (err));
      return err;
    }

  err = assuan_pipe_connect (ctx, get_gpgsm_path (), argv, NULL,
			     NULL, NULL, 128);
  if (err)
    {
      assuan_release (ctx);
      DEBUG (DBG_CRIT, "spawning %s\n", get_gpgsm_path ());
      return err;
    }

  exp.buffer = NULL;
  exp.buffer_len = 0;
  exp.buffer_size = 0;

  snprintf (cmd, sizeof (cmd), "EXPORT --data -- %s", cert->fpr);
  err = assuan_transact (ctx, cmd, export_cert_cb, &exp,
			 NULL, NULL, NULL, NULL);
  assuan_release (ctx);

  if (!err)
    {
      cert->cert_der = exp.buffer;
      cert->cert_der_len = exp.buffer_len;
    }

  if (!err)
    err = scute_agent_is_trusted (fpr, &cert->is_trusted);

  return err;
}


/* Search for certificates using a key listing using PATTERN which is
 * described by MODE.  Invoke SEARCH_CB for each certificate found.  */
gpg_error_t
scute_gpgsm_search_certs (enum keylist_modes mode, const char *pattern,
                          cert_search_cb_t search_cb,
                          void *search_cb_hook)
{
  gpg_error_t err;
  assuan_context_t ctx;
  const char *argv[] = { "gpgsm", "--server", NULL };
  char line[ASSUAN_LINELENGTH];
  struct keylist_ctx  keylist_ctx;

  err = assuan_new (&ctx);
  if (err)
    {
      DEBUG (DBG_CRIT, "failed to allocate assuan context: %s",
	     gpg_strerror (err));
      return err;
    }

  err = assuan_pipe_connect (ctx, get_gpgsm_path (), argv, NULL,
			     NULL, NULL, 128);
  if (err)
    {
      assuan_release (ctx);
      DEBUG (DBG_CRIT, "failed to spawn %s\n", get_gpgsm_path ());
      return err;
    }

  memset (&keylist_ctx, 0, sizeof keylist_ctx);
  keylist_ctx.search_cb = search_cb;
  keylist_ctx.search_cb_hook = search_cb_hook;

  err = assuan_transact (ctx, "OPTION with-key-data", NULL, NULL,
                         NULL, NULL, NULL, NULL);
  if (err)
    goto leave;


  snprintf (line, sizeof line, "LISTKEYS %s%s",
            mode == KEYLIST_BY_GRIP? "&":"",
            pattern);
  err = assuan_transact (ctx, line,
                         keylist_cb, &keylist_ctx,
                         NULL, NULL,
                         NULL, NULL);
  if (err)
    goto leave;

  /* Signal the EOF.  This is not done by Assuan for us.  */
  err = keylist_cb (&keylist_ctx, NULL, 0);
  if (err)
    goto leave;

 leave:
  cert_reset (&keylist_ctx.cert);
  assuan_release (ctx);
  return err;
}
